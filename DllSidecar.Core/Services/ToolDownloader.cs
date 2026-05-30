using System.IO.Compression;
using System.Net.Http;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

public enum DownloadPhase { Idle, Validating, Downloading, Extracting, Verifying, Configuring, Done, Failed }

public class DownloadProgress
{
    public DownloadPhase Phase { get; set; }
    public long BytesReceived { get; set; }
    public long? TotalBytes { get; set; }
    public string Message { get; set; } = "";
    public double Percent => TotalBytes.HasValue && TotalBytes.Value > 0
        ? (double)BytesReceived / TotalBytes.Value * 100.0
        : 0;
}

public class DownloadResult
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public string? InstallPath { get; set; }
    public Dictionary<string, string> ResolvedBinaries { get; set; } = [];
    public List<string> VerifiedSigned { get; set; } = [];
    public List<string> VerificationFailures { get; set; } = [];
}

/// <summary>Downloads whitelisted tools over HTTPS, extracts, Authenticode-verifies, and updates config. Aborts on signature failure.</summary>
public static class ToolDownloader
{
    private static readonly HashSet<string> HostWhitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        "download.sysinternals.com",
        "live.sysinternals.com",
        "github.com",
        "objects.githubusercontent.com",
        "raw.githubusercontent.com",
    };

    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromMinutes(10),
    };

    public static string ToolsRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DllSidecar", "tools");

    public static IReadOnlyList<ToolDownloadDef> Catalog { get; } = new List<ToolDownloadDef>
    {
        new()
        {
            Id = "sysinternals-suite",
            DisplayName = "Sysinternals Suite (Microsoft)",
            Url = "https://download.sysinternals.com/files/SysinternalsSuite.zip",
            MaxSizeBytes = 200 * 1024 * 1024,
            InstallSubdir = "Sysinternals",
            BinariesToVerify = ["Procmon64.exe", "sigcheck64.exe"],
            ConfigUpdates =
            {
                ["SysinternalsDir"] = "",
                ["ProcmonPath"] = "Procmon64.exe",
                ["SigcheckPath"] = "sigcheck64.exe",
            },
        },
        new()
        {
            Id = "procmon",
            DisplayName = "Process Monitor (standalone)",
            Url = "https://download.sysinternals.com/files/ProcessMonitor.zip",
            MaxSizeBytes = 20 * 1024 * 1024,
            InstallSubdir = "Procmon",
            BinariesToVerify = ["Procmon64.exe"],
            ConfigUpdates = { ["ProcmonPath"] = "Procmon64.exe" },
        },
        new()
        {
            Id = "sigcheck",
            DisplayName = "Sigcheck (standalone)",
            Url = "https://download.sysinternals.com/files/Sigcheck.zip",
            MaxSizeBytes = 10 * 1024 * 1024,
            InstallSubdir = "Sigcheck",
            BinariesToVerify = ["sigcheck64.exe"],
            ConfigUpdates = { ["SigcheckPath"] = "sigcheck64.exe" },
        },
    };

    public static ToolDownloadDef? GetById(string id) =>
        Catalog.FirstOrDefault(d => d.Id == id);

    public static async Task<DownloadResult> InstallAsync(
        ToolDownloadDef def,
        IProgress<DownloadProgress>? progress,
        CancellationToken ct)
    {
        var result = new DownloadResult();
        var report = new DownloadProgress();

        report.Phase = DownloadPhase.Validating;
        report.Message = "Validating URL and policy";
        progress?.Report(report);

        if (!Uri.TryCreate(def.Url, UriKind.Absolute, out var uri))
        {
            return Fail(result, progress, report, "Malformed URL");
        }
        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            return Fail(result, progress, report, $"HTTPS required, got '{uri.Scheme}'");
        }
        if (!HostWhitelist.Contains(uri.Host))
        {
            return Fail(result, progress, report, $"Host '{uri.Host}' not in download whitelist");
        }

        var tempZip = Path.Combine(Path.GetTempPath(), $"dllsidecar-{def.Id}-{Guid.NewGuid():N}.zip");
        try
        {
            report.Phase = DownloadPhase.Downloading;
            report.Message = $"Downloading from {uri.Host}";
            progress?.Report(report);

            using var resp = await Http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
            resp.EnsureSuccessStatusCode();

            var total = resp.Content.Headers.ContentLength;
            if (total.HasValue && total.Value > def.MaxSizeBytes)
            {
                return Fail(result, progress, report,
                    $"Refused: server reports {total.Value / (1024 * 1024)}MB, limit is {def.MaxSizeBytes / (1024 * 1024)}MB");
            }
            report.TotalBytes = total;

            await using var contentStream = await resp.Content.ReadAsStreamAsync(ct);
            await using (var fs = File.Create(tempZip))
            {
                var buffer = new byte[81920];
                long received = 0;
                int read;
                while ((read = await contentStream.ReadAsync(buffer, ct)) > 0)
                {
                    ct.ThrowIfCancellationRequested();
                    await fs.WriteAsync(buffer.AsMemory(0, read), ct);
                    received += read;
                    if (received > def.MaxSizeBytes)
                    {
                        return Fail(result, progress, report,
                            $"Refused: stream exceeded {def.MaxSizeBytes / (1024 * 1024)}MB cap");
                    }
                    report.BytesReceived = received;
                    report.Message = $"Downloaded {received:N0} / {(total?.ToString("N0") ?? "?")} bytes";
                    progress?.Report(report);
                }
            }
            Log.Info("download", $"{def.Id}: downloaded {new FileInfo(tempZip).Length:N0} bytes");

            // 3) Extract
            var installPath = Path.Combine(ToolsRoot, def.InstallSubdir);
            // Clean previous install
            if (Directory.Exists(installPath))
            {
                try { Directory.Delete(installPath, recursive: true); }
                catch (IOException ex) { Log.Warn("download", $"Could not clean previous {installPath}", ex); }
            }
            Directory.CreateDirectory(installPath);

            report.Phase = DownloadPhase.Extracting;
            report.Message = $"Extracting to {installPath}";
            progress?.Report(report);

            ZipFile.ExtractToDirectory(tempZip, installPath, overwriteFiles: true);
            Log.Info("download", $"{def.Id}: extracted to {installPath}");

            // 4) Authenticode verify required binaries (dogfooding AuthenticodeVerifier)
            report.Phase = DownloadPhase.Verifying;
            report.Message = "Verifying Authenticode signatures";
            progress?.Report(report);

            foreach (var binName in def.BinariesToVerify)
            {
                ct.ThrowIfCancellationRequested();
                var binPath = Path.Combine(installPath, binName);
                if (!File.Exists(binPath))
                {
                    var msg = $"Expected binary not found after extraction: {binName}";
                    Log.Error("download", msg);
                    result.VerificationFailures.Add(msg);
                    continue;
                }
                var sig = AuthenticodeVerifier.Verify(binPath);
                if (sig.IsTrusted)
                {
                    result.VerifiedSigned.Add($"{binName}: {sig.Subject}");
                    Log.Info("download", $"{binName} signature OK ({sig.Subject})");
                }
                else
                {
                    var msg = $"{binName} Authenticode status: {sig.Status} ({sig.ErrorMessage ?? "no cert"})";
                    Log.Error("download", msg);
                    result.VerificationFailures.Add(msg);
                }
            }

            if (result.VerificationFailures.Count > 0)
            {
                // ABORT: refuse to install untrusted binaries. Remove extracted files.
                try { Directory.Delete(installPath, recursive: true); } catch (Exception ex) { Log.Warn("download", "Cleanup failed", ex); }
                return Fail(result, progress, report,
                    $"Aborted: Authenticode verification failed for {result.VerificationFailures.Count} binary(ies)");
            }

            // 5) Update config
            report.Phase = DownloadPhase.Configuring;
            report.Message = "Updating configuration";
            progress?.Report(report);

            var tools = ConfigManager.Current.Tools;
            foreach (var (key, rel) in def.ConfigUpdates)
            {
                var full = string.IsNullOrEmpty(rel) ? installPath : Path.Combine(installPath, rel);
                switch (key)
                {
                    case "SysinternalsDir": tools.SysinternalsDir = full; break;
                    case "ProcmonPath":     tools.ProcmonPath = full;     break;
                    case "SigcheckPath":    tools.SigcheckPath = full;    break;
                    case "DependenciesGuiPath": tools.DependenciesGuiPath = full; break;
                    case "X64DbgPath":      tools.X64DbgPath = full;      break;
                    case "X32DbgPath":      tools.X32DbgPath = full;      break;
                    default: Log.Warn("download", $"Unknown config key in def: {key}"); break;
                }
                result.ResolvedBinaries[key] = full;
            }
            var saveRes = ConfigManager.Save();
            if (!saveRes.Success)
                Log.Warn("download", $"Binaries installed but config save failed: {saveRes.ErrorMessage}");

            report.Phase = DownloadPhase.Done;
            report.Message = "Installation complete";
            progress?.Report(report);
            result.Success = true;
            result.InstallPath = installPath;
            return result;
        }
        catch (OperationCanceledException)
        {
            Log.Info("download", $"{def.Id}: cancelled by user");
            return Fail(result, progress, report, "Cancelled");
        }
        catch (HttpRequestException ex)
        {
            Log.Error("download", $"{def.Id}: HTTP error", ex);
            return Fail(result, progress, report, $"HTTP error: {ex.Message}");
        }
        catch (IOException ex)
        {
            Log.Error("download", $"{def.Id}: I/O error", ex);
            return Fail(result, progress, report, $"I/O error: {ex.Message}");
        }
        catch (InvalidDataException ex)
        {
            Log.Error("download", $"{def.Id}: ZIP invalid", ex);
            return Fail(result, progress, report, $"Downloaded archive is not a valid ZIP: {ex.Message}");
        }
        finally
        {
            if (File.Exists(tempZip))
            {
                try { File.Delete(tempZip); }
                catch (IOException ex) { Log.Warn("download", $"Could not delete temp {tempZip}", ex); }
            }
        }
    }

    private static DownloadResult Fail(DownloadResult r, IProgress<DownloadProgress>? p, DownloadProgress rep, string msg)
    {
        r.Success = false;
        r.ErrorMessage = msg;
        rep.Phase = DownloadPhase.Failed;
        rep.Message = msg;
        p?.Report(rep);
        Log.Error("download", msg);
        return r;
    }
}
