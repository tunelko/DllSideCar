using System.Diagnostics;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Extracts installers (.msi / .exe) WITHOUT executing them. Tries in order:
///   (1) 7-Zip — best coverage: MSI, NSIS, InnoSetup, CAB, self-extracting EXE; no custom
///       actions, no registry writes, purely static.
///   (2) msiexec /a — admin install sequence; safer than /i but still runs some custom
///       actions of type 1/2. Fallback for MSIs that 7-Zip can't open.
///   (3) innounp — Inno Setup-specific extractor.
/// Extraction goes to %LOCALAPPDATA%\DllSidecar\extracted\{guid}\ by default.
/// </summary>
public static class InstallerExtractor
{
    public static string DefaultExtractionRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DllSidecar", "extracted");

    public static async Task<InstallerExtractionResult> ExtractAsync(
        string installerPath,
        string? targetDir,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        var result = new InstallerExtractionResult();

        if (!File.Exists(installerPath))
        {
            result.ErrorMessage = $"File not found: {installerPath}";
            return result;
        }

        // Prepare a unique output dir if none provided
        Directory.CreateDirectory(DefaultExtractionRoot);
        var outDir = targetDir ?? Path.Combine(DefaultExtractionRoot,
            $"{Path.GetFileNameWithoutExtension(installerPath)}_{Guid.NewGuid():N}"[..32]);
        Directory.CreateDirectory(outDir);
        result.OutputDir = outDir;

        var ext = Path.GetExtension(installerPath).ToLowerInvariant();
        var tools = ConfigManager.Current.Tools;

        progress?.Report($"Target: {outDir}");
        progress?.Report($"Input:  {installerPath} ({ext})");
        result.Logs.Add($"Input: {installerPath}");
        result.Logs.Add($"Output: {outDir}");

        // Attempt 1: 7-Zip
        if (!string.IsNullOrWhiteSpace(tools.SevenZipPath) && File.Exists(tools.SevenZipPath))
        {
            progress?.Report("Trying 7-Zip...");
            if (await TryExtractWith7ZipAsync(tools.SevenZipPath, installerPath, outDir, result, progress, ct))
            {
                result.Success = true;
                result.MethodUsed = ExtractionMethod.SevenZip;
                PopulateStats(result);
                return result;
            }
            progress?.Report("7-Zip failed");
        }
        else
        {
            progress?.Report("7-Zip not configured — skipping");
            result.Logs.Add("(7-Zip not configured — would have been tried first)");
        }

        // Attempt 2: msiexec /a for .msi
        if (ext == ".msi")
        {
            progress?.Report("Trying msiexec /a (admin install)...");
            if (await TryExtractWithMsiExecAsync(installerPath, outDir, result, progress, ct))
            {
                result.Success = true;
                result.MethodUsed = ExtractionMethod.MsiExec;
                PopulateStats(result);
                return result;
            }
            progress?.Report("msiexec failed");
        }

        // Attempt 3: innounp
        if (!string.IsNullOrWhiteSpace(tools.InnoUnpPath) && File.Exists(tools.InnoUnpPath))
        {
            progress?.Report("Trying innounp (Inno Setup)...");
            if (await TryExtractWithInnoUnpAsync(tools.InnoUnpPath, installerPath, outDir, result, progress, ct))
            {
                result.Success = true;
                result.MethodUsed = ExtractionMethod.InnoUnp;
                PopulateStats(result);
                return result;
            }
            progress?.Report("innounp failed");
        }

        result.ErrorMessage = "All extraction methods failed or unavailable";
        progress?.Report(result.ErrorMessage);
        // Clean up empty dir
        try { if (Directory.Exists(outDir) && !Directory.EnumerateFileSystemEntries(outDir).Any()) Directory.Delete(outDir); }
        catch (IOException ex) { Log.Warn("installer", $"Cleanup failed for {outDir}", ex); }
        return result;
    }

    private static async Task<bool> TryExtractWith7ZipAsync(
        string sevenZip, string installer, string outDir,
        InstallerExtractionResult result, IProgress<string>? progress, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = sevenZip,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        // ArgumentList — each arg escaped by the runtime, no shell interpolation
        psi.ArgumentList.Add("x");
        psi.ArgumentList.Add(installer);
        psi.ArgumentList.Add($"-o{outDir}");
        psi.ArgumentList.Add("-y");        // assume yes on prompts
        psi.ArgumentList.Add("-bb0");      // quiet log level
        psi.ArgumentList.Add("-bsp0");     // no progress to stdout (we'd need to parse)

        return await RunProcessAsync(psi, result, progress, ct, "7z");
    }

    private static async Task<bool> TryExtractWithMsiExecAsync(
        string installer, string outDir,
        InstallerExtractionResult result, IProgress<string>? progress, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "msiexec.exe",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("/a");
        psi.ArgumentList.Add(installer);
        psi.ArgumentList.Add("/qn");
        psi.ArgumentList.Add($"TARGETDIR={outDir}");

        return await RunProcessAsync(psi, result, progress, ct, "msiexec");
    }

    private static async Task<bool> TryExtractWithInnoUnpAsync(
        string innounp, string installer, string outDir,
        InstallerExtractionResult result, IProgress<string>? progress, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = innounp,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-x");        // extract
        psi.ArgumentList.Add("-y");        // assume yes
        psi.ArgumentList.Add($"-d{outDir}");
        psi.ArgumentList.Add(installer);

        return await RunProcessAsync(psi, result, progress, ct, "innounp");
    }

    private static async Task<bool> RunProcessAsync(
        ProcessStartInfo psi, InstallerExtractionResult result,
        IProgress<string>? progress, CancellationToken ct, string label)
    {
        Process? p = null;
        try
        {
            p = Process.Start(psi);
            if (p == null)
            {
                result.Logs.Add($"[{label}] Process.Start returned null");
                return false;
            }

            var stdoutTask = p.StandardOutput.ReadToEndAsync(ct);
            var stderrTask = p.StandardError.ReadToEndAsync(ct);

            using var reg = ct.Register(() =>
            {
                try { if (!p.HasExited) p.Kill(entireProcessTree: true); }
                catch (Exception ex) { Log.Warn("installer", $"Kill failed for {label}", ex); }
            });

            await p.WaitForExitAsync(ct);
            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            if (!string.IsNullOrEmpty(stdout)) result.Logs.Add($"[{label}] stdout:\n{stdout.Trim()}");
            if (!string.IsNullOrEmpty(stderr)) result.Logs.Add($"[{label}] stderr:\n{stderr.Trim()}");

            var ok = p.ExitCode == 0;
            progress?.Report(ok ? $"{label} exited 0 (success)" : $"{label} exited {p.ExitCode}");
            if (!ok) result.Logs.Add($"[{label}] exit code {p.ExitCode}");
            return ok;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            result.Logs.Add($"[{label}] Win32 error: {ex.Message}");
            Log.Warn("installer", $"{label} failed to start", ex);
            return false;
        }
        catch (OperationCanceledException)
        {
            result.Logs.Add($"[{label}] cancelled");
            return false;
        }
        finally
        {
            p?.Dispose();
        }
    }

    private static void PopulateStats(InstallerExtractionResult result)
    {
        if (string.IsNullOrEmpty(result.OutputDir) || !Directory.Exists(result.OutputDir)) return;
        try
        {
            long total = 0;
            int count = 0;
            foreach (var f in Directory.EnumerateFiles(result.OutputDir, "*", SearchOption.AllDirectories))
            {
                count++;
                try { total += new FileInfo(f).Length; }
                catch (IOException) { /* transient — skip */ }
            }
            result.FilesExtracted = count;
            result.TotalBytesExtracted = total;
        }
        catch (UnauthorizedAccessException ex) { Log.Warn("installer", "Stats gather failed", ex); }
    }
}
