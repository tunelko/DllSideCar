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

        progress?.Report($"Output: {outDir}");
        progress?.Report($"Input:  {Path.GetFileName(installerPath)} ({ext})");
        result.Logs.Add($"Input: {installerPath}");
        result.Logs.Add($"Output: {outDir}");

        // Attempt 1: 7-Zip
        // Tool-brand names are kept ONLY in result.Logs (technical detail) — the
        // user-facing progress messages are deliberately generic so the workflow
        // reads as "Extracting installer..." instead of "Trying 7-Zip...". This
        // is what the researcher asked for: the underlying tool is an
        // implementation detail, not part of the UX vocabulary.
        if (!string.IsNullOrWhiteSpace(tools.SevenZipPath) && File.Exists(tools.SevenZipPath))
        {
            progress?.Report("Extracting installer...");
            result.Logs.Add("[stage 1] 7-Zip");
            if (await TryExtractWith7ZipAsync(tools.SevenZipPath, installerPath, outDir, result, progress, ct))
            {
                PopulateStats(result);
                // 7-Zip happily returns exit 0 even when it cannot find an
                // archive inside a self-extracting PE (e.g. InstallShield /
                // Wise / custom packers). Without this guard the UI shows
                // "Success — 0 files" which is the bug the user reported.
                // Treat 0 files as failure and fall through to the next
                // method so the researcher gets either a real extraction
                // or an actionable "all methods failed" error.
                if (result.FilesExtracted > 0)
                {
                    result.Success = true;
                    result.MethodUsed = ExtractionMethod.SevenZip;
                    return result;
                }
                progress?.Report("Primary method produced no files — trying alternate...");
                result.Logs.Add("[stage 1] 7-Zip returned exit 0 but produced 0 files (unknown archive format inside PE)");
            }
            else
            {
                progress?.Report("Primary method failed — trying alternate...");
                result.Logs.Add("[stage 1] 7-Zip failed");
            }
        }
        else
        {
            progress?.Report("Primary extractor not configured — falling back...");
            result.Logs.Add("(7-Zip not configured — would have been tried first)");
        }

        // Attempt 2: msiexec /a for .msi
        if (ext == ".msi")
        {
            progress?.Report("Trying MSI admin install...");
            result.Logs.Add("[stage 2] msiexec /a");
            if (await TryExtractWithMsiExecAsync(installerPath, outDir, result, progress, ct))
            {
                PopulateStats(result);
                if (result.FilesExtracted > 0)
                {
                    result.Success = true;
                    result.MethodUsed = ExtractionMethod.MsiExec;
                    return result;
                }
                progress?.Report("MSI admin install produced no files — trying alternate...");
                result.Logs.Add("[stage 2] msiexec returned exit 0 but produced 0 files");
            }
            else
            {
                progress?.Report("MSI admin install failed — trying alternate...");
                result.Logs.Add("[stage 2] msiexec failed");
            }
        }

        // Attempt 3: innounp
        if (!string.IsNullOrWhiteSpace(tools.InnoUnpPath) && File.Exists(tools.InnoUnpPath))
        {
            progress?.Report("Trying Inno Setup unpacker...");
            result.Logs.Add("[stage 3] innounp");
            if (await TryExtractWithInnoUnpAsync(tools.InnoUnpPath, installerPath, outDir, result, progress, ct))
            {
                PopulateStats(result);
                if (result.FilesExtracted > 0)
                {
                    result.Success = true;
                    result.MethodUsed = ExtractionMethod.InnoUnp;
                    return result;
                }
                progress?.Report("Inno Setup unpacker produced no files");
                result.Logs.Add("[stage 3] innounp returned exit 0 but produced 0 files");
            }
            else
            {
                progress?.Report("Inno Setup unpacker failed");
                result.Logs.Add("[stage 3] innounp failed");
            }
        }

        result.ErrorMessage =
            "Could not extract this installer. None of the static-extraction methods (7-Zip, MSI admin install, " +
            "Inno Setup unpacker) recognized the format. The installer may use a custom packer such as " +
            "InstallShield, Wise, or a proprietary self-extracting wrapper. Check the extraction log for the " +
            "raw output from each attempted method.";
        progress?.Report("Could not extract this installer — see log for details.");
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
        // -bb1 emits one log line per extracted file (`- path/to/file`). The page
        // streams these lines to the loading overlay so the user can see real-time
        // progress instead of staring at a static spinner. -bsp0 keeps the
        // per-second percentage off stdout — it uses CR (not LF) so it would
        // break our line-based reader.
        psi.ArgumentList.Add("-bb1");
        psi.ArgumentList.Add("-bsp0");

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
        // Per-line streaming via OutputDataReceived events instead of ReadToEndAsync.
        // The previous implementation buffered the entire child output until the
        // process exited, which meant the page-level IProgress callback only fired
        // ONCE per extraction (after completion). For 7-Zip with -bb1 emitting one
        // line per extracted file, line-streaming lets the LoadingOverlay subtitle
        // update in real time so the user sees forward motion instead of a static
        // spinner. Lists are filled inside the event handlers (single producer
        // thread per stream, so List<T> is safe here without locking).
        var stdoutLines = new List<string>();
        var stderrLines = new List<string>();
        try
        {
            p = Process.Start(psi);
            if (p == null)
            {
                result.Logs.Add($"[{label}] Process.Start returned null");
                return false;
            }

            // 7-Zip with -bb1 emits one "- path/to/file" line per extracted entry.
            // We must NOT echo every line to the UI: a mid-size installer produces
            // thousands of lines, and surfacing each one through the WPF progress
            // pump (a) overloads the UI thread, (b) exposes tool-internal syntax
            // (the leading "- " is 7-Zip vocabulary), and (c) makes the live
            // status unreadable. Instead, count file-prefix lines and emit a
            // milestone report every 10 files. Full raw output is preserved in
            // result.Logs for post-mortem debugging.
            int extractedSoFar = 0;
            p.OutputDataReceived += (_, e) =>
            {
                if (e.Data == null) return;
                stdoutLines.Add(e.Data);
                if (e.Data.StartsWith("- ", StringComparison.Ordinal))
                {
                    extractedSoFar++;
                    if (extractedSoFar % 10 == 0)
                        progress?.Report($"Extracted {extractedSoFar} files...");
                }
            };
            p.ErrorDataReceived += (_, e) =>
            {
                if (e.Data == null) return;
                stderrLines.Add(e.Data);
                // Stderr is rare and meaningful — surface it as a generic warning
                // without the tool label so the user-facing log stays brand-free.
                progress?.Report($"Extractor warning: {e.Data}");
            };
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();

            using var reg = ct.Register(() =>
            {
                try { if (!p.HasExited) p.Kill(entireProcessTree: true); }
                catch (Exception ex) { Log.Warn("installer", $"Kill failed for {label}", ex); }
            });

            await p.WaitForExitAsync(ct);

            if (stdoutLines.Count > 0) result.Logs.Add($"[{label}] stdout:\n{string.Join("\n", stdoutLines)}");
            if (stderrLines.Count > 0) result.Logs.Add($"[{label}] stderr:\n{string.Join("\n", stderrLines)}");

            var ok = p.ExitCode == 0;
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
