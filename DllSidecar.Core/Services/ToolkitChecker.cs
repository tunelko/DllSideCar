using System.Diagnostics;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Logging;

namespace DllSidecar.Core.Services;

public class ToolStatus
{
    public required string Name { get; init; }
    public required string Purpose { get; init; }
    public string? ResolvedPath { get; set; }
    public string? Version { get; set; }
    public bool IsAvailable => !string.IsNullOrEmpty(ResolvedPath);
    public string? DownloadUrl { get; set; }
    public bool Required { get; set; }
    public string? Notes { get; set; }
}

public class ToolkitReport
{
    public List<ToolStatus> Tools { get; } = [];
    public int AvailableCount => Tools.Count(t => t.IsAvailable);
    public int TotalCount => Tools.Count;
    public int RequiredMissing => Tools.Count(t => t.Required && !t.IsAvailable);
    public bool AllRequiredPresent => RequiredMissing == 0;
}

public static class ToolkitChecker
{
    /// <summary>Async wrapper — offloads the Process.Start version probes off the UI thread.</summary>
    public static Task<ToolkitReport> CheckAllAsync(CancellationToken ct = default) =>
        Task.Run(() => { ct.ThrowIfCancellationRequested(); return CheckAll(); }, ct);

    public static ToolkitReport CheckAll()
    {
        var cfg = ConfigManager.Current;
        var report = new ToolkitReport();

        // MinGW — required for compilation
        var gcc64 = BuildSystem.FindGcc("x64");
        var gcc32 = BuildSystem.FindGcc("x86");
        report.Tools.Add(new ToolStatus
        {
            Name = "MinGW gcc (x64)",
            Purpose = "Compile proxy/sideload DLLs (x64)",
            Required = true,
            ResolvedPath = gcc64,
            Version = gcc64 != null ? RunVersion(gcc64, "--version") : null,
            DownloadUrl = "https://www.msys2.org/",
            Notes = "MSYS2 with mingw-w64-x86_64-gcc package",
        });
        report.Tools.Add(new ToolStatus
        {
            Name = "MinGW gcc (x86)",
            Purpose = "Compile proxy/sideload DLLs (x86)",
            Required = false,
            ResolvedPath = gcc32,
            Version = gcc32 != null ? RunVersion(gcc32, "--version") : null,
            DownloadUrl = "https://www.msys2.org/",
            Notes = "MSYS2 with mingw-w64-i686-gcc package",
        });

        var wr64 = BuildSystem.FindWindres("x64");
        var wr32 = BuildSystem.FindWindres("x86");
        report.Tools.Add(new ToolStatus
        {
            Name = "windres",
            Purpose = "Compile .rc resource files for metadata cloning",
            Required = false,
            ResolvedPath = wr64 ?? wr32,
            DownloadUrl = "https://www.msys2.org/",
        });

        // ProcMon — required for dynamic verification
        var procmon = ResolveTool(cfg.Tools.ProcmonPath, ["Procmon64.exe", "Procmon.exe"]);
        report.Tools.Add(new ToolStatus
        {
            Name = "Process Monitor",
            Purpose = "Phase 2 — dynamic verification: record NAME NOT FOUND events",
            Required = true,
            ResolvedPath = procmon,
            DownloadUrl = "https://learn.microsoft.com/sysinternals/downloads/procmon",
            Notes = "Part of Sysinternals Suite",
        });

        // Sigcheck — optional cross-check of Authenticode
        var sigcheck = ResolveTool(cfg.Tools.SigcheckPath, ["sigcheck64.exe", "sigcheck.exe"]);
        report.Tools.Add(new ToolStatus
        {
            Name = "sigcheck",
            Purpose = "Cross-check of Authenticode signatures (complements native WinVerifyTrust)",
            Required = false,
            ResolvedPath = sigcheck,
            Version = sigcheck != null ? RunVersion(sigcheck, "-nobanner -accepteula -?") : null,
            DownloadUrl = "https://learn.microsoft.com/sysinternals/downloads/sigcheck",
            Notes = "Part of Sysinternals Suite — first run pops EULA",
        });

        // Dependencies (lucasg) — visual IAT browser
        var deps = ResolveTool(cfg.Tools.DependenciesGuiPath, ["DependenciesGui.exe", "Dependencies.exe"]);
        report.Tools.Add(new ToolStatus
        {
            Name = "Dependencies (lucasg)",
            Purpose = "Visual import tree browser (modern Dependency Walker)",
            Required = false,
            ResolvedPath = deps,
            DownloadUrl = "https://github.com/lucasg/Dependencies/releases",
        });

        // x64dbg / x32dbg — manual debugging
        var x64dbg = ResolveTool(cfg.Tools.X64DbgPath, ["x64dbg.exe"]);
        var x32dbg = ResolveTool(cfg.Tools.X32DbgPath, ["x32dbg.exe"]);
        report.Tools.Add(new ToolStatus
        {
            Name = "x64dbg / x32dbg",
            Purpose = "Manual debugging to verify execution context of injected payload",
            Required = false,
            ResolvedPath = x64dbg ?? x32dbg,
            DownloadUrl = "https://x64dbg.com/",
        });

        // 7-Zip — installer extraction
        var sevenZip = ResolveTool(cfg.Tools.SevenZipPath, ["7z.exe"]);
        report.Tools.Add(new ToolStatus
        {
            Name = "7-Zip",
            Purpose = "Extract MSI / NSIS / InnoSetup installers without executing them",
            Required = false,
            ResolvedPath = sevenZip,
            DownloadUrl = "https://www.7-zip.org/",
        });

        // InnoUnp — Inno Setup-specific extractor
        var innounp = ResolveTool(cfg.Tools.InnoUnpPath, ["innounp.exe"]);
        report.Tools.Add(new ToolStatus
        {
            Name = "InnoUnp",
            Purpose = "Extract Inno Setup installers (.exe) when 7-Zip fails",
            Required = false,
            ResolvedPath = innounp,
            DownloadUrl = "https://innounp.sourceforge.net/",
        });

        return report;
    }

    private static string? ResolveTool(string? configured, string[] defaultNames)
    {
        // 1. Explicit user-configured path wins if valid
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured))
            return configured;

        var tools = ConfigManager.Current.Tools;

        // 2. Sysinternals directory — covers Procmon, sigcheck, psexec, autoruns, handle, etc
        if (!string.IsNullOrWhiteSpace(tools.SysinternalsDir) && Directory.Exists(tools.SysinternalsDir))
        {
            foreach (var name in defaultNames)
            {
                var full = Path.Combine(tools.SysinternalsDir, name);
                if (File.Exists(full)) return full;
            }
        }

        // 3. Generic tools root — probe root + immediate subdirs (one level deep)
        if (!string.IsNullOrWhiteSpace(tools.ToolsRootDir) && Directory.Exists(tools.ToolsRootDir))
        {
            foreach (var name in defaultNames)
            {
                var full = Path.Combine(tools.ToolsRootDir, name);
                if (File.Exists(full)) return full;
            }
            try
            {
                foreach (var sub in Directory.EnumerateDirectories(tools.ToolsRootDir))
                    foreach (var name in defaultNames)
                    {
                        var full = Path.Combine(sub, name);
                        if (File.Exists(full)) return full;
                    }
            }
            catch (UnauthorizedAccessException) { /* permission denied on a subdir — skip */ }
            catch (IOException ex) { Log.Warn("toolkit", $"Error enumerating {tools.ToolsRootDir}", ex); }
        }

        // 4. Search PATH
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathVar.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var name in defaultNames)
            {
                var full = Path.Combine(dir.Trim(), name);
                if (File.Exists(full)) return full;
            }
        }

        // 5. Common install locations (fallback)
        string[] commonRoots = [
            @"C:\Tools",
            @"C:\Sysinternals",
            @"C:\Program Files\Sysinternals",
            @"C:\Program Files\7-Zip",
            @"C:\Program Files (x86)\7-Zip",
            @"C:\Program Files\x64dbg",
        ];
        foreach (var root in commonRoots)
            foreach (var name in defaultNames)
            {
                var full = Path.Combine(root, name);
                if (File.Exists(full)) return full;
            }

        return null;
    }

    private static string? RunVersion(string exe, string arg)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        // Individual args — no shell interpolation
        foreach (var a in arg.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            psi.ArgumentList.Add(a);

        Process? p = null;
        try
        {
            p = Process.Start(psi);
            if (p == null) { Log.Warn("toolkit", $"Failed to start {exe} for version probe"); return null; }
            var line = p.StandardOutput.ReadLine() ?? p.StandardError.ReadLine();
            if (!p.WaitForExit(3000))
            {
                Log.Warn("toolkit", $"Version probe timed out for {exe}; killing");
                try { p.Kill(entireProcessTree: true); } catch (Exception kx) { Log.Warn("toolkit", $"Failed to kill {exe}", kx); }
                return null;
            }
            return line?.Trim();
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Log.Debug("toolkit", $"Version probe Win32 error for {exe}", ex);
            return null;
        }
        finally
        {
            p?.Dispose();
        }
    }

}
