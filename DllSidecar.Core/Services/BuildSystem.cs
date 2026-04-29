using System.Diagnostics;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

public class BuildResult
{
    public bool Success { get; set; }
    public string Output { get; set; } = "";
    public string Errors { get; set; } = "";
    public string? OutputPath { get; set; }
    public long OutputSize { get; set; }
    public int ExportCount { get; set; }
}

public static class BuildSystem
{
    private static readonly Dictionary<string, string> GccPrefix = new()
    {
        ["x86"] = "i686-w64-mingw32",
        ["x64"] = "x86_64-w64-mingw32",
    };

    private static string[] MingwPathsFor(string arch) =>
        ConfigManager.Current.Mingw.GetSearchPaths(arch);

    public static string? FindGcc(string arch)
    {
        if (!GccPrefix.TryGetValue(arch, out var prefix)) return null;
        var gccName = $"{prefix}-gcc.exe";

        foreach (var path in MingwPathsFor(arch))
        {
            var full = Path.Combine(path, gccName);
            if (File.Exists(full)) return full;
        }

        return FindInPath(gccName);
    }

    /// <summary>
    /// Locate vcvarsall.bat — the entry point for setting up an MSVC build
    /// environment. Required when an evasion technique uses MSVC-only constructs
    /// (HardwareBreakPointLib's #pragma section + __declspec, lvalue casts).
    /// Resolution order:
    ///   1. ConfigManager.Current.Tools.MsvcVcvarsAllPath (user override)
    ///   2. Standard VS 2022/2019 install paths under Program Files
    /// Returns null when not found — caller surfaces a configurable error.
    /// </summary>
    public static string? FindMsvcVcvarsAll()
    {
        var configured = ConfigManager.Current.Tools.MsvcVcvarsAllPath;
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured))
            return configured;

        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        // VS 2017+ standard layout. Editions in priority order: BuildTools is
        // smallest, then Community → Pro → Enterprise.
        string[] roots = {
            Path.Combine(pf,  "Microsoft Visual Studio", "2022", "BuildTools"),
            Path.Combine(pf,  "Microsoft Visual Studio", "2022", "Community"),
            Path.Combine(pf,  "Microsoft Visual Studio", "2022", "Professional"),
            Path.Combine(pf,  "Microsoft Visual Studio", "2022", "Enterprise"),
            Path.Combine(pf86,"Microsoft Visual Studio", "2019", "BuildTools"),
            Path.Combine(pf86,"Microsoft Visual Studio", "2019", "Community"),
            Path.Combine(pf86,"Microsoft Visual Studio", "2019", "Professional"),
            Path.Combine(pf86,"Microsoft Visual Studio", "2019", "Enterprise"),
        };
        foreach (var r in roots)
        {
            var p = Path.Combine(r, "VC", "Auxiliary", "Build", "vcvarsall.bat");
            if (File.Exists(p)) return p;
        }
        return null;
    }

    public static string? FindWindres(string arch)
    {
        if (!GccPrefix.TryGetValue(arch, out var prefix)) return null;
        var names = new[] { $"{prefix}-windres.exe", "windres.exe" };
        var paths = MingwPathsFor(arch);

        foreach (var name in names)
        foreach (var path in paths)
        {
            var full = Path.Combine(path, name);
            if (File.Exists(full)) return full;
        }

        foreach (var name in names)
        {
            var found = FindInPath(name);
            if (found != null) return found;
        }
        return null;
    }

    public static async Task<BuildResult> CompileDllAsync(
        string sourceFile, string defFile, string outputFile, string arch,
        IEnumerable<string>? includeDirs = null,
        IEnumerable<string>? extraObjects = null,
        IProgress<string>? progress = null)
    {
        var gcc = FindGcc(arch);
        if (gcc == null)
            return new BuildResult { Errors = $"MinGW GCC for {arch} not found" };

        var args = new List<string> { "-shared", "-static", "-o", outputFile, sourceFile, defFile };

        if (extraObjects != null)
            args.AddRange(extraObjects);

        if (includeDirs != null)
            foreach (var inc in includeDirs)
                args.AddRange(new[] { "-I", inc });

        args.AddRange(new[] { "-luser32", "-lkernel32", "-ladvapi32", "-Os", "-s", "-w" });

        progress?.Report($"Compiling: {Path.GetFileName(sourceFile)} -> {Path.GetFileName(outputFile)} ({arch})");

        var result = await RunProcessAsync(gcc, args, arch);

        if (result.Success && File.Exists(outputFile))
        {
            result.OutputPath = outputFile;
            result.OutputSize = new FileInfo(outputFile).Length;

            // Quick validation with PeNet — failure here is informational, not fatal
            try
            {
                var pe = new PeNet.PeFile(outputFile);
                result.ExportCount = pe.ExportedFunctions?.Length ?? 0;
            }
            catch (Exception ex)
            {
                Log.Warn("build", $"Produced DLL could not be re-parsed for validation: {outputFile}", ex);
            }

            progress?.Report($"Success: {Path.GetFileName(outputFile)} ({result.OutputSize:N0} bytes, {result.ExportCount} exports)");
        }
        else
        {
            progress?.Report($"Compilation failed");
        }

        return result;
    }

    public static async Task<bool> CompileResourceAsync(string rcFile, string outputObj, string arch,
        IProgress<string>? progress = null)
    {
        var windres = FindWindres(arch);
        if (windres == null)
        {
            progress?.Report("windres not found");
            return false;
        }

        progress?.Report($"Compiling resource: {Path.GetFileName(rcFile)}");

        var result = await RunProcessAsync(windres, [rcFile, "-o", outputObj], arch);
        return result.Success && File.Exists(outputObj);
    }

    public static void StompTimestamps(string sourceFile, string targetFile)
    {
        var fi = new FileInfo(sourceFile);
        File.SetCreationTime(targetFile, fi.CreationTime);
        File.SetLastWriteTime(targetFile, fi.LastWriteTime);
        File.SetLastAccessTime(targetFile, fi.LastAccessTime);
    }

    private static async Task<BuildResult> RunProcessAsync(string exe, IEnumerable<string> args, string arch)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        // ArgumentList is individually escaped per-arg by the runtime — no shell interpolation,
        // no quoting issues with spaces/quotes/backslashes in file paths. Safer than joining
        // into a single Arguments string.
        foreach (var a in args) psi.ArgumentList.Add(a);

        // Add MinGW to PATH so child linker finds cc1.exe, libgcc, etc.
        var paths = MingwPathsFor(arch);
        if (paths.Length > 0)
        {
            var currentPath = psi.Environment.TryGetValue("PATH", out var p) ? p ?? "" : "";
            psi.Environment["PATH"] = string.Join(';', paths) + ";" + currentPath;
        }

        Process? proc = null;
        try
        {
            proc = Process.Start(psi);
            if (proc == null)
            {
                Log.Error("build", $"Failed to start process: {exe}");
                return new BuildResult { Success = false, Errors = $"Could not start {exe}" };
            }
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            return new BuildResult
            {
                Success = proc.ExitCode == 0,
                Output = stdout,
                Errors = stderr,
            };
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Log.Error("build", $"Win32 error running {exe}", ex);
            return new BuildResult { Success = false, Errors = ex.Message };
        }
        finally
        {
            proc?.Dispose();
        }
    }

    private static string? FindInPath(string filename)
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathVar.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var full = Path.Combine(dir, filename);
            if (File.Exists(full)) return full;
        }
        return null;
    }
}
