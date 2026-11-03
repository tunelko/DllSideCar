using System.Diagnostics;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services.Compilation;

public sealed class MsvcBackend : ICompilerBackend
{
    public CompilerKind Kind => CompilerKind.Msvc;

    public static string? CompatibilityProblem(string source)
    {
        if (source.Contains("__asm", StringComparison.Ordinal) || source.Contains("__attribute__", StringComparison.Ordinal))
            return "This source uses GNU assembly/attributes. Select MinGW for this template.";
        foreach (var header in new[] { "dinvoke.h", "syscalls.h", "syscalls_indirect.h", "unhook.h", "etw.h", "cryptor.h" })
            if (source.Contains('"' + header + '"', StringComparison.Ordinal))
                return $"{header} belongs to the MinGW template set. Select MinGW.";
        return null;
    }

    public static string? FindVcVarsAll()
    {
        var configured = ConfigManager.Current.Compiler.VcVarsAllPath;
        if (!string.IsNullOrWhiteSpace(configured)) return File.Exists(configured) ? configured : null;
        var install = Environment.GetEnvironmentVariable("VSINSTALLDIR");
        if (!string.IsNullOrEmpty(install))
        {
            var path = Path.Combine(install, "VC", "Auxiliary", "Build", "vcvarsall.bat");
            if (File.Exists(path)) return path;
        }
        var vswhere = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Microsoft Visual Studio", "Installer", "vswhere.exe");
        if (!File.Exists(vswhere)) return null;
        try
        {
            var psi = new ProcessStartInfo(vswhere)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
            };
            foreach (var arg in new[] { "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath" })
                psi.ArgumentList.Add(arg);
            using var proc = Process.Start(psi);
            if (proc == null) return null;
            var read = proc.StandardOutput.ReadToEndAsync();
            if (!proc.WaitForExit(5000)) { proc.Kill(true); return null; }
            var root = read.GetAwaiter().GetResult().Trim();
            if (root.Length == 0) return null;
            var path = Path.Combine(root, "VC", "Auxiliary", "Build", "vcvarsall.bat");
            return File.Exists(path) ? path : null;
        }
        catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception or InvalidOperationException)
        { return null; }
    }

    private static async Task<Dictionary<string, string>> EnvironmentFor(string arch)
    {
        if (arch is not ("x86" or "x64")) throw new InvalidOperationException($"Unsupported MSVC architecture: {arch}");
        var script = FindVcVarsAll() ?? throw new FileNotFoundException("Visual Studio C++ Build Tools not found (vcvarsall.bat)");
        if (script.IndexOfAny(['"', '%', '\r', '\n']) >= 0)
            throw new InvalidOperationException("vcvarsall path contains unsupported command characters");
        // Only the toolchain initialization goes through cmd. File names and compiler arguments use ArgumentList.
        var psi = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"))
        {
            Arguments = $"/d /s /c \"\"{script}\" {arch} >nul && set\"",
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        using var proc = Process.Start(psi) ?? throw new IOException("Could not initialize MSVC");
        var stdout = proc.StandardOutput.ReadToEndAsync();
        var stderr = proc.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await proc.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { proc.Kill(true); throw new TimeoutException("MSVC initialization timed out"); }
        if (proc.ExitCode != 0) throw new IOException("vcvarsall failed: " + await stderr);
        var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in (await stdout).Split('\n'))
        {
            var separator = line.IndexOf('=');
            if (separator > 0) env[line[..separator]] = line[(separator + 1)..].TrimEnd('\r');
        }
        return env;
    }

    internal static string? FindTool(Dictionary<string, string> env, string name) =>
        env.GetValueOrDefault("PATH", "").Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => Path.Combine(p.Trim('"'), name)).FirstOrDefault(File.Exists);

    public async Task<BuildResult> CompileAsync(DllBuildRequest r)
    {
        string? scratch = null;
        try
        {
            var problem = CompatibilityProblem(await File.ReadAllTextAsync(r.SourceFile));
            if (problem != null) return new() { Errors = problem, Compiler = CompilerKind.Msvc };
            var env = await EnvironmentFor(r.Arch);
            var cl = FindTool(env, "cl.exe") ?? throw new FileNotFoundException("cl.exe missing from MSVC environment");
            var outDir = Path.GetDirectoryName(Path.GetFullPath(r.OutputFile))!;
            scratch = Path.Combine(Path.GetTempPath(), "DllSidecar.msvc", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(scratch);
            var definition = MsvcDefinitionAdapter.Adapt(await File.ReadAllTextAsync(r.DefFile));
            var defFile = Path.GetFullPath(r.DefFile);
            var args = new List<string>
            {
                "/nologo", "/LD", "/MT", "/TC", "/W3", "/O1", "/utf-8", "/D_CRT_SECURE_NO_WARNINGS",
                "/Fo" + scratch + Path.DirectorySeparatorChar, Path.GetFullPath(r.SourceFile),
            };
            if (definition.Forwarders > 0)
            {
                defFile = Path.Combine(scratch, "exports.def");
                var directives = Path.Combine(scratch, "forwarders-" + Guid.NewGuid().ToString("N") + ".c");
                await File.WriteAllTextAsync(defFile, definition.Definition);
                await File.WriteAllTextAsync(directives, definition.Directives);
                args.Add(directives);
                r.Progress?.Report($"MSVC: preserving {definition.Forwarders} forwarders via object directives");
            }
            foreach (var inc in r.IncludeDirs ?? []) args.Add("/I" + Path.GetFullPath(inc));
            args.Add("/link");
            args.Add("/OUT:" + Path.GetFullPath(r.OutputFile));
            args.Add("/IMPLIB:" + Path.ChangeExtension(Path.GetFullPath(r.OutputFile), ".lib"));
            args.Add("/DEF:" + defFile);
            args.Add("/MACHINE:" + (r.Arch == "x86" ? "X86" : "X64"));
            args.AddRange(r.ExtraObjects ?? []);
            args.AddRange(new[] { "user32.lib", "kernel32.lib", "advapi32.lib" });
            args.AddRange((r.ExtraLibs ?? []).Select(l => l.EndsWith(".lib", StringComparison.OrdinalIgnoreCase) ? l : l + ".lib"));
            r.Progress?.Report($"Compiling with MSVC ({r.Arch}): {cl}");
            var result = await Run(cl, args, env, outDir);
            result.Compiler = CompilerKind.Msvc;
            if (result.Success)
            {
                var pe = PeAnalyzer.Analyze(r.OutputFile);
                if (!pe.IsDll || pe.Arch != r.Arch) return new() { Errors = "MSVC output PE architecture/type mismatch", Compiler = CompilerKind.Msvc };
                result.OutputPath = r.OutputFile;
                result.OutputSize = new FileInfo(r.OutputFile).Length;
                result.ExportCount = pe.Exports.Count;
            }
            return result;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or TimeoutException or System.ComponentModel.Win32Exception)
        { return new() { Errors = ex.Message, Compiler = CompilerKind.Msvc }; }
        finally
        {
            if (scratch != null)
                try { Directory.Delete(scratch, true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { r.Progress?.Report("Could not remove MSVC temporary build directory: " + ex.Message); }
        }
    }

    public static async Task<bool> CompileResource(string input, string output, string arch, IProgress<string>? progress)
    {
        try
        {
            var env = await EnvironmentFor(arch);
            var rc = FindTool(env, "rc.exe") ?? throw new FileNotFoundException("Windows SDK rc.exe not found");
            var result = await Run(rc, ["/nologo", "/fo", output, input], env, Path.GetDirectoryName(Path.GetFullPath(output))!);
            if (!result.Success) progress?.Report(result.Errors);
            return result.Success && File.Exists(output);
        }
        catch (Exception ex) { progress?.Report("MSVC resource build failed: " + ex.Message); return false; }
    }

    private static async Task<BuildResult> Run(string exe, IEnumerable<string> args, Dictionary<string, string> env, string workingDir)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
            RedirectStandardError = true, WorkingDirectory = workingDir,
        };
        foreach (var arg in args) psi.ArgumentList.Add(arg);
        foreach (var (key, value) in env) psi.Environment[key] = value;
        using var proc = Process.Start(psi) ?? throw new IOException("Could not start MSVC tool");
        var stdout = proc.StandardOutput.ReadToEndAsync();
        var stderr = proc.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try { await proc.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { proc.Kill(true); throw new TimeoutException("MSVC compilation timed out"); }
        var output = await stdout;
        var error = await stderr;
        return new() { Success = proc.ExitCode == 0, Output = output, Errors = proc.ExitCode == 0 ? error : output + "\n" + error };
    }
}
