using DllSidecar.Core.Models;
using DllSidecar.Core.Services;
using DllSidecar.Core.Services.Compilation;

namespace DllSidecar.Core.Tests.Services;

public sealed class MsvcTheoryAttribute : TheoryAttribute
{
    public MsvcTheoryAttribute()
    {
        if (MsvcBackend.FindVcVarsAll() == null)
            Skip = "Visual Studio C++ tools are required for native compilation tests";
    }
}

public sealed class BothCompilersTheoryAttribute : TheoryAttribute
{
    public BothCompilersTheoryAttribute()
    {
        if (MsvcBackend.FindVcVarsAll() == null || BuildSystem.FindGcc("x64") == null || BuildSystem.FindGcc("x86") == null)
            Skip = "MSVC and both MinGW architectures are required for cross-backend tests";
    }
}

public class CompilerBackendTests
{
    [MsvcTheory]
    [InlineData("x64", "Example=sample_orig.Example @17")]
    [InlineData("x86", "Example=sample_orig.Example @17")]
    [InlineData("x64", "Ordinal=sample_orig.#17 @17 NONAME")]
    public async Task NativeForwarderDefinitionLinks(string arch, string definition)
    {
        var dir = Path.Combine(Path.GetTempPath(), "DllSidecar compiler tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var source = Path.Combine(dir, "test.c");
            var def = Path.Combine(dir, "test.def");
            await File.WriteAllTextAsync(source, "#include <windows.h>\nBOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) { return TRUE; }");
            await File.WriteAllTextAsync(def, "LIBRARY sample\nEXPORTS\n " + definition + "\n");
            var result = await BuildSystem.CompileDllAsync(source, def, Path.Combine(dir, "sample.dll"), arch,
                compiler: CompilerKind.Msvc);
            Assert.True(result.Success, definition + "\n" + result.Output + "\n" + result.Errors);
            var export = PeAnalyzer.Analyze(Path.Combine(dir, "sample.dll")).Exports.Single();
            Assert.Equal(definition.Contains("NONAME") ? "sample_orig.#17" : "sample_orig.Example", export.ForwardedTo);
            Assert.Equal(17, export.Ordinal);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("void f() { __asm__(\"nop\"); }")]
    [InlineData("void __attribute__((naked)) f();")]
    [InlineData("#include \"dinvoke.h\"")]
    public void MsvcRejectsGnuTemplatesWithActionableReason(string source)
    {
        Assert.Contains("MinGW", MsvcBackend.CompatibilityProblem(source));
        Assert.Null(MsvcBackend.CompatibilityProblem("#include <windows.h>\nint answer(void) { return 42; }"));
    }

    [MsvcTheory]
    [InlineData("x64")]
    [InlineData("x86")]
    [Trait("Category", "NativeCompiler")]
    public async Task MsvcCompilesHarmlessDllWithNamesOrdinalsAndResources(string arch)
    {
        var dir = Path.Combine(Path.GetTempPath(), "DllSidecar compiler tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var source = Path.Combine(dir, "sample.c");
            var def = Path.Combine(dir, "sample.def");
            var output = Path.Combine(dir, "sample.dll");
            var rc = Path.Combine(dir, "sample.rc");
            var resource = Path.Combine(dir, "sample.res");
            await File.WriteAllTextAsync(source, "#include <windows.h>\nint named(void) { return 42; }\nint ordinal(void) { return 7; }\nBOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) { return TRUE; }");
            await File.WriteAllTextAsync(def, "LIBRARY sample\nEXPORTS\n named @1\n ordinal @17 NONAME\n");
            await File.WriteAllTextAsync(rc, "1 RCDATA { 1, 2, 3, 4 }\n");
            Assert.True(await BuildSystem.CompileResourceAsync(rc, resource, arch, compiler: CompilerKind.Msvc));
            var result = await BuildSystem.CompileDllAsync(source, def, output, arch,
                extraObjects: [resource], compiler: CompilerKind.Msvc);
            Assert.True(result.Success, result.Output + "\n" + result.Errors + "\n" + await File.ReadAllTextAsync(def));
            Assert.Equal(CompilerKind.Msvc, result.Compiler);
            var pe = PeAnalyzer.Analyze(output);
            Assert.True(pe.IsDll);
            Assert.Equal(arch, pe.Arch);
            Assert.Contains(pe.Exports, e => e.Name == "named" && e.Ordinal == 1);
            Assert.Contains(pe.Exports, e => e.Ordinal == 17 && string.IsNullOrEmpty(e.Name));
        }
        finally { Directory.Delete(dir, true); }
    }

    [BothCompilersTheory]
    [InlineData("x64", GenerationMode.Sideload, CompilerKind.Msvc)]
    [InlineData("x86", GenerationMode.Sideload, CompilerKind.Msvc)]
    [InlineData("x64", GenerationMode.Proxy, CompilerKind.Msvc)]
    [InlineData("x86", GenerationMode.Proxy, CompilerKind.Msvc)]
    [InlineData("x64", GenerationMode.Sideload, CompilerKind.MinGW)]
    [InlineData("x86", GenerationMode.Sideload, CompilerKind.MinGW)]
    [InlineData("x64", GenerationMode.Proxy, CompilerKind.MinGW)]
    [InlineData("x86", GenerationMode.Proxy, CompilerKind.MinGW)]
    [Trait("Category", "NativeCompiler")]
    public async Task PortableGeneratedSourceCompilesWithoutRunningIt(string arch, GenerationMode mode, CompilerKind compiler)
    {
        var dir = Path.Combine(Path.GetTempPath(), "DllSidecar compiler tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var pe = new PeAnalysis { Path = Path.Combine(dir, "sample.dll"), Filename = "sample.dll", Arch = arch, IsDll = true,
                Exports = [new() { Name = "Example", Ordinal = 17, Rva = 4096 }] };
            var config = new TemplateConfig { Mode = mode, Compiler = compiler,
                Payload = PayloadType.MessageBox, WriteProofFile = false };
            var files = TemplateEngine.Generate(pe, config);
            foreach (var (name, content) in files)
                await File.WriteAllTextAsync(Path.Combine(dir, name), content);
            var source = Directory.GetFiles(dir, "*.c").Single(f => !f.EndsWith(".msvc_exports.c"));
            var def = Directory.GetFiles(dir, "*.def").Single(f => !f.EndsWith(".msvc.def"));
            var result = await BuildSystem.CompileDllAsync(source, def, pe.Path, arch, compiler: compiler);
            Assert.True(result.Success, result.Output + "\n" + result.Errors);
            Assert.Equal(arch, PeAnalyzer.Analyze(pe.Path).Arch);
            Assert.Equal(compiler, result.Compiler);
            if (mode == GenerationMode.Proxy)
            {
                var export = PeAnalyzer.Analyze(pe.Path).Exports.Single(e => e.Name == "Example");
                Assert.Equal(17, export.Ordinal);
                Assert.Equal("sample_orig.Example", export.ForwardedTo);
            }

            // Execute only the build section, never deployment/launch or the generated DLL.
            var script = CompilerScriptWriter.Write(pe, config, Path.GetFileNameWithoutExtension(source), mode.ToString().ToLowerInvariant());
            var scriptPath = Path.Combine(dir, "compile-only.bat");
            await File.WriteAllTextAsync(scriptPath, script);
            await File.WriteAllTextAsync(Path.Combine(dir, "version.rc"), "1 RCDATA { 1, 2, 3, 4 }\n");
            File.Delete(pe.Path);
            var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe")
            {
                Arguments = $"/d /s /c \"\"{scriptPath}\"\"", WorkingDirectory = dir,
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var process = System.Diagnostics.Process.Start(psi)!;
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException) { process.Kill(true); throw; }
            Assert.True(process.ExitCode == 0, await stdout + "\n" + await stderr);
            var output = PeAnalyzer.Analyze(pe.Path);
            Assert.Equal(arch, output.Arch);
            if (mode == GenerationMode.Proxy)
                Assert.Equal("sample_orig.Example", output.Exports.Single(e => e.Name == "Example").ForwardedTo);
        }
        finally { Directory.Delete(dir, true); }
    }
}
