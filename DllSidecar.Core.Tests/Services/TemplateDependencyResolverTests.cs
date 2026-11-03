using DllSidecar.Core.Services;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Tests.Services;

public class TemplateDependencyResolverTests
{
    [Theory]
    [InlineData("etw.h")]
    [InlineData("syscalls.h")]
    [InlineData("syscalls_indirect.h")]
    [InlineData("unhook.h")]
    public void SpecializedHeaderPullsItsDinvokeDependency(string header)
    {
        var templates = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "templates"));
        var required = TemplateDependencyResolver.ResolveRequiredHeaders(
            [$"#include <windows.h>\n#include \"{header}\""], templates);

        Assert.Equal([header, "dinvoke.h"], required);
    }

    [Fact]
    public void CopiesTransitiveDependenciesOnceAndRejectsMissingHeaders()
    {
        var root = Path.Combine(Path.GetTempPath(), "DllSidecar dependency tests", Guid.NewGuid().ToString("N"));
        var templates = Path.Combine(root, "templates");
        var output = Path.Combine(root, "output");
        Directory.CreateDirectory(templates);
        try
        {
            File.WriteAllText(Path.Combine(templates, "outer.h"), "#include \"inner.h\"\n#include \"inner.h\"");
            File.WriteAllText(Path.Combine(templates, "inner.h"), "#pragma once");
            var copied = TemplateDependencyResolver.CopyRequiredHeaders(["#include \"outer.h\""], templates, output);
            Assert.Equal(["outer.h", "inner.h"], copied);
            Assert.True(File.Exists(Path.Combine(output, "outer.h")));
            Assert.True(File.Exists(Path.Combine(output, "inner.h")));
            Assert.Throws<FileNotFoundException>(() =>
                TemplateDependencyResolver.ResolveRequiredHeaders(["#include \"missing.h\""], templates));
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    [Trait("Category", "NativeCompiler")]
    public async Task EtwEnabledProxyCompilesWithItsTransitiveHeaders()
    {
        if (BuildSystem.FindGcc("x64") == null) return;
        var root = Path.Combine(Path.GetTempPath(), "DllSidecar dependency tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var templates = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "templates"));
            var pe = new PeAnalysis
            {
                Path = Path.Combine(root, "sample.dll"), Filename = "sample.dll", Arch = "x64", IsDll = true,
                Exports = [new() { Name = "Example", Ordinal = 1, Rva = 4096 }],
            };
            var files = TemplateEngine.Generate(pe, new()
            {
                Mode = GenerationMode.Proxy, Compiler = CompilerKind.MinGW,
                Payload = PayloadType.MessageBox, PatchEtw = true, WriteProofFile = false,
            });
            foreach (var (name, content) in files)
                await File.WriteAllTextAsync(Path.Combine(root, name), content);
            var copied = TemplateDependencyResolver.CopyRequiredHeaders(files.Values, templates, root);
            Assert.Contains("etw.h", copied);
            Assert.Contains("dinvoke.h", copied);

            var source = Directory.GetFiles(root, "*.c").Single(f => !f.EndsWith(".msvc_exports.c"));
            var def = Directory.GetFiles(root, "*.def").Single(f => !f.EndsWith(".msvc.def"));
            var result = await BuildSystem.CompileDllAsync(source, def, pe.Path, "x64",
                includeDirs: [root], compiler: CompilerKind.MinGW);
            Assert.True(result.Success, result.Output + "\n" + result.Errors);
            Assert.True(PeAnalyzer.Analyze(pe.Path).IsDll);
        }
        finally { Directory.Delete(root, true); }
    }
}
