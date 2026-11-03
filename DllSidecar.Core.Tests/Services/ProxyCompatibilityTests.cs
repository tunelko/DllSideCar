using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.Core.Tests.Services;

public class ProxyCompatibilityTests
{
    private static PeAnalysis Pe(string name, bool dll = false) => new()
        { Filename = name, Path = @"C:\fixture\" + name, Arch = "x64", IsDll = dll };

    [Fact]
    public void CoversNamesAndOrdinalsAndKeepsCaseSensitiveNames()
    {
        var importer = Pe("app.exe");
        importer.Imports.Add(new() { DllName = "lib.dll", Functions = ["Entry"], Ordinals = [17], SymbolsComplete = true });
        var dll = Pe("lib.dll", true);
        dll.Exports = [new() { Name = "Entry", Ordinal = 1, Rva = 123 }, new() { Ordinal = 17, Rva = 124 }];
        Assert.Equal(ProxyReadinessLevel.Ready, ProxyCompatibilityAnalyzer.Evaluate(importer, "LIB.dll", dll).Level);
        dll.Exports[0].Name = "entry";
        var missing = ProxyCompatibilityAnalyzer.Evaluate(importer, "lib.dll", dll);
        Assert.Equal(ProxyReadinessLevel.Unsafe, missing.Level);
        Assert.Contains("Entry", missing.Missing);
    }

    [Fact]
    public void ForwardersIncompleteImportsAndWrongArchitectureAreNotReady()
    {
        var importer = Pe("app.exe");
        importer.Imports.Add(new() { DllName = "lib.dll", Functions = ["Entry"], SymbolsComplete = true, IsDelayLoad = true });
        var dll = Pe("lib.dll", true);
        dll.Exports.Add(new() { Name = "Entry", ForwardedTo = "other.Entry", Ordinal = 1 });
        Assert.Equal(ProxyReadinessLevel.Partial, ProxyCompatibilityAnalyzer.Evaluate(importer, "lib.dll", dll).Level);
        dll.Arch = "x86";
        Assert.Equal(ProxyReadinessLevel.Unsafe, ProxyCompatibilityAnalyzer.Evaluate(importer, "lib.dll", dll).Level);
        Assert.Equal(ProxyReadinessLevel.Unknown, ProxyCompatibilityAnalyzer.Evaluate(importer, "lib.dll", null).Level);
    }
}
