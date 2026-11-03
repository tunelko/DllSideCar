using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.Core.Tests.Services;

public class ImportGraphBuilderTests
{
    [Fact]
    public void GetImportersOf_DoesNotCrossAssociateSameBasenameAcrossApplications()
    {
        var appA = Pe(@"C:\Root\AppA\app-a.exe", "x64", isDll: false, "common.dll");
        var dllA = Pe(@"C:\Root\AppA\common.dll", "x64", isDll: true);
        var dllB = Pe(@"C:\Root\AppB\common.dll", "x64", isDll: true);
        var graph = Build(appA, dllA, dllB);

        var importersA = graph.GetImportersOf(dllA);
        var importersB = graph.GetImportersOf(dllB);

        var edge = Assert.Single(importersA);
        Assert.Equal(appA.Path, edge.ImporterPath);
        Assert.Equal(ImportResolutionKind.ResolvedLocal, edge.Resolution!.Kind);
        Assert.Empty(importersB);
    }

    [Fact]
    public void GetImportersOf_RejectsArchitectureMismatch()
    {
        var importer = Pe(@"C:\Root\app.exe", "x64", isDll: false, "x86-only.dll");
        var candidate = Pe(@"C:\Root\x86-only.dll", "x86", isDll: true);
        var graph = Build(importer, candidate);

        Assert.Empty(graph.GetImportersOf(candidate));
    }

    [Fact]
    public void GetImportersOf_System32RestrictionRejectsLocalCopy()
    {
        var importer = Pe(@"C:\Root\app.exe", "x64", isDll: false, "restricted.dll");
        importer.Security.DependentLoadFlags = 0x800;
        var candidate = Pe(@"C:\Root\restricted.dll", "x64", isDll: true);
        var graph = Build(importer, candidate);

        Assert.Empty(graph.GetImportersOf(candidate));
    }

    private static ImportGraphBuilder Build(params PeAnalysis[] analyses)
    {
        var graph = new ImportGraphBuilder();
        foreach (var analysis in analyses) graph.Add(analysis);
        return graph;
    }

    private static PeAnalysis Pe(
        string path,
        string arch,
        bool isDll,
        params string[] imports) => new()
    {
        Path = path,
        Filename = Path.GetFileName(path),
        Arch = arch,
        IsDll = isDll,
        Imports = imports.Select(name => new ImportedDll { DllName = name }).ToList(),
    };
}
