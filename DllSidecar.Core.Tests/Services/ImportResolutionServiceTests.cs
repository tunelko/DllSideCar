using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.Core.Tests.Services;

public class ImportResolutionServiceTests
{
    [Fact]
    public void Resolve_LocalPeWithMatchingArchitecture_ReturnsExactLocalPath()
    {
        var importer = Pe(@"C:\Suite\app.exe", "x64", isDll: false, "helper.dll");
        var candidate = Pe(@"C:\Suite\helper.dll", "x64", isDll: true);
        var scanned = Index(importer, candidate);

        var result = ImportResolutionService.Resolve(importer, importer.Imports[0], scanned, EmptyEnvironment());

        Assert.Equal(ImportResolutionKind.ResolvedLocal, result.Kind);
        Assert.True(ImportResolutionService.PathsEqual(candidate.Path, result.ResolvedPath));
        Assert.Contains(result.Steps, step =>
            step.Location == ImportSearchLocationKind.LocalDirectory
            && step.Outcome == ImportSearchOutcome.Found);
    }

    [Fact]
    public void Resolve_LocalPeWithWrongArchitecture_ReturnsAmbiguous()
    {
        var importer = Pe(@"C:\Suite\app.exe", "x64", isDll: false, "helper.dll");
        var candidate = Pe(@"C:\Suite\helper.dll", "x86", isDll: true);

        var result = ImportResolutionService.Resolve(
            importer, importer.Imports[0], Index(importer, candidate), EmptyEnvironment());

        Assert.Equal(ImportResolutionKind.Ambiguous, result.Kind);
        Assert.Contains("does not match", result.Reason);
    }

    [Fact]
    public void Resolve_X86_DoesNotUseDllFoundOnlyInX64SystemDirectory()
    {
        const string dllName = "architecture_only.dll";
        var importer = Pe(@"C:\Suite\app.exe", "x86", isDll: false, dllName);
        var environment = EnvironmentWithExisting(@"C:\Windows\System32\architecture_only.dll");

        var result = ImportResolutionService.Resolve(
            importer, importer.Imports[0], Index(importer), environment);

        Assert.Equal(ImportResolutionKind.Unresolved, result.Kind);
        Assert.Contains(result.Steps, step =>
            step.Location == ImportSearchLocationKind.OtherArchitectureSystemDirectory
            && step.Outcome == ImportSearchOutcome.Skipped);
    }

    [Fact]
    public void PhantomDetector_SystemFallback_EmitsPlantableLocalSlot()
    {
        const string dllName = "fallback_test.dll";
        var importer = Pe(@"C:\Suite\app.exe", "x64", isDll: false, dllName);
        var environment = EnvironmentWithExisting(@"C:\Windows\System32\fallback_test.dll");

        var hits = PhantomDetector.Find(importer, Index(importer), environment);

        var hit = Assert.Single(hits);
        Assert.Equal(ImportResolutionKind.ResolvedSystem, hit.Resolution.Kind);
        Assert.True(ImportResolutionService.PathsEqual(
            @"C:\Windows\System32\fallback_test.dll", hit.Resolution.ResolvedPath));
        Assert.Contains(hit.Resolution.Steps, step =>
            step.Location == ImportSearchLocationKind.LocalDirectory
            && step.Outcome == ImportSearchOutcome.NotFound);
    }

    [Fact]
    public void PhantomDetector_System32Only_DoesNotEmitLocalSlot()
    {
        const string dllName = "restricted_test.dll";
        var importer = Pe(@"C:\Suite\app.exe", "x64", isDll: false, dllName);
        importer.Security.DependentLoadFlags = 0x800;
        var local = Pe(@"C:\Suite\restricted_test.dll", "x64", isDll: true);
        var environment = EnvironmentWithExisting(
            @"C:\Suite\restricted_test.dll",
            @"C:\Windows\System32\restricted_test.dll");

        var hits = PhantomDetector.Find(importer, Index(importer, local), environment);

        Assert.Empty(hits);
        var resolution = ImportResolutionService.Resolve(
            importer, importer.Imports[0], Index(importer, local), environment);
        Assert.Equal(ImportResolutionKind.ResolvedSystem, resolution.Kind);
        Assert.Contains(resolution.Steps, step =>
            step.Location == ImportSearchLocationKind.LocalDirectory
            && step.Outcome == ImportSearchOutcome.Skipped);
    }

    [Fact]
    public void Resolve_DllImporterWithSameNameElsewhere_IsAmbiguous()
    {
        const string dllName = "shared_test.dll";
        var importer = Pe(@"C:\Suite\plugins\plugin.dll", "x64", isDll: true, dllName);
        var otherCopy = Pe(@"C:\Suite\shared_test.dll", "x64", isDll: true);

        var result = ImportResolutionService.Resolve(
            importer, importer.Imports[0], Index(importer, otherCopy), EmptyEnvironment());

        Assert.Equal(ImportResolutionKind.Ambiguous, result.Kind);
        Assert.Contains(result.Steps, step =>
            step.Location == ImportSearchLocationKind.OtherScannedDirectory);
    }

    [Fact]
    public void Score_SystemFallback_ImprovesStaticConfidenceWithoutInflatingImpact()
    {
        var phantom = new PhantomCandidate
        {
            DllName = "fallback_test.dll",
            DirectoryPath = @"C:\Suite",
            StaticResolutionKind = ImportResolutionKind.ResolvedSystem,
            Dir = new DirectoryPermissions { Path = @"C:\Suite" },
            Importers =
            [
                new ImporterRef
                {
                    ExePath = @"C:\Suite\app.exe",
                    ExeFilename = "app.exe",
                    ResolutionKind = ImportResolutionKind.ResolvedSystem,
                    ResolvedImportPath = @"C:\Windows\System32\fallback_test.dll",
                },
            ],
        };

        var score = ExploitabilityScorer.ScorePhantom(phantom);

        Assert.Equal(2, score.Exploitability);
        Assert.Equal(3, score.Confidence);
        Assert.Equal(1, score.Impact);
        Assert.Contains(score.Factors, factor => factor.Name == "SystemFallbackSlot");
        Assert.Contains(score.Factors, factor => factor.Name == "StaticPathResolved");
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

    private static Dictionary<string, PeAnalysis> Index(params PeAnalysis[] files) =>
        files.ToDictionary(file => file.Path, StringComparer.OrdinalIgnoreCase);

    private static ImportResolutionEnvironment EmptyEnvironment() => new()
    {
        System32Directory = @"C:\Windows\System32",
        SysWow64Directory = @"C:\Windows\SysWOW64",
        FileExists = _ => false,
    };

    private static ImportResolutionEnvironment EnvironmentWithExisting(params string[] paths)
    {
        var existing = paths.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return new ImportResolutionEnvironment
        {
            System32Directory = @"C:\Windows\System32",
            SysWow64Directory = @"C:\Windows\SysWOW64",
            FileExists = path => existing.Any(item => ImportResolutionService.PathsEqual(item, path)),
        };
    }
}
