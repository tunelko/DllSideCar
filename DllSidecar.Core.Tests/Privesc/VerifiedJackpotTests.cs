using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;
using DllSidecar.Core.Services;
using DllSidecar.Core.Services.Privesc;

namespace DllSidecar.Core.Tests.Privesc;

public class VerifiedJackpotTests
{
    private const string UpdaterPath = @"C:\Program Files\Vendor\updater.exe";

    [Fact]
    public void Analyzer_SystemUpdaterContext_DoesNotClaimJackpotBeforeCandidateValidation()
    {
        var pe = MakePe(UpdaterPath, "updater.exe", isDll: false);
        var analyzer = new PrivescAnalyzer(
        [
            new FixedDetector(MakeFinding(
                PrivescVector.UpdaterHeuristic,
                PrivescSeverity.Informational,
                UpdaterPath,
                "UpdaterHeuristicDetector")),
            new FixedDetector(MakeFinding(
                PrivescVector.ServiceSystem,
                PrivescSeverity.High,
                UpdaterPath,
                "ServicesDetector")),
        ]);
        analyzer.Prepare(@"C:\Program Files\Vendor", [pe], CancellationToken.None);

        var context = analyzer.Analyze(pe, CancellationToken.None);

        Assert.Equal(PrivescSeverity.High, context.HighestSeverity);
        Assert.DoesNotContain(context.Findings, f => f.Severity == PrivescSeverity.Critical);
    }

    [Fact]
    public void SystemUpdater_WithoutWritableDirectory_RemainsHighImpact()
    {
        var candidate = MakeCandidate(userWritable: false, trustedImporter: true);

        var score = ExploitabilityScorer.Score(candidate);

        Assert.Equal(8, score.Impact);
        Assert.DoesNotContain(candidate.Privesc!.Findings,
            f => f.Severity == PrivescSeverity.Critical);
    }

    [Fact]
    public void SystemUpdater_WithoutTrustedImporter_RemainsHighImpact()
    {
        var candidate = MakeCandidate(userWritable: true, trustedImporter: false);

        var score = ExploitabilityScorer.Score(candidate);

        Assert.Equal(8, score.Impact);
        Assert.DoesNotContain(candidate.Privesc!.Findings,
            f => f.Severity == PrivescSeverity.Critical);
    }

    [Fact]
    public void SystemUpdater_WithDelayLoadOnly_RemainsHighImpact()
    {
        var candidate = MakeCandidate(userWritable: true, trustedImporter: true, delayLoad: true);

        var score = ExploitabilityScorer.Score(candidate);

        Assert.Equal(8, score.Impact);
        Assert.DoesNotContain(candidate.Privesc!.Findings,
            f => f.Severity == PrivescSeverity.Critical);
    }

    [Fact]
    public void SystemUpdater_WithSystem32OnlyImporter_RemainsHighImpact()
    {
        var candidate = MakeCandidate(
            userWritable: true,
            trustedImporter: true,
            forcesSystem32Only: true);

        var score = ExploitabilityScorer.Score(candidate);

        Assert.Equal(8, score.Impact);
        Assert.Contains(score.Factors,
            f => f.Axis == ScoreAxis.Exploitability && f.Name == "System32OnlyForced");
        Assert.DoesNotContain(candidate.Privesc!.Findings,
            f => f.Severity == PrivescSeverity.Critical);
    }

    [Fact]
    public void UpdaterAndSystemFindings_FromDifferentPes_RemainHighImpact()
    {
        var candidate = MakeCandidate(
            userWritable: true,
            trustedImporter: true,
            updaterSource: @"C:\Program Files\Vendor\other-updater.exe");

        var score = ExploitabilityScorer.Score(candidate);

        Assert.Equal(8, score.Impact);
        Assert.DoesNotContain(candidate.Privesc!.Findings,
            f => f.Severity == PrivescSeverity.Critical);
    }

    [Fact]
    public void CompleteSystemUpdaterChain_IsPromotedToCriticalIdempotently()
    {
        var candidate = MakeCandidate(userWritable: true, trustedImporter: true);

        var first = ExploitabilityScorer.Score(candidate);
        var second = ExploitabilityScorer.Score(candidate);

        Assert.Equal(10, first.Impact);
        Assert.Equal(10, second.Impact);
        var jackpot = Assert.Single(candidate.Privesc!.Findings.Where(f =>
            f.Extras.TryGetValue("Rule", out var rule) &&
            rule == "VerifiedSystemUpdaterChain"));
        Assert.Equal(PrivescVector.ServiceSystem, jackpot.Vector);
        Assert.Equal(UpdaterPath, jackpot.Extras["SourcePE"]);
        Assert.Contains(second.Factors,
            f => f.Axis == ScoreAxis.Impact && f.Name == "ImpactSystemJackpot");
    }

    private static SideloadCandidate MakeCandidate(
        bool userWritable,
        bool trustedImporter,
        bool delayLoad = false,
        bool forcesSystem32Only = false,
        string updaterSource = UpdaterPath)
    {
        var privesc = new PrivescContext();
        privesc.Findings.Add(MakeFinding(
            PrivescVector.UpdaterHeuristic,
            PrivescSeverity.Informational,
            updaterSource,
            "UpdaterHeuristicDetector"));
        privesc.Findings.Add(MakeFinding(
            PrivescVector.ServiceSystem,
            PrivescSeverity.High,
            UpdaterPath,
            "ServicesDetector"));

        return new SideloadCandidate
        {
            Dll = MakePe(@"C:\Program Files\Vendor\target.dll", "target.dll", isDll: true),
            Dir = new DirectoryPermissions
            {
                Path = @"C:\Program Files\Vendor",
                UsersWrite = userWritable,
                WritableBy = userWritable ? [@"BUILTIN\Users"] : [],
            },
            Importers =
            [
                new ImporterRef
                {
                    ExePath = UpdaterPath,
                    ExeFilename = "updater.exe",
                    Signing = new SigningInfo
                    {
                        Status = trustedImporter ? SigningStatus.Valid : SigningStatus.NotSigned,
                    },
                    IsDelayLoad = delayLoad,
                    ForcesSystem32Only = forcesSystem32Only,
                },
            ],
            Privesc = privesc,
        };
    }

    private static PeAnalysis MakePe(string path, string filename, bool isDll) => new()
    {
        Path = path,
        Filename = filename,
        Arch = "x64",
        IsDll = isDll,
    };

    private static PrivescFinding MakeFinding(
        PrivescVector vector,
        PrivescSeverity severity,
        string sourcePe,
        string detector) => new()
    {
        Vector = vector,
        Severity = severity,
        DetectorName = detector,
        Title = vector.ToString(),
        Evidence = "test",
        PrivilegedProcessPath = sourcePe,
        PrivilegedAccount = severity >= PrivescSeverity.High ? "LocalSystem" : null,
        Extras = { ["SourcePE"] = sourcePe },
    };

    private sealed class FixedDetector(PrivescFinding finding) : IPrivescDetector
    {
        public string Name => "FixedDetector";

        public void Prepare(PrivescDetectorContext ctx, CancellationToken ct) { }

        public IEnumerable<PrivescFinding> Detect(
            PeAnalysis pe,
            PrivescDetectorContext ctx,
            CancellationToken ct)
        {
            yield return finding;
        }
    }
}
