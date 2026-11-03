using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.Core.Tests.Etw;

public class EtwOperationCorrelatorTests
{
    private static EtwTraceEvent Event() => new()
    {
        ProcessId = 42, ProcessName = "fixture.exe", FilePath = @"C:\fixture\sample.dll",
        Timestamp = new DateTime(2026, 1, 1), Access = AccessClass.LoaderLike,
    };

    [Theory]
    [InlineData(0u, "SUCCESS", false)]
    [InlineData(0xC0000034u, "NAME NOT FOUND", true)]
    [InlineData(0xC000003Au, "PATH NOT FOUND", true)]
    [InlineData(0xC0000022u, "ACCESS DENIED", false)]
    public void ActualCompletionDeterminesOutcome(uint status, string label, bool missing)
    {
        var c = new EtwOperationCorrelator();
        var ev = Event();
        c.Begin(1, ev);
        var completed = c.Complete(1, status, ev.Timestamp.AddMilliseconds(1));
        Assert.NotNull(completed);
        Assert.Equal(label, completed.Result);
        Assert.Equal(missing, completed.IsMissing);
        Assert.Null(c.Complete(1, status, ev.Timestamp.AddMilliseconds(2)));
    }

    [Fact]
    public void LostCompletionsAndReusedIrpsDoNotBecomeMissingDlls()
    {
        var c = new EtwOperationCorrelator(2);
        c.Begin(1, Event()); c.Begin(2, Event()); c.Begin(3, Event());
        Assert.Equal(1, c.Uncompleted);
        var newer = Event(); newer.Timestamp = newer.Timestamp.AddSeconds(5);
        c.Begin(3, newer);
        Assert.Null(c.Complete(3, 0xC0000034, newer.Timestamp.AddSeconds(-1)));
        Assert.Equal(4, c.Finish());
    }

    [Fact]
    public void UnknownSuccessfulAndImageLoadEventsAreNotPhantoms()
    {
        var unknown = Event();
        var success = Event(); success.NtStatus = 0;
        var loaded = Event(); loaded.Kind = EtwEventKind.ImageLoad;
        var denied = Event(); denied.NtStatus = 0xC0000022;
        var trace = new EtwTraceResult { Events = [unknown, success, loaded, denied] };
        Assert.Empty(EtwResultConverter.ToPhantomCandidates(trace));
        var parsed = EtwResultConverter.ToProcmonResult(trace);
        Assert.Equal("Load Image", Assert.Single(parsed.Events).Operation);
    }

    [Fact]
    public void RuntimeCorrelationUsesProcessIdentityNotOnlyBasename()
    {
        var candidate = new PhantomCandidate
        {
            DllName = "sample.dll", DirectoryPath = @"C:\fixture",
            Importers = [new() { ExePath = @"C:\correct\fixture.exe", ExeFilename = "fixture.exe" }],
        };
        var ev = Event(); ev.NtStatus = 0xC0000034;
        ev.ProcessImagePath = @"C:\different\fixture.exe";
        var scan = new ScanResults { Phantoms = [candidate] };
        var report = ProcmonCorrelator.Correlate(scan, EtwResultConverter.ToProcmonResult(new() { Events = [ev] }));
        Assert.Equal(0, report.PhantomMatched);
        Assert.Null(candidate.Evidence);
        ev.ProcessImagePath = @"C:\correct\fixture.exe";
        report = ProcmonCorrelator.Correlate(scan, EtwResultConverter.ToProcmonResult(new() { Events = [ev] }));
        Assert.Equal(1, report.PhantomMatched);
        Assert.True(candidate.IsDynamicallyVerified);
        Assert.Equal(1, candidate.Evidence!.VerifiedMissEventCount);
    }

    [Fact]
    public void ImageLoadRaisesOnlyConfidenceWhileUnverifiedLegacyEventsDoNot()
    {
        var score = new ScoreBreakdown { Exploitability = 4, Impact = 8 };
        var evidence = new DynamicEvidence { DllName = "sample.dll", Source = EvidenceSource.RuntimeTrace,
            EventCount = 1, LoaderLikeEventCount = 1, MatchedByDirectory = true };
        ExploitabilityScorer.ApplyDynamicEvidence(score, null, evidence);
        Assert.Equal(3, score.Confidence);
        Assert.False(evidence.HasLoadEvidence);
        evidence.ImageLoadEventCount = 1;
        ExploitabilityScorer.ApplyDynamicEvidence(score, null, evidence);
        Assert.True(evidence.HasLoadEvidence);
        Assert.Equal(9, score.Confidence);
        Assert.Equal(4, score.Exploitability);
        Assert.Equal(8, score.Impact);
    }
}
