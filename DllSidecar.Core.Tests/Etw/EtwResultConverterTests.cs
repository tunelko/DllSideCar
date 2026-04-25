using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.Core.Tests.Etw;

public class EtwResultConverterTests
{
    private static EtwTraceResult MakeResult(params (string Proc, string Dll, string Dir)[] events)
    {
        var result = new EtwTraceResult();
        foreach (var (proc, dll, dir) in events)
        {
            var ev = new EtwTraceEvent
            {
                ProcessId = 100,
                ProcessName = proc,
                ProcessImagePath = $@"C:\fake\{proc}",
                FilePath = Path.Combine(dir, dll),
                Timestamp = DateTime.Now,
            };
            result.Events.Add(ev);
            result.FilteredEvents++;
        }

        var byDll = result.Events
            .GroupBy(e => e.DllName, StringComparer.OrdinalIgnoreCase);
        foreach (var g in byDll)
        {
            var agg = new ProcmonAggregation { DllName = g.Key };
            foreach (var e in g)
            {
                agg.Processes.Add(e.ProcessName);
                agg.SearchedDirs.Add(e.Directory);
                agg.EventCount++;
            }
            result.ByDll.Add(agg);
        }

        return result;
    }

    [Fact]
    public void ToPhantomCandidates_GroupsByDllAndDir()
    {
        var result = MakeResult(
            ("Acrobat.exe", "AID.dll", @"C:\Program Files\Adobe"),
            ("Acrobat.exe", "AID.dll", @"C:\Program Files\Adobe"),
            ("Acrobat.exe", "AID.dll", @"C:\Windows\System32"));

        var phantoms = EtwResultConverter.ToPhantomCandidates(result);

        Assert.Equal(2, phantoms.Count);
        Assert.All(phantoms, p => Assert.Equal("AID.dll", p.DllName));
    }

    [Fact]
    public void ToPhantomCandidates_DedupCollapsesDuplicateEvents()
    {
        var result = MakeResult(
            ("App.exe", "test.dll", @"C:\fake\dir"),
            ("App.exe", "test.dll", @"C:\fake\dir"),
            ("App.exe", "test.dll", @"C:\fake\dir"));

        var phantoms = EtwResultConverter.ToPhantomCandidates(result);

        Assert.Single(phantoms);
        Assert.Equal(3, phantoms[0].Evidence!.EventCount);
    }

    [Fact]
    public void ToPhantomCandidates_SetsRuntimeTraceSource()
    {
        var result = MakeResult(("App.exe", "evil.dll", @"C:\fake"));

        var phantoms = EtwResultConverter.ToPhantomCandidates(result);

        Assert.Single(phantoms);
        Assert.Equal(EvidenceSource.RuntimeTrace, phantoms[0].Evidence!.Source);
        Assert.True(phantoms[0].Evidence!.IsRuntimeObserved);
    }

    [Fact]
    public void ToPhantomCandidates_HasScore()
    {
        var result = MakeResult(("App.exe", "test.dll", @"C:\fake"));

        var phantoms = EtwResultConverter.ToPhantomCandidates(result);

        Assert.Single(phantoms);
        Assert.True(phantoms[0].Score.Total > 0);
        Assert.True(phantoms[0].Score.Confidence > 3,
            "Runtime-traced phantom should have Confidence > static floor");
    }

    [Fact]
    public void ToPhantomCandidates_MultipleProcessImages_CreateMultipleImporters()
    {
        var result = new EtwTraceResult();
        result.Events.Add(new EtwTraceEvent
        {
            ProcessId = 100, ProcessName = "A.exe",
            ProcessImagePath = @"C:\A.exe",
            FilePath = @"C:\dir\test.dll", Timestamp = DateTime.Now,
        });
        result.Events.Add(new EtwTraceEvent
        {
            ProcessId = 200, ProcessName = "B.exe",
            ProcessImagePath = @"C:\B.exe",
            FilePath = @"C:\dir\test.dll", Timestamp = DateTime.Now,
        });
        result.FilteredEvents = 2;
        result.ByDll.Add(new ProcmonAggregation
        {
            DllName = "test.dll", EventCount = 2,
            Processes = { "A.exe", "B.exe" },
            SearchedDirs = { @"C:\dir" },
        });

        var phantoms = EtwResultConverter.ToPhantomCandidates(result);

        Assert.Single(phantoms);
        Assert.Equal(2, phantoms[0].Importers.Count);
    }

    [Fact]
    public void DeduplicatedSummary_GroupsByProcessDllDir()
    {
        var result = MakeResult(
            ("A.exe", "x.dll", @"C:\d1"),
            ("A.exe", "x.dll", @"C:\d1"),
            ("B.exe", "x.dll", @"C:\d1"),
            ("A.exe", "x.dll", @"C:\d2"));

        var summary = EtwResultConverter.DeduplicatedSummary(result);

        Assert.Equal(3, summary.Count);
    }

    [Fact]
    public void ToProcmonResult_ProducesValidParseResult()
    {
        var result = MakeResult(
            ("App.exe", "AID.dll", @"C:\test"),
            ("App.exe", "other.dll", @"C:\test"));

        var pr = EtwResultConverter.ToProcmonResult(result);

        Assert.Equal(2, pr.FilteredRows);
        Assert.Equal(2, pr.Events.Count);
        Assert.All(pr.Events, e => Assert.Equal("NAME NOT FOUND", e.Result));
        Assert.Equal(2, pr.ByDll.Count);
    }

    [Fact]
    public void Scorer_RuntimeTrace_DirMatch_HigherConfidenceThanProcmon()
    {
        var procmonEvidence = new DynamicEvidence
        {
            DllName = "test.dll", EventCount = 1,
            MatchedByName = true, MatchedByDirectory = true,
            Source = EvidenceSource.ProcmonCsv,
        };
        var runtimeEvidence = new DynamicEvidence
        {
            DllName = "test.dll", EventCount = 1,
            MatchedByName = true, MatchedByDirectory = true,
            MissInWritableDir = true,
            Source = EvidenceSource.RuntimeTrace,
        };

        var s1 = new ScoreBreakdown();
        ExploitabilityScorer.ApplyDynamicEvidence(s1, null, procmonEvidence);

        var s2 = new ScoreBreakdown();
        ExploitabilityScorer.ApplyDynamicEvidence(s2, null, runtimeEvidence);

        Assert.True(s2.Confidence >= s1.Confidence,
            $"RuntimeTrace confidence ({s2.Confidence}) should be >= ProcMon ({s1.Confidence})");
    }

    [Fact]
    public void Scorer_RuntimeTrace_NameOnly_HigherThanProcmon()
    {
        var procmonEvidence = new DynamicEvidence
        {
            DllName = "test.dll", EventCount = 1,
            MatchedByName = true, MatchedByDirectory = false,
            Source = EvidenceSource.ProcmonCsv,
        };
        var runtimeEvidence = new DynamicEvidence
        {
            DllName = "test.dll", EventCount = 1,
            MatchedByName = true, MatchedByDirectory = false,
            Source = EvidenceSource.RuntimeTrace,
        };

        var s1 = new ScoreBreakdown();
        ExploitabilityScorer.ApplyDynamicEvidence(s1, null, procmonEvidence);

        var s2 = new ScoreBreakdown();
        ExploitabilityScorer.ApplyDynamicEvidence(s2, null, runtimeEvidence);

        Assert.True(s2.Confidence > s1.Confidence,
            $"RuntimeTrace name-only confidence ({s2.Confidence}) should be > ProcMon ({s1.Confidence})");
    }

    [Fact]
    public void EtwTraceFilter_Defaults()
    {
        var filter = new EtwTraceFilter();

        Assert.True(filter.IncludeChildren);
        Assert.True(filter.NameNotFoundOnly);
        Assert.True(filter.DllOnly);
        Assert.Equal("", filter.ProcessFilter);
    }

    [Fact]
    public void Preflight_ReturnsResult()
    {
        var result = EtwDllTracer.Preflight();
        Assert.NotNull(result);
        Assert.NotEmpty(result.Message);
    }
}
