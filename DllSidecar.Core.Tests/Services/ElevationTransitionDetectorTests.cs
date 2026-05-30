using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.Core.Tests.Services;

public class ElevationTransitionDetectorTests
{
    private static ProcmonEvent MakeEvent(string proc, int pid, string dll, DateTime ts) => new()
    {
        ProcessName = proc,
        Operation = "CreateFile",
        Result = "NAME NOT FOUND",
        Path = $"C:\\app\\{dll}",
        Pid = pid,
        Timestamp = ts,
    };

    [Fact]
    public void Detect_MultiPid_StrictTemporalOrder_ReturnsTransition()
    {
        var t0 = new DateTime(2026, 5, 28, 11, 30, 0);
        var events = new List<ProcmonEvent>
        {
            MakeEvent("WinDirStat.exe", 100, "user.dll",   t0),
            MakeEvent("WinDirStat.exe", 100, "policy.dll", t0.AddMilliseconds(50)),
            MakeEvent("WinDirStat.exe", 200, "bcrypt.dll", t0.AddSeconds(2)),
            MakeEvent("WinDirStat.exe", 200, "msimg32.dll",t0.AddSeconds(2).AddMilliseconds(20)),
        };

        var transitions = ElevationTransitionDetector.Detect(events);

        Assert.Single(transitions);
        Assert.Equal("WinDirStat.exe", transitions[0].ProcessName);
        Assert.Equal(100, transitions[0].ParentPid);
        Assert.Equal(200, transitions[0].ChildPid);
        Assert.NotNull(transitions[0].Gap);
        Assert.True(transitions[0].Gap!.Value.TotalSeconds is > 1 and < 3);
    }

    [Fact]
    public void Detect_SinglePid_ReturnsNoTransition()
    {
        var t0 = new DateTime(2026, 5, 28, 11, 30, 0);
        var events = new List<ProcmonEvent>
        {
            MakeEvent("WinDirStat.exe", 100, "user.dll",   t0),
            MakeEvent("WinDirStat.exe", 100, "policy.dll", t0.AddMilliseconds(50)),
        };

        Assert.Empty(ElevationTransitionDetector.Detect(events));
    }

    [Fact]
    public void Detect_OverlappingWindows_RejectsAmbiguousOrdering()
    {
        // PID 100 last event > PID 200 first event => not strict parent->child.
        var t0 = new DateTime(2026, 5, 28, 11, 30, 0);
        var events = new List<ProcmonEvent>
        {
            MakeEvent("foo.exe", 100, "a.dll", t0),
            MakeEvent("foo.exe", 200, "b.dll", t0.AddMilliseconds(10)),
            MakeEvent("foo.exe", 100, "c.dll", t0.AddSeconds(1)),
        };

        Assert.Empty(ElevationTransitionDetector.Detect(events));
    }

    [Fact]
    public void TagEvents_AssignsPhaseToBothSides()
    {
        var t0 = new DateTime(2026, 5, 28, 11, 30, 0);
        var events = new List<ProcmonEvent>
        {
            MakeEvent("WinDirStat.exe", 100, "user.dll",   t0),
            MakeEvent("WinDirStat.exe", 200, "bcrypt.dll", t0.AddSeconds(2)),
            MakeEvent("OtherProc.exe",  300, "thing.dll",  t0.AddSeconds(3)),
        };

        ElevationTransitionDetector.DetectAndTag(events);

        Assert.Equal(IlPhase.MediumIl, events[0].Phase);
        Assert.Equal(IlPhase.HighIl,   events[1].Phase);
        Assert.Equal(IlPhase.Unknown,  events[2].Phase);
    }

    [Fact]
    public void PopulateAggregationFlags_SetsHighIlSearch_OnElevatedDll()
    {
        var t0 = new DateTime(2026, 5, 28, 11, 30, 0);
        var events = new List<ProcmonEvent>
        {
            MakeEvent("WinDirStat.exe", 100, "user.dll",   t0),
            MakeEvent("WinDirStat.exe", 200, "bcrypt.dll", t0.AddSeconds(2)),
        };
        var aggregations = new List<ProcmonAggregation>
        {
            new() { DllName = "user.dll",   AnyDirUserSpace = true },
            new() { DllName = "bcrypt.dll", AnyDirUserSpace = true },
        };

        ElevationTransitionDetector.DetectAndTag(events);
        ElevationTransitionDetector.PopulateAggregationFlags(aggregations, events);

        Assert.False(aggregations.Single(a => a.DllName == "user.dll").HighIlSearch);
        Assert.True (aggregations.Single(a => a.DllName == "bcrypt.dll").HighIlSearch);
        Assert.True (aggregations.Single(a => a.DllName == "bcrypt.dll").PrivescCandidate);
    }

    [Fact]
    public void PrivescCandidate_RequiresBothHighIlAndUserWritableDir()
    {
        var t0 = new DateTime(2026, 5, 28, 11, 30, 0);
        var events = new List<ProcmonEvent>
        {
            MakeEvent("WinDirStat.exe", 100, "user.dll",   t0),
            MakeEvent("WinDirStat.exe", 200, "bcrypt.dll", t0.AddSeconds(2)),
        };
        // bcrypt.dll search dirs are NOT user-writable in this scenario.
        var aggregations = new List<ProcmonAggregation>
        {
            new() { DllName = "bcrypt.dll", AnyDirUserSpace = false },
        };

        ElevationTransitionDetector.DetectAndTag(events);
        ElevationTransitionDetector.PopulateAggregationFlags(aggregations, events);

        Assert.True (aggregations[0].HighIlSearch);
        Assert.False(aggregations[0].PrivescCandidate); // gated by AnyDirUserSpace
    }

    /// <summary>Regression guard: only user-writable non-KnownDLL loader-touched phantom survives.</summary>
    [Fact]
    public void IdentifyCarriers_OnlyUserWritableNonKnownDllSurvives()
    {
        const string writableDir = @"X:\writable-install";
        const string lockedDir   = @"X:\locked-system";
        var t0 = new DateTime(2026, 5, 28, 11, 30, 0);

        var events = new List<ProcmonEvent>
        {
            // Medium-IL parent (not a carrier even with writable search dir).
            new() { ProcessName = "host.exe", Operation = "CreateFile", Result = "NAME NOT FOUND",
                    Path = $@"{writableDir}\parent-only.dll", Pid = 100, Timestamp = t0,
                    Access = AccessClass.LoaderLike },
            // Elevated child — phantom in writable dir (the surviving carrier).
            new() { ProcessName = "host.exe", Operation = "CreateFile", Result = "NAME NOT FOUND",
                    Path = $@"{writableDir}\phantom.dll", Pid = 200, Timestamp = t0.AddSeconds(2),
                    Access = AccessClass.LoaderLike },
            // Elevated child in locked dir (filtered by writability gate).
            new() { ProcessName = "host.exe", Operation = "CreateFile", Result = "NAME NOT FOUND",
                    Path = $@"{lockedDir}\noise.dll", Pid = 200, Timestamp = t0.AddSeconds(2).AddMilliseconds(10),
                    Access = AccessClass.LoaderLike },
            // KnownDLL in writable dir (filtered by KnownDLL gate).
            new() { ProcessName = "host.exe", Operation = "CreateFile", Result = "NAME NOT FOUND",
                    Path = $@"{writableDir}\kernel32.dll", Pid = 200, Timestamp = t0.AddSeconds(2).AddMilliseconds(20),
                    Access = AccessClass.LoaderLike },
        };

        var byDll = events
            .GroupBy(e => e.DllName, StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var agg = new ProcmonAggregation { DllName = g.Key };
                foreach (var e in g)
                {
                    agg.EventCount++;
                    agg.SearchedDirs.Add(e.SearchDir);
                    agg.Processes.Add(e.ProcessName);
                    if (e.Access == AccessClass.LoaderLike) agg.LoaderLikeCount++;
                    else if (e.Access == AccessClass.MetadataProbe) agg.MetadataProbeCount++;
                }
                return agg;
            })
            .ToList();

        ElevationTransitionDetector.RunFullPipeline(events, byDll);

        // Pre-seed the ACL cache so the test doesn't depend on disk state.
        var acl = new DirAclCache();
        acl.Seed(writableDir, new Models.DirectoryPermissions { Path = writableDir, CurrentUserWrite = true });
        acl.Seed(lockedDir,   new Models.DirectoryPermissions { Path = lockedDir });

        var carriers = PrivescCarrierIdentifier.FromAggregations(byDll, acl);

        Assert.Single(carriers);
        Assert.Equal("phantom.dll", carriers[0].DllName, ignoreCase: true);
        Assert.Equal(writableDir,   carriers[0].PlantSlot, ignoreCase: true);
    }
}
