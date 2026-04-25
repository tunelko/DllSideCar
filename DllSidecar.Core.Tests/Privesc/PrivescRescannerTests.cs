using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;
using DllSidecar.Core.Services;
using DllSidecar.Core.Services.Privesc;

namespace DllSidecar.Core.Tests.Privesc;

public class PrivescRescannerTests
{
    private static PrivescFinding MakeTaskFinding(string resolvedTarget, string status = "Resolved", string taskName = "Vendor\\T")
    {
        return new PrivescFinding
        {
            Vector = PrivescVector.ScheduledTask,
            Severity = PrivescSeverity.High,
            DetectorName = "ScheduledTaskDetector",
            Title = "test finding",
            Evidence = "",
            PrivilegedProcessPath = resolvedTarget,
            Extras =
            {
                ["TaskName"]         = taskName,
                ["ResolvedTarget"]   = resolvedTarget,
                ["ResolutionStatus"] = status,
                ["ResolvedViaWrapper"] = "true",
                ["WrapperKind"]      = "Cmd",
            },
        };
    }

    private static PrivescFinding MakeServiceFinding(string resolvedTarget, string svcName = "VendorSvc")
    {
        return new PrivescFinding
        {
            Vector = PrivescVector.ServiceSystem,
            Severity = PrivescSeverity.High,
            DetectorName = "ServicesDetector",
            Title = "test svc",
            Evidence = "",
            PrivilegedProcessPath = resolvedTarget,
            Extras =
            {
                ["ServiceName"]      = svcName,
                ["ResolvedTarget"]   = resolvedTarget,
                ["ResolutionStatus"] = "Resolved",
            },
        };
    }

    private static ScanResults WrapFindingOnExisting(PrivescFinding f)
    {
        // Attach the finding to a synthetic Existing candidate so the collector can find
        // it via the scan graph walk. The candidate itself is irrelevant for collection.
        var c = new SideloadCandidate
        {
            Dll = new PeAnalysis { Path = "X:\\fake\\host.exe", Filename = "host.exe", Arch = "x64", IsDll = false },
            Privesc = new PrivescContext { Findings = { f } },
        };
        return new ScanResults { Existing = { c } };
    }

    [Fact]
    public void Collect_Empty_ReturnsEmpty()
    {
        var results = new ScanResults();
        var got = PrivescRescanner.CollectResolvedTargets(results, new HashSet<string>());
        Assert.Empty(got);
    }

    [Fact]
    public void Collect_PartialStatus_IsSkipped()
    {
        var coreDll = typeof(ScoreBreakdown).Assembly.Location;
        var results = WrapFindingOnExisting(MakeTaskFinding(coreDll, status: "Partial"));
        Assert.Empty(PrivescRescanner.CollectResolvedTargets(results, new HashSet<string>()));
    }

    [Fact]
    public void Collect_NonExistentFile_IsSkipped()
    {
        var results = WrapFindingOnExisting(MakeTaskFinding(@"X:\does\not\exist.exe"));
        Assert.Empty(PrivescRescanner.CollectResolvedTargets(results, new HashSet<string>()));
    }

    [Fact]
    public void Collect_NonPeExtension_IsSkipped()
    {
        // Create a real temp file with a non-PE extension
        var tmp = Path.Combine(Path.GetTempPath(), $"rescan-{Guid.NewGuid():N}.bat");
        File.WriteAllText(tmp, "echo hi");
        try
        {
            var results = WrapFindingOnExisting(MakeTaskFinding(tmp));
            Assert.Empty(PrivescRescanner.CollectResolvedTargets(results, new HashSet<string>()));
        }
        finally { try { File.Delete(tmp); } catch { } }
    }

    [Fact]
    public void Collect_AlreadyKnownPath_IsSkipped()
    {
        var coreDll = typeof(ScoreBreakdown).Assembly.Location;
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { coreDll.ToLowerInvariant() };
        var results = WrapFindingOnExisting(MakeTaskFinding(coreDll));
        Assert.Empty(PrivescRescanner.CollectResolvedTargets(results, known));
    }

    [Fact]
    public void Collect_DuplicateTarget_IsDeduped()
    {
        var coreDll = typeof(ScoreBreakdown).Assembly.Location;
        var f1 = MakeTaskFinding(coreDll, taskName: "A");
        var f2 = MakeTaskFinding(coreDll, taskName: "B");
        var c = new SideloadCandidate
        {
            Dll = new PeAnalysis { Path = "X:\\host.exe", Filename = "host.exe", Arch = "x64", IsDll = false },
            Privesc = new PrivescContext { Findings = { f1, f2 } },
        };
        var scan = new ScanResults { Existing = { c } };
        var got = PrivescRescanner.CollectResolvedTargets(scan, new HashSet<string>());
        Assert.Single(got);
    }

    [Fact]
    public void Collect_HappyPath_ReturnsTargetWithViaLabel()
    {
        var coreDll = typeof(ScoreBreakdown).Assembly.Location;
        var results = WrapFindingOnExisting(MakeTaskFinding(coreDll, taskName: "Adobe\\Updater"));
        var got = PrivescRescanner.CollectResolvedTargets(results, new HashSet<string>());
        var t = Assert.Single(got);
        Assert.Equal(coreDll.ToLowerInvariant(), t.NormalizedPath);
        Assert.Equal("Task 'Adobe\\Updater'", t.ViaLabel);
    }

    [Fact]
    public void Collect_ServiceFinding_ProducesServiceViaLabel()
    {
        var coreDll = typeof(ScoreBreakdown).Assembly.Location;
        var results = WrapFindingOnExisting(MakeServiceFinding(coreDll, svcName: "VendorSvc"));
        var got = PrivescRescanner.CollectResolvedTargets(results, new HashSet<string>());
        var t = Assert.Single(got);
        Assert.Equal("Service 'VendorSvc'", t.ViaLabel);
    }

    [Fact]
    public void Expand_RealPe_ProducesDiscoveredCandidate()
    {
        var coreDll = typeof(ScoreBreakdown).Assembly.Location;
        var target = new PrivescRescanner.DiscoveredTarget
        {
            NormalizedPath = coreDll.ToLowerInvariant(),
            SourceFinding = MakeTaskFinding(coreDll),
            ViaLabel = "Task 'Adobe\\Updater'",
        };

        var produced = PrivescRescanner.Expand(new[] { target });

        var c = Assert.Single(produced);
        Assert.Equal(DiscoveryOrigin.PrivescResolvedTarget, c.Discovery);
        Assert.Equal("Task 'Adobe\\Updater'", c.DiscoveredViaLabel);
        Assert.NotNull(c.Privesc);
        Assert.Single(c.Privesc!.Findings);
        // Impact axis must be lifted by the inherited SYSTEM-severity finding
        Assert.True(c.Score.Impact >= 5,
            $"Impact should reflect inherited High-severity task finding, got {c.Score.Impact}");
        // And Exploitability must NOT be artificially inflated — no importer graph here
        Assert.True(c.Score.Exploitability <= 3,
            $"Exploitability should be honest (no importers), got {c.Score.Exploitability}");
    }

    [Fact]
    public void Expand_DoesNotCascade_DiscoveredCandidateDoesNotProduceNewTargets()
    {
        // Invariant: the scanner calls Expand once. A second pass over its output must
        // find nothing new because the discovered candidate already lives in the known set.
        var coreDll = typeof(ScoreBreakdown).Assembly.Location;
        var target = new PrivescRescanner.DiscoveredTarget
        {
            NormalizedPath = coreDll.ToLowerInvariant(),
            SourceFinding = MakeTaskFinding(coreDll),
            ViaLabel = "Task 'X'",
        };

        var firstPass = PrivescRescanner.Expand(new[] { target });
        var c = Assert.Single(firstPass);

        // Simulate what the scanner does: put the discovered candidate into the
        // known-set and ask for targets again. Nothing new should come out.
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { coreDll.ToLowerInvariant() };
        var secondPass = PrivescRescanner.CollectResolvedTargets(
            new ScanResults { Existing = { c } }, known);
        Assert.Empty(secondPass);
    }
}
