using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Models;

/// <summary>A phantom drop-point: a DLL name imported but not present in any standard search path.</summary>
public class PhantomCandidate
{
    public required string DllName { get; set; }
    public required string DirectoryPath { get; set; }
    public SigningInfo DllSigning { get; set; } = new() { Status = SigningStatus.NotSigned };
    public DirectoryPermissions Dir { get; set; } = new() { Path = "" };
    public List<ImporterRef> Importers { get; set; } = [];
    public List<string> SearchedLocations { get; set; } = [];
    public ScoreBreakdown Score { get; set; } = new();
    public DynamicEvidence? Evidence { get; set; }   // set by ProcmonCorrelator
    public PrivescContext? Privesc { get; set; }     // set by PrivescAnalyzer (via any importer)
    public Cve.CveQueryResult? Cve { get; set; }     // set by background CVE query from ScanPage

    /// <summary>SandboxClassifier verdict for the primary importer; gates the SandboxEscape payload.</summary>
    public SandboxKind SandboxKind { get; set; } = SandboxKind.None;

    public bool AnyDelayLoad => Importers.Any(i => i.IsDelayLoad);
    public bool AllDelayLoad => Importers.Count > 0 && Importers.All(i => i.IsDelayLoad);
    public bool AnyImporterSigned => Importers.Any(i => i.Signing.IsTrusted);
    /// <summary>True iff at least one real loader open backs this candidate (probe-only does not count).</summary>
    public bool IsDynamicallyVerified => Evidence != null && !Evidence.IsProbeOnly;
    /// <summary>True iff runtime evidence exists but every event was a metadata probe.</summary>
    public bool IsRuntimeProbeOnly => Evidence?.IsProbeOnly == true;
    public bool HasPrivescPath => Privesc != null && Privesc.Findings.Count > 0;
}
