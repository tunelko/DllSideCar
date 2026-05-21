using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Models;

/// <summary>
/// A "phantom" drop-point: a DLL name that at least one PE in the scanned directory
/// imports (IAT or delay-load) but that does NOT exist in the importer's directory,
/// System32/SysWOW64, is not a KnownDLL, and is not an API set. Dropping a crafted
/// DLL with this name into the importer's directory gives code execution.
/// </summary>
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

    /// <summary>Verdict from SandboxClassifier for the primary importer (Importers[0]).
    /// Set by EtwResultConverter when promoting from a runtime trace. CraftStage
    /// uses it to gate whether SandboxEscape appears in the Payload picker.</summary>
    public SandboxKind SandboxKind { get; set; } = SandboxKind.None;

    public bool AnyDelayLoad => Importers.Any(i => i.IsDelayLoad);
    public bool AllDelayLoad => Importers.Count > 0 && Importers.All(i => i.IsDelayLoad);
    public bool AnyImporterSigned => Importers.Any(i => i.Signing.IsTrusted);
    /// <summary>
    /// True when at least one real loader open backs this candidate. Probe-only
    /// evidence does NOT count as verified — the loader never attempted to map the
    /// DLL, so a "verified" badge would be misleading.
    /// </summary>
    public bool IsDynamicallyVerified => Evidence != null && !Evidence.IsProbeOnly;
    /// <summary>True iff runtime evidence exists but every event was a metadata probe.</summary>
    public bool IsRuntimeProbeOnly => Evidence?.IsProbeOnly == true;
    public bool HasPrivescPath => Privesc != null && Privesc.Findings.Count > 0;
}
