using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Models;

/// <summary>How the candidate was surfaced.</summary>
public enum DiscoveryOrigin
{
    DirectEnumeration,
    PrivescResolvedTarget,
    DynamicRuntime,
}

public class ImporterRef
{
    public required string ExePath { get; set; }
    public required string ExeFilename { get; set; }
    public SigningInfo Signing { get; set; } = new();
    public ushort Subsystem { get; set; }         // 2=GUI, 3=Console, etc
    public bool IsService { get; set; }           // heuristic: in \Services\ or .sys-adjacent — we don't detect this statically yet
    public bool ForcesSystem32Only { get; set; } // DependentLoadFlags & 0x800
    public bool IsDelayLoad { get; set; }
}

public class SideloadCandidate
{
    public required PeAnalysis Dll { get; set; }
    public SigningInfo DllSigning { get; set; } = new();
    public DirectoryPermissions Dir { get; set; } = new() { Path = "" };
    public List<ImporterRef> Importers { get; set; } = [];
    public ScoreBreakdown Score { get; set; } = new();
    public DynamicEvidence? Evidence { get; set; }   // set by ProcmonCorrelator
    public PrivescContext? Privesc { get; set; }     // set by PrivescAnalyzer
    public Cve.CveQueryResult? Cve { get; set; }     // set by background CVE query from ScanPage

    /// <summary>SandboxClassifier verdict for the primary importer; gates the SandboxEscape payload.</summary>
    public SandboxKind SandboxKind { get; set; } = SandboxKind.None;

    /// <summary>How this candidate was surfaced.</summary>
    public DiscoveryOrigin Discovery { get; set; } = DiscoveryOrigin.DirectEnumeration;

    /// <summary>Short label describing which privesc finding led to a PrivescResolvedTarget candidate.</summary>
    public string? DiscoveredViaLabel { get; set; }

    public bool HasImporters => Importers.Count > 0;
    public bool AnyImporterSigned => Importers.Any(i => i.Signing.IsTrusted);
    /// <summary>True iff at least one real loader open backs this candidate (probe-only does not count).</summary>
    public bool IsDynamicallyVerified => Evidence != null && !Evidence.IsProbeOnly;
    /// <summary>True iff runtime evidence exists but every event was a metadata probe.</summary>
    public bool IsRuntimeProbeOnly => Evidence?.IsProbeOnly == true;
    public bool HasPrivescPath => Privesc != null && Privesc.Findings.Count > 0;
}
