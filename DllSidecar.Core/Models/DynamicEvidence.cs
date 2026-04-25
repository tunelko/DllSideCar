namespace DllSidecar.Core.Models;

public enum EvidenceSource
{
    ProcmonCsv,
    RuntimeTrace,
}

/// <summary>
/// Ground-truth evidence that the loader actually attempted to resolve this DLL at runtime.
/// Attached to a SideloadCandidate or PhantomCandidate after correlation (ProcMon CSV) or
/// live tracing (ETW). Presence of evidence raises the Confidence axis of ScoreBreakdown;
/// it never affects Exploitability or Impact.
/// </summary>
public class DynamicEvidence
{
    public required string DllName { get; set; }
    public int EventCount { get; set; }
    public List<string> Processes { get; set; } = [];
    public List<string> SearchedDirs { get; set; } = [];
    public bool MatchedByName { get; set; }
    public bool MatchedByDirectory { get; set; }
    public bool MissInWritableDir { get; set; }
    public EvidenceSource Source { get; set; } = EvidenceSource.ProcmonCsv;

    public bool IsRuntimeObserved => Source == EvidenceSource.RuntimeTrace;

    /// <summary>Match quality heuristic — 1.0 means DLL+dir matched, 0.6 means only name.</summary>
    public double Confidence => MatchedByDirectory ? 1.0 : 0.6;
}
