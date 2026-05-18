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
    /// <summary>How many events were classified as real loader image opens.</summary>
    public int LoaderLikeEventCount { get; set; }
    /// <summary>How many events were metadata-only probes (GetFileAttributes-class).</summary>
    public int MetadataProbeEventCount { get; set; }

    public bool IsRuntimeObserved => Source == EvidenceSource.RuntimeTrace;

    /// <summary>
    /// All evidence is metadata probes — the loader never attempted a real open on
    /// this DLL. Indicates app-internal PATH enumeration, not a sideload primitive.
    /// </summary>
    public bool IsProbeOnly => LoaderLikeEventCount == 0 && MetadataProbeEventCount > 0;

    /// <summary>
    /// User-facing access label mirroring ProcMon's <c>Options:</c> field. One of
    /// <see cref="AccessClassLabels.Load"/>, <see cref="AccessClassLabels.Probe"/>,
    /// <see cref="AccessClassLabels.Mixed"/>, or empty when the events were Unknown.
    /// </summary>
    public string AccessLabel => AccessClassLabels.FromCounts(LoaderLikeEventCount, MetadataProbeEventCount);

    /// <summary>Match quality heuristic — 1.0 means DLL+dir matched, 0.6 means only name.</summary>
    public double Confidence => MatchedByDirectory ? 1.0 : 0.6;
}
