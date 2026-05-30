namespace DllSidecar.Core.Models;

public enum EvidenceSource
{
    ProcmonCsv,
    RuntimeTrace,
}

/// <summary>Runtime evidence that the loader attempted to resolve this DLL; raises the Confidence axis only.</summary>
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

    /// <summary>All evidence is metadata probes; no real loader open occurred.</summary>
    public bool IsProbeOnly => LoaderLikeEventCount == 0 && MetadataProbeEventCount > 0;

    /// <summary>User-facing access label mirroring ProcMon's <c>Options:</c> field.</summary>
    public string AccessLabel => AccessClassLabels.FromCounts(LoaderLikeEventCount, MetadataProbeEventCount);

    /// <summary>Match quality heuristic — 1.0 means DLL+dir matched, 0.6 means only name.</summary>
    public double Confidence => MatchedByDirectory ? 1.0 : 0.6;
}
