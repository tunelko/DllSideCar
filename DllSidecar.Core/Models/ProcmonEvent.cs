namespace DllSidecar.Core.Models;

/// <summary>Inferred IL phase relative to a detected UAC elevation transition.</summary>
public enum IlPhase { Unknown, MediumIl, HighIl }

/// <summary>Single CreateFile / NAME NOT FOUND row from a ProcMon CSV export on *.dll paths.</summary>
public class ProcmonEvent
{
    public required string ProcessName { get; set; }
    public required string Operation { get; set; }
    public required string Result { get; set; }
    public required string Path { get; set; }       // full path searched
    public string DllName => System.IO.Path.GetFileName(Path);
    public string SearchDir => System.IO.Path.GetDirectoryName(Path) ?? "";
    public DateTime? Timestamp { get; set; }
    public int? Pid { get; set; }
    /// <summary>Raw ProcMon Detail string (Desired Access / Options / ...).</summary>
    public string? Detail { get; set; }
    /// <summary>Loader-vs-probe classification derived from <see cref="Detail"/>.</summary>
    public AccessClass Access { get; set; } = AccessClass.Unknown;
    /// <summary>Inferred IL phase; HighIl events are the privesc-relevant ones. Set retroactively by the detector.</summary>
    public IlPhase Phase { get; set; } = IlPhase.Unknown;
}

/// <summary>One detected UAC elevation handoff: same process name under two PIDs with strict temporal ordering.</summary>
public sealed record ElevationTransition(
    string ProcessName,
    int ParentPid,
    int ChildPid,
    DateTime? ParentLastSeen,
    DateTime? ChildFirstSeen)
{
    /// <summary>Gap between parent's last event and child's first event; diagnostic only.</summary>
    public TimeSpan? Gap =>
        (ParentLastSeen.HasValue && ChildFirstSeen.HasValue)
            ? ChildFirstSeen.Value - ParentLastSeen.Value
            : null;
}

/// <summary>DLL name → all events that searched for it. Aggregation view.</summary>
public class ProcmonAggregation
{
    public required string DllName { get; set; }
    public HashSet<string> Processes { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> SearchedDirs { get; } = new(StringComparer.OrdinalIgnoreCase);
    public int EventCount { get; set; }
    public bool AnyDirUserSpace { get; set; }   // heuristic: any dir outside Windows/Program Files
    /// <summary>How many of the events were classified as loader-style image opens.</summary>
    public int LoaderLikeCount { get; set; }
    /// <summary>How many of the events were metadata-only probes (GetFileAttributes-class).</summary>
    public int MetadataProbeCount { get; set; }
    /// <summary>True when at least one event was performed by the post-UAC elevated child.</summary>
    public bool HighIlSearch { get; set; }
    /// <summary>True when HighIlSearch and at least one searched dir is user-writable.</summary>
    public bool PrivescCandidate => HighIlSearch && AnyDirUserSpace;

    public string RiskHeuristic => AnyDirUserSpace ? "HIGH" : "LOW";

    /// <summary>Every event was a metadata probe; loader never opened the DLL.</summary>
    public bool IsProbeOnly => LoaderLikeCount == 0 && MetadataProbeCount > 0;
}
