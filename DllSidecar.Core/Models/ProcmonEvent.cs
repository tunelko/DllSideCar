namespace DllSidecar.Core.Models;

/// <summary>
/// Single relevant row from a ProcMon CSV export. Filtered to CreateFile / NAME NOT FOUND
/// events on *.dll paths — the ground truth for DLL resolution failures at runtime.
/// </summary>
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
    /// <summary>
    /// Loader-vs-probe classification derived from <see cref="Detail"/>. Default Unknown
    /// when Detail is absent (older CSVs / synthetic events) — treated as LoaderLike by
    /// downstream so we never silently drop a real load.
    /// </summary>
    public AccessClass Access { get; set; } = AccessClass.Unknown;
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

    public string RiskHeuristic => AnyDirUserSpace ? "HIGH" : "LOW";

    /// <summary>
    /// True when every event for this DLL is a metadata probe — the loader never
    /// actually attempted to open it. Indicates the app is enumerating PATH on its
    /// own (which-style); a planted DLL here is inert.
    /// </summary>
    public bool IsProbeOnly => LoaderLikeCount == 0 && MetadataProbeCount > 0;
}
