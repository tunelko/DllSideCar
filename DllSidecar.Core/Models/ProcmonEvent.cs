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
}

/// <summary>DLL name → all events that searched for it. Aggregation view.</summary>
public class ProcmonAggregation
{
    public required string DllName { get; set; }
    public HashSet<string> Processes { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> SearchedDirs { get; } = new(StringComparer.OrdinalIgnoreCase);
    public int EventCount { get; set; }
    public bool AnyDirUserSpace { get; set; }   // heuristic: any dir outside Windows/Program Files

    public string RiskHeuristic => AnyDirUserSpace ? "HIGH" : "LOW";
}
