namespace DllSidecar.Core.Models.Cve;

public class CveQueryResult
{
    public List<CveMatch> Matches { get; set; } = [];
    public int TotalFromApi { get; set; }       // NVD reported count (may exceed Matches.Count if we paginated)
    public string? Error { get; set; }
    public bool FromCache { get; set; }
    public DateTime QueryTime { get; set; } = DateTime.UtcNow;
    public string? Query { get; set; }           // keywordSearch used

    public bool HasExactMatch => Matches.Any(m => m.Confidence == MatchConfidence.Exact);
    public bool HasLikelyMatch => Matches.Any(m => m.Confidence >= MatchConfidence.Likely);
    public int ExactCount => Matches.Count(m => m.Confidence == MatchConfidence.Exact);
    public int LikelyCount => Matches.Count(m => m.Confidence == MatchConfidence.Likely);
}
