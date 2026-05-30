namespace DllSidecar.Core.Models.Cve;

/// <summary>A single NVD CVE entry, enriched with match-confidence against the target PE.</summary>
public class CveMatch
{
    public required string CveId { get; set; }                  // "CVE-2024-30283"
    public required string Description { get; set; }
    public string? Vendor { get; set; }                          // from CPE match when available
    public string? Product { get; set; }
    public DateTime? PublishedDate { get; set; }
    public DateTime? LastModifiedDate { get; set; }
    public double? CvssScore { get; set; }                       // CVSS 3.1 base score if available
    public string? CvssSeverity { get; set; }                    // LOW / MEDIUM / HIGH / CRITICAL
    public string? CvssVector { get; set; }
    public List<string> Cwes { get; set; } = [];                 // e.g. ["CWE-427"]
    public List<string> References { get; set; } = [];           // URLs
    public MatchConfidence Confidence { get; set; } = MatchConfidence.Unrelated;
    public List<string> MatchReasons { get; set; } = [];         // why we scored it as we did

    public string NvdUrl => $"https://nvd.nist.gov/vuln/detail/{CveId}";
}
