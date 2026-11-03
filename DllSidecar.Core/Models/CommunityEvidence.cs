namespace DllSidecar.Core.Models;

public enum CommunityMatch { DllName, ExeDllNames }

public sealed class CommunityEvidence
{
    public CommunityMatch Match { get; set; }
    public string DllName { get; set; } = "";
    public string? ImporterPath { get; set; }
    public string Vendor { get; set; } = "";
    public string Type { get; set; } = "";
    public string SourceUrl { get; set; } = "";
    public string DatasetSha256 { get; set; } = "";
    public DateTime RetrievedAtUtc { get; set; }
    public string Summary => $"{(Match == CommunityMatch.ExeDllNames ? "EXE + DLL names" : "DLL name only")}: " +
        $"{Vendor} {Type}\n{SourceUrl}\nDataset {RetrievedAtUtc:u} / SHA256 {DatasetSha256}\n" +
        "Community documentation; installed version and exploitability are not confirmed.";
}
