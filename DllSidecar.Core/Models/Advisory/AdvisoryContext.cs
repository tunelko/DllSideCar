using DllSidecar.Core.Configuration;
using DllSidecar.Core.Models.Cve;
using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Models.Advisory;

/// <summary>Inputs for the advisory markdown template.</summary>
public class AdvisoryContext
{
    // Researcher identity; AdvisoryPage hydrates from AppConfig.Researcher before rendering.
    public string ResearcherName { get; set; } = "";
    public string ResearcherHandle { get; set; } = "";
    public string ResearcherBlog { get; set; } = "";
    public string ResearcherEmail { get; set; } = "";
    public string ResearcherPgpFingerprint { get; set; } = "";
    public string ResearcherPgpKeyId { get; set; } = "";

    // Target
    public string? Vendor { get; set; }
    public string? VendorUrl { get; set; }
    public string? VendorPocName { get; set; }
    public string? VendorPocEmail { get; set; }
    public string? Product { get; set; }
    public string? Version { get; set; }
    public string? Architecture { get; set; }
    public string? DeviceUrlReference { get; set; }
    public string? DeviceBriefSummary { get; set; }
    public string? PePath { get; set; }
    public string? PeFilename { get; set; }

    // Vulnerability
    public string Title { get; set; } = "DLL Sideloading in {Product} via {Filename}";
    public string Cwe { get; set; } = "CWE-427";
    public string CweName { get; set; } = "Uncontrolled Search Path Element";
    public string VulnType { get; set; } = "DLL Sideloading";
    public string VulnerabilityTypeText { get; set; } = "DLL Sideloading / Uncontrolled Search Path Element (CWE-427)";
    public string AttackScenario { get; set; } = "";
    public string Impact { get; set; } = "";
    public string ProposedSolution { get; set; } = "";
    public string AffectedComponents { get; set; } = "";        // free-text, one entry per line
    public string PreviousRequirements { get; set; } = "";       // free-text, one entry per line
    public string HasContactedVendorNote { get; set; } = "";     // free-text status of vendor contact

    // Directory context
    public string? InstallDirectory { get; set; }
    public string? WritableByPrincipals { get; set; }
    public bool DirectoryLowPrivWritable { get; set; }

    // PoC
    public string? GeneratedDllPath { get; set; }
    public string? ImporterExe { get; set; }
    public string PayloadDescription { get; set; } = "calc.exe spawn";

    // Privesc vectors if any
    public PrivescContext? Privesc { get; set; }
    public List<PrivescFinding> RelevantPrivescFindings { get; set; } = [];

    // CVSS v3.1 (kept — used by Markdown renderer and most general audiences)
    public CvssVector Cvss { get; set; } = new();
    public double CvssScore { get; set; }
    public string CvssSeverity { get; set; } = "HIGH";

    // CVSS v4.0 (optional — surfaced in Template Fields for renderers that consume it).
    public CvssV4Vector CvssV4 { get; set; } = new();
    public double CvssV4Score { get; set; }
    public string CvssV4Severity { get; set; } = "HIGH";

    // CVE dedup
    public CveQueryResult? CveDedup { get; set; }

    // Timeline
    public DateTime DiscoveredOn { get; set; } = DateTime.Today;
    public DateTime? ReportedOn { get; set; }
    public DateTime? DisclosedOn { get; set; }
    public string DisclosurePolicy { get; set; } = "Coordinated with vendor / MITRE";

    // References
    public List<string> References { get; set; } = [];

    /// <summary>Substitute `{Product}`, `{Filename}`, `{Vendor}` placeholders in the Title.</summary>
    public string ResolveTitle() => ResolvePlaceholders(Title);

    public string ResolvePlaceholders(string? input) => string.IsNullOrEmpty(input) ? "" :
        input.Replace("{Product}",  Product   ?? "")
             .Replace("{Filename}", PeFilename ?? "")
             .Replace("{Vendor}",   Vendor    ?? "")
             .Replace("  ", " ")
             .Trim();

    /// <summary>Fill blank researcher identity fields from <see cref="ConfigManager.Current"/>; already-populated values are preserved.</summary>
    public void ApplyResearcherFromConfig()
    {
        var r = ConfigManager.Current.Researcher;
        if (string.IsNullOrWhiteSpace(ResearcherName)) ResearcherName = r.Name ?? "";
        if (string.IsNullOrWhiteSpace(ResearcherHandle)) ResearcherHandle = r.Handle ?? "";
        if (string.IsNullOrWhiteSpace(ResearcherBlog)) ResearcherBlog = r.Blog ?? "";
        if (string.IsNullOrWhiteSpace(ResearcherEmail)) ResearcherEmail = r.Email ?? "";
        if (string.IsNullOrWhiteSpace(ResearcherPgpFingerprint)) ResearcherPgpFingerprint = r.PgpFingerprint ?? "";
        if (string.IsNullOrWhiteSpace(ResearcherPgpKeyId)) ResearcherPgpKeyId = r.PgpKeyId ?? "";
    }
}
