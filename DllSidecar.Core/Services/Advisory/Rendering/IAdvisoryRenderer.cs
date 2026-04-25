using DllSidecar.Core.Models.Advisory;

namespace DllSidecar.Core.Services.Advisory.Rendering;

/// <summary>
/// One implementation per destination (Markdown, INCIBE CNA, GHSA, future CSAF, ...).
/// Each renderer reads what it needs from the shared AdvisoryContext; the UI
/// dynamically shows the form fields each renderer declares as required via
/// <see cref="FieldHints"/>.
/// </summary>
public interface IAdvisoryRenderer
{
    /// <summary>Stable identifier used in file paths and artifact kind (e.g. "markdown", "incibe", "ghsa").</summary>
    string Id { get; }

    /// <summary>User-facing label in the template dropdown (e.g. "Markdown", "INCIBE CNA", "GHSA").</summary>
    string DisplayName { get; }

    /// <summary>Preferred file extension including dot (".md", ".txt", ".yaml").</summary>
    string FileExtension { get; }

    /// <summary>Default output filename inside the format folder (e.g. "advisory.md").</summary>
    string DefaultFilename { get; }

    /// <summary>Produce the rendered text of the advisory.</summary>
    string Render(AdvisoryContext ctx);

    /// <summary>
    /// Set of <see cref="AdvisoryField"/> values this renderer actively consumes.
    /// AdvisoryPage uses this to show/hide form inputs per active template so the
    /// researcher isn't drowned in fields that the current destination ignores.
    /// </summary>
    IReadOnlyCollection<AdvisoryField> FieldHints { get; }
}

/// <summary>
/// Typed declaration of the AdvisoryContext fields a renderer cares about.
/// Drives the UI accordion in AdvisoryPage (Paso 4).
/// </summary>
public enum AdvisoryField
{
    Title,
    Vendor,
    VendorUrl,
    VendorPocName,
    VendorPocEmail,
    Product,
    ProductVersion,
    Architecture,
    DeviceUrlReference,
    DeviceBriefSummary,
    PePath,
    PeFilename,
    Cwe,
    CweName,
    VulnerabilityTypeText,
    AttackType,
    ImpactCategory,
    AttackScenario,
    Impact,
    AffectedComponents,
    PreviousRequirements,
    ProposedSolution,
    HasContactedVendorNote,
    CvssV3,
    CvssV4,
    DiscoveredOn,
    ReportedOn,
    DisclosedOn,
    DisclosurePolicy,
    References,
    CveDedup,
    Privesc,
    GeneratedDllPath,
    ImporterExe,
    PayloadDescription,
    InstallDirectory,
    WritableByPrincipals,
    DirectoryLowPrivWritable,
    ResearcherPgp,
    IncibeRanking,
}
