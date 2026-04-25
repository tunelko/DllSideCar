using DllSidecar.Core.Models.Advisory;

namespace DllSidecar.Core.Services.Advisory.Rendering;

/// <summary>Thin adapter around the existing AdvisoryTemplate so it fits the IAdvisoryRenderer plug-in.</summary>
public sealed class MarkdownRenderer : IAdvisoryRenderer
{
    public string Id => "markdown";
    public string DisplayName => "Markdown";
    public string FileExtension => ".md";
    public string DefaultFilename => "advisory.md";
    public string Render(AdvisoryContext ctx) => AdvisoryTemplate.Render(ctx);

    public IReadOnlyCollection<AdvisoryField> FieldHints { get; } = new[]
    {
        AdvisoryField.Title, AdvisoryField.Vendor, AdvisoryField.Product, AdvisoryField.ProductVersion,
        AdvisoryField.Architecture, AdvisoryField.PePath, AdvisoryField.PeFilename,
        AdvisoryField.Cwe, AdvisoryField.CweName, AdvisoryField.AttackScenario, AdvisoryField.Impact,
        AdvisoryField.CvssV3, AdvisoryField.DiscoveredOn, AdvisoryField.ReportedOn, AdvisoryField.DisclosedOn,
        AdvisoryField.DisclosurePolicy, AdvisoryField.References, AdvisoryField.CveDedup, AdvisoryField.Privesc,
        AdvisoryField.GeneratedDllPath, AdvisoryField.ImporterExe, AdvisoryField.PayloadDescription,
        AdvisoryField.InstallDirectory, AdvisoryField.WritableByPrincipals, AdvisoryField.DirectoryLowPrivWritable,
    };
}
