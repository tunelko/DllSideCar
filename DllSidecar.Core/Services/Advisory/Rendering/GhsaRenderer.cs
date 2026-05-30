using System.Text;
using DllSidecar.Core.Models.Advisory;
using DllSidecar.Core.Services.Advisory;

namespace DllSidecar.Core.Services.Advisory.Rendering;

/// <summary>
/// Renders the GHSA Markdown body (Impact / Technical details / Patches / Workarounds / References / CVE / Credits).
/// </summary>
public sealed class GhsaRenderer : IAdvisoryRenderer
{
    public string Id => "ghsa";
    public string DisplayName => "GHSA (GitHub Advisory)";
    public string FileExtension => ".md";
    public string DefaultFilename => "advisory.md";

    public IReadOnlyCollection<AdvisoryField> FieldHints { get; } = new[]
    {
        AdvisoryField.Title, AdvisoryField.Vendor, AdvisoryField.Product, AdvisoryField.ProductVersion,
        AdvisoryField.Cwe, AdvisoryField.AttackScenario, AdvisoryField.Impact,
        AdvisoryField.CvssV3, AdvisoryField.CvssV4,
        AdvisoryField.DiscoveredOn, AdvisoryField.DisclosedOn,
        AdvisoryField.References, AdvisoryField.CveDedup,
    };

    public string Render(AdvisoryContext ctx)
    {
        var title = ctx.Title
            .Replace("{Product}", ctx.Product ?? "Unknown product")
            .Replace("{Filename}", ctx.PeFilename ?? "target.dll")
            .Replace("{Vendor}", ctx.Vendor ?? "");

        var sb = new StringBuilder();
        sb.AppendLine($"# {title}");
        sb.AppendLine();
        sb.AppendLine(ComposeBody(ctx));
        return sb.ToString();
    }

    /// <summary>
    /// Builds the GHSA markdown body following GitHub's web form template.
    /// </summary>
    private static string ComposeBody(AdvisoryContext ctx)
    {
        var sb = new StringBuilder();

        // Resolve narrative fields; fall back to synthesizers when blank.
        var resolvedImpact = string.IsNullOrWhiteSpace(ctx.Impact)
            ? AdvisoryTemplate.DefaultImpactText(ctx)
            : ctx.Impact.Trim();
        var resolvedScenario = string.IsNullOrWhiteSpace(ctx.AttackScenario)
            ? AdvisoryTemplate.DefaultVulnDetailsText(ctx)
            : ctx.AttackScenario.Trim();
        var resolvedPatches = string.IsNullOrWhiteSpace(ctx.ProposedSolution)
            ? AdvisoryTemplate.DefaultMitigationsText()
            : ctx.ProposedSolution.Trim();

        // Summary callout — first sentence of the attack scenario.
        var summary = FirstSentence(resolvedScenario);
        if (!string.IsNullOrWhiteSpace(summary))
        {
            sb.AppendLine($"> **Summary**: {summary}");
            sb.AppendLine();
        }

        // Affected-component block.
        sb.AppendLine("### Affected component");
        sb.AppendLine();
        if (!string.IsNullOrWhiteSpace(ctx.Vendor))
            sb.AppendLine($"- **Vendor**: {ctx.Vendor}");
        if (!string.IsNullOrWhiteSpace(ctx.Product))
            sb.AppendLine($"- **Product**: {ctx.Product}"
                + (string.IsNullOrWhiteSpace(ctx.Version) ? "" : $" {ctx.Version}"));
        if (!string.IsNullOrWhiteSpace(ctx.PeFilename))
            sb.AppendLine($"- **Binary**: `{ctx.PeFilename}`"
                + (string.IsNullOrWhiteSpace(ctx.Architecture) ? "" : $" ({ctx.Architecture})"));
        if (!string.IsNullOrWhiteSpace(ctx.InstallDirectory))
            sb.AppendLine($"- **Install directory**: `{ctx.InstallDirectory}`");
        sb.AppendLine($"- **Weakness**: {ctx.Cwe} — {ctx.CweName}");
        if (ctx.CvssScore > 0)
            sb.AppendLine($"- **CVSS v3.1**: {ctx.CvssScore:0.0} ({ctx.CvssSeverity}) — `{ctx.Cvss.VectorString}`");
        if (ctx.CvssV4Score > 0)
            sb.AppendLine($"- **CVSS v4.0**: {ctx.CvssV4Score:0.0} ({ctx.CvssV4Severity}) — `{ctx.CvssV4.VectorString}`");
        sb.AppendLine();

        // Canonical GitHub template sections start here.
        sb.AppendLine("### Impact");
        sb.AppendLine();
        sb.AppendLine(resolvedImpact);
        sb.AppendLine();

        // Technical details — sits between Impact and Patches.
        sb.AppendLine("### Technical details");
        sb.AppendLine();
        sb.AppendLine(resolvedScenario);
        sb.AppendLine();

        sb.AppendLine("### Patches");
        sb.AppendLine();
        sb.AppendLine(resolvedPatches);
        sb.AppendLine();

        // Workarounds — placeholder; no dedicated context field yet.
        sb.AppendLine("### Workarounds");
        sb.AppendLine();
        sb.AppendLine("_Is there a way for users to fix or remediate the vulnerability without upgrading?_");
        sb.AppendLine();

        sb.AppendLine("### References");
        sb.AppendLine();
        if (ctx.References.Count == 0)
            sb.AppendLine("_None at submission time._");
        else
            for (int i = 0; i < ctx.References.Count; i++)
                sb.AppendLine($"{i + 1}. {ctx.References[i]}");
        sb.AppendLine();

        // CVE block — kept inline so the markdown is self-contained.
        sb.AppendLine("### CVE");
        sb.AppendLine();
        sb.AppendLine(ctx.CveDedup?.HasExactMatch == true
            ? $"`{ctx.CveDedup.Matches[0].CveId}` — see references for the matching NVD entry."
            : "Pending coordinated assignment.");
        sb.AppendLine();

        sb.AppendLine("### Credits");
        sb.AppendLine();
        var credits = $"- {ctx.ResearcherName}"
            + (string.IsNullOrWhiteSpace(ctx.ResearcherHandle) ? "" : $" ({ctx.ResearcherHandle})")
            + (string.IsNullOrWhiteSpace(ctx.ResearcherBlog) ? "" : $" — {ctx.ResearcherBlog}");
        sb.AppendLine(credits);

        return sb.ToString().TrimEnd();
    }

    /// <summary>
    /// Return text up to the first sentence-ending punctuation or newline; preserves embedded dots in filenames.
    /// </summary>
    private static string FirstSentence(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "";
        var trimmed = text.Trim();

        // Newline always ends the summary.
        var newlineIdx = trimmed.IndexOfAny(new[] { '\n', '\r' });

        // Period must be followed by whitespace or EOS (skip filename dots).
        var periodIdx = -1;
        for (int i = 0; i < trimmed.Length; i++)
        {
            if (trimmed[i] != '.') continue;
            if (i == trimmed.Length - 1 || char.IsWhiteSpace(trimmed[i + 1]))
            {
                periodIdx = i;
                break;
            }
        }

        var idx = -1;
        if (newlineIdx >= 0 && periodIdx >= 0) idx = Math.Min(newlineIdx, periodIdx);
        else if (newlineIdx >= 0) idx = newlineIdx;
        else if (periodIdx >= 0) idx = periodIdx;

        return idx > 0 ? trimmed[..idx].Trim() : trimmed;
    }

}
