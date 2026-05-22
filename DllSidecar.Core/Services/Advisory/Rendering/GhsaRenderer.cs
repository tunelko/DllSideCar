using System.Text;
using DllSidecar.Core.Models.Advisory;
using DllSidecar.Core.Services.Advisory;

namespace DllSidecar.Core.Services.Advisory.Rendering;

/// <summary>
/// Renders the GHSA (GitHub Security Advisory) format the researcher pastes into
/// the GitHub web editor at https://github.com/&lt;owner&gt;/&lt;repo&gt;/security/advisories/new.
///
/// Output is pure Markdown — the canonical four sections GitHub pre-fills (Impact /
/// Patches / Workarounds / References) plus the contextual blocks reviewers always ask
/// for (Affected component, Technical details, CVE, Credits). The old OSV YAML
/// front-matter (schema-version, ecosystem, affected ranges …) was removed in
/// v1.1.9 — it duplicated the body, confused the preview, and only mattered for
/// direct PRs into github/advisory-database, a workflow DllSidecar's researcher
/// does not use (the central DB is fed automatically by GitHub once a published
/// repo advisory gets an assigned CVE).
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
    /// Builds the GHSA markdown body. Layout follows GitHub's official "Draft a new security
    /// advisory" web form template (Impact / Patches / Workarounds / References) so the
    /// researcher can copy-paste the output straight into the GitHub advisory editor without
    /// re-sectioning. Around that scaffold we add the contextual blocks reviewers always ask
    /// for first — affected component (vendor / product / binary / arch / install dir / CWE /
    /// CVSS), a one-line summary callout, technical details, CVE status, and credits.
    /// Blank fields fall back to the italicised prompt text GitHub itself uses, so empty
    /// renders still read as a fill-in-the-blanks template instead of an inconsistent dump.
    /// </summary>
    private static string ComposeBody(AdvisoryContext ctx)
    {
        var sb = new StringBuilder();

        // Resolve narrative fields up front. If the user hasn't typed a custom Impact /
        // AttackScenario / ProposedSolution, fall back to the same synthesizer the Markdown
        // renderer uses — otherwise a switch from Markdown to GHSA on a fully populated
        // advisory would surface italic GitHub placeholders even though the ctx carries
        // enough metadata (vendor, product, importer, install dir, privesc) to draft a
        // sensible default for every section.
        var resolvedImpact = string.IsNullOrWhiteSpace(ctx.Impact)
            ? AdvisoryTemplate.DefaultImpactText(ctx)
            : ctx.Impact.Trim();
        var resolvedScenario = string.IsNullOrWhiteSpace(ctx.AttackScenario)
            ? AdvisoryTemplate.DefaultVulnDetailsText(ctx)
            : ctx.AttackScenario.Trim();
        var resolvedPatches = string.IsNullOrWhiteSpace(ctx.ProposedSolution)
            ? AdvisoryTemplate.DefaultMitigationsText()
            : ctx.ProposedSolution.Trim();

        // Summary callout — first sentence of the (resolved) attack scenario, surfaced as a
        // quote so the reader gets the vulnerability in one line before scrolling.
        var summary = FirstSentence(resolvedScenario);
        if (!string.IsNullOrWhiteSpace(summary))
        {
            sb.AppendLine($"> **Summary**: {summary}");
            sb.AppendLine();
        }

        // Affected-component block — the GitHub web template doesn't include this but every
        // reviewer asks for it on first read ("which binary in which version of which
        // product?"). Skipping fields we don't have keeps the list tight.
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

        // Technical details — sits between Impact and Patches; the template doesn't include
        // it but DLL-sideloading findings need the search-order narrative so the reviewer
        // can map "loader looks for X.dll in <dir>" to the proof-of-concept payload path.
        sb.AppendLine("### Technical details");
        sb.AppendLine();
        sb.AppendLine(resolvedScenario);
        sb.AppendLine();

        sb.AppendLine("### Patches");
        sb.AppendLine();
        sb.AppendLine(resolvedPatches);
        sb.AppendLine();

        // Workarounds — AdvisoryContext doesn't carry a dedicated field for this yet, so
        // the placeholder is left for the researcher to fill in before submission. A future
        // refactor can promote this to a model field if the same workaround keeps recurring.
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

        // CVE block — the GitHub UI tracks CVE separately on the form, but having it inline
        // in the markdown keeps the body self-contained when exported to other CNAs.
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
    /// Returns text up to the first sentence-ending punctuation or newline. Used to derive
    /// the one-line Summary callout from the AttackScenario without having to track a
    /// separate field on the context.
    ///
    /// A "sentence end" is a period followed by whitespace or the end of the string — not
    /// any period at all, otherwise filenames like <c>Agent.exe</c> truncate the summary
    /// at the first dot.
    /// </summary>
    private static string FirstSentence(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "";
        var trimmed = text.Trim();

        // Newline always ends the summary — we want one line, not the whole paragraph.
        var newlineIdx = trimmed.IndexOfAny(new[] { '\n', '\r' });

        // Scan for a period that's actually a sentence terminator: followed by whitespace
        // or end-of-string. Skip periods embedded in filenames / version strings.
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
