using System.Text;
using DllSidecar.Core.Models.Advisory;

namespace DllSidecar.Core.Services.Advisory.Rendering;

/// <summary>
/// Renders to the GitHub Security Advisory (GHSA) format used in the
/// https://github.com/github/advisory-database repository: YAML front-matter with the
/// structured metadata followed by a Markdown body.
///
/// Note: GHSA's "affected" array expects a package ecosystem (npm, nuget, maven, rubygems,
/// composer, pip, go, rust). For DLL-sideloading findings against proprietary Windows
/// binaries there is no matching ecosystem — we emit a descriptive placeholder and the
/// researcher edits it if publishing on a GitHub project whose source is open-source.
/// </summary>
public sealed class GhsaRenderer : IAdvisoryRenderer
{
    public string Id => "ghsa";
    public string DisplayName => "GHSA (GitHub Advisory)";
    public string FileExtension => ".yaml";
    public string DefaultFilename => "advisory.yaml";

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
        var sb = new StringBuilder();
        var title = ctx.Title
            .Replace("{Product}", ctx.Product ?? "Unknown product")
            .Replace("{Filename}", ctx.PeFilename ?? "target.dll")
            .Replace("{Vendor}", ctx.Vendor ?? "");

        var severity = MapSeverity(ctx.CvssScore > 0 ? ctx.CvssScore : ctx.CvssV4Score);
        var cveLine = ctx.CveDedup?.HasExactMatch == true
            ? $"  - type: CVE\n    value: {ctx.CveDedup.Matches[0].CveId}"
            : "";

        // YAML frontmatter
        sb.AppendLine("---");
        sb.AppendLine($"schema-version: \"1.4.0\"");
        sb.AppendLine($"id: GHSA-xxxx-xxxx-xxxx   # replaced by GitHub on publish");
        sb.AppendLine("modified: " + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
        sb.AppendLine($"published: {ctx.DisclosedOn?.ToUniversalTime():yyyy-MM-ddTHH:mm:ssZ}".Replace("published: T", "published: "));
        sb.AppendLine($"aliases: []");
        sb.AppendLine($"summary: {Yaml(title)}");
        sb.AppendLine($"details: |-");
        var body = ComposeBody(ctx);
        foreach (var line in body.Split('\n')) sb.AppendLine("  " + line.TrimEnd('\r'));
        sb.AppendLine();
        sb.AppendLine("severity:");
        sb.AppendLine($"  - type: CVSS_V3");
        sb.AppendLine($"    score: {ctx.Cvss.VectorString}");
        if (ctx.CvssV4Score > 0)
        {
            sb.AppendLine($"  - type: CVSS_V4");
            sb.AppendLine($"    score: {ctx.CvssV4.VectorString}");
        }
        sb.AppendLine("affected:");
        sb.AppendLine("  - package:");
        sb.AppendLine($"      ecosystem: \"other\"");
        sb.AppendLine($"      name: {Yaml(ctx.Product ?? ctx.PeFilename ?? "unknown")}");
        sb.AppendLine("    ranges:");
        sb.AppendLine("      - type: ECOSYSTEM");
        sb.AppendLine("        events:");
        sb.AppendLine($"          - introduced: \"0\"");
        if (!string.IsNullOrWhiteSpace(ctx.Version))
            sb.AppendLine($"          - last_affected: {Yaml(ctx.Version)}");
        sb.AppendLine("database-specific:");
        sb.AppendLine($"  cwe-ids:");
        sb.AppendLine($"    - {ctx.Cwe}");
        sb.AppendLine($"  severity: {severity}");
        sb.AppendLine("references:");
        foreach (var r in ctx.References) sb.AppendLine($"  - type: WEB\n    url: {Yaml(r)}");
        if (!string.IsNullOrEmpty(cveLine))
        {
            sb.AppendLine(cveLine);
        }
        sb.AppendLine("credits:");
        sb.AppendLine("  - type: finder");
        sb.AppendLine($"    value: {Yaml(ctx.ResearcherName + " " + ctx.ResearcherHandle)}");
        sb.AppendLine("---");
        sb.AppendLine();

        // Markdown body repeated outside frontmatter for GitHub web rendering
        sb.AppendLine($"# {title}");
        sb.AppendLine();
        sb.AppendLine(body);

        return sb.ToString();
    }

    private static string ComposeBody(AdvisoryContext ctx)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(ctx.AttackScenario)) parts.Add($"## Description\n\n{ctx.AttackScenario.Trim()}");
        if (!string.IsNullOrWhiteSpace(ctx.Impact))         parts.Add($"## Impact\n\n{ctx.Impact.Trim()}");
        if (!string.IsNullOrWhiteSpace(ctx.ProposedSolution)) parts.Add($"## Patches / Mitigation\n\n{ctx.ProposedSolution.Trim()}");
        if (parts.Count == 0) parts.Add("## Description\n\n(describe the vulnerability here)");
        return string.Join("\n\n", parts);
    }

    /// <summary>Quote a YAML scalar only when necessary; keeps simple values unquoted.</summary>
    private static string Yaml(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return "\"\"";
        if (raw.Contains(':') || raw.Contains('#') || raw.Contains('"') || raw.StartsWith("- ") || raw.StartsWith(" ") || raw.EndsWith(" "))
            return "\"" + raw.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        return raw;
    }

    private static string MapSeverity(double score) => score switch
    {
        0 => "LOW",
        < 4 => "LOW",
        < 7 => "MODERATE",
        < 9 => "HIGH",
        _ => "CRITICAL",
    };
}
