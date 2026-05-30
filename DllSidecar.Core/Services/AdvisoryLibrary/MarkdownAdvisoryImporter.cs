using System.Text.RegularExpressions;
using DllSidecar.Core.Models.Advisory;

namespace DllSidecar.Core.Services.AdvisoryLibrary;

/// <summary>Best-effort parser that turns a markdown file into a draft AdvisoryContext.</summary>
public static class MarkdownAdvisoryImporter
{
    private static readonly Regex H1 = new(@"^\s*#\s+(?<t>.+?)\s*$", RegexOptions.Multiline | RegexOptions.Compiled);
    private static readonly Regex CveId = new(@"CVE-\d{4}-\d{4,}", RegexOptions.Compiled);
    private static readonly Regex CweId = new(@"CWE-\d+", RegexOptions.Compiled);
    private static readonly Regex VendorLine = new(@"^\s*(?:\*\*)?[Vv]endor(?:\*\*)?\s*[:·|]\s*(?<v>.+?)\s*$", RegexOptions.Multiline | RegexOptions.Compiled);
    private static readonly Regex ProductLine = new(@"^\s*(?:\*\*)?[Pp]roduct(?:\*\*)?\s*[:·|]\s*(?<v>.+?)\s*$", RegexOptions.Multiline | RegexOptions.Compiled);
    private static readonly Regex VersionLine = new(@"^\s*(?:\*\*)?[Vv]ersion(?:\*\*)?\s*[:·|]\s*(?<v>.+?)\s*$", RegexOptions.Multiline | RegexOptions.Compiled);

    public static AdvisoryContext Parse(string markdown)
    {
        var ctx = new AdvisoryContext();
        if (string.IsNullOrWhiteSpace(markdown)) return ctx;

        var h1 = H1.Match(markdown);
        if (h1.Success) ctx.Title = CleanInline(h1.Groups["t"].Value);

        var vendor = VendorLine.Match(markdown);
        if (vendor.Success) ctx.Vendor = CleanInline(vendor.Groups["v"].Value);

        var product = ProductLine.Match(markdown);
        if (product.Success) ctx.Product = CleanInline(product.Groups["v"].Value);

        var version = VersionLine.Match(markdown);
        if (version.Success) ctx.Version = CleanInline(version.Groups["v"].Value);

        var cwe = CweId.Match(markdown);
        if (cwe.Success) ctx.Cwe = cwe.Value;

        // CVE id appended to Title; CveDedup stays empty (NVD-API sourced).
        var cve = CveId.Match(markdown);
        if (cve.Success && !ctx.Title.Contains(cve.Value, StringComparison.OrdinalIgnoreCase))
        {
            ctx.Title = $"{ctx.Title} ({cve.Value})".Trim();
        }

        return ctx;
    }

    /// <summary>Strip markdown inline formatting (** __ ` *) from a single-line value.</summary>
    private static string CleanInline(string v)
    {
        v = v.Trim();
        v = Regex.Replace(v, @"\*\*|__|`", "");
        return v.Trim();
    }
}
