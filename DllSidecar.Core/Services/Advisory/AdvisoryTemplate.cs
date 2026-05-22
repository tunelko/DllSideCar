using System.Text;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Advisory;
using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Services.Advisory;

/// <summary>
/// Renders an AdvisoryContext into a Markdown document. The output is a complete
/// first-draft advisory — the researcher then edits freely. Follows the CLAUDE.md
/// rules on tone: factual, objective, no sarcasm, no "trivially/obviously/amateur".
/// </summary>
public static class AdvisoryTemplate
{
    public static string Render(AdvisoryContext ctx)
    {
        var sb = new StringBuilder();

        // ----- Frontmatter -----
        var title = ctx.Title
            .Replace("{Product}", ctx.Product ?? "Unknown product")
            .Replace("{Filename}", ctx.PeFilename ?? "target.dll");

        sb.AppendLine($"# {title}");
        sb.AppendLine();
        sb.AppendLine("| Field | Value |");
        sb.AppendLine("|-------|-------|");
        sb.AppendLine($"| CVE ID | *(pending assignment)* |");
        sb.AppendLine($"| Reporter | {ctx.ResearcherName} ({ctx.ResearcherHandle}) |");
        sb.AppendLine($"| Blog | {ctx.ResearcherBlog} |");
        sb.AppendLine($"| Discovered | {ctx.DiscoveredOn:yyyy-MM-dd} |");
        sb.AppendLine($"| Vulnerability type | {ctx.VulnType} |");
        sb.AppendLine($"| CWE | [{ctx.Cwe}](https://cwe.mitre.org/data/definitions/{ctx.Cwe.Replace("CWE-", "")}.html) — {ctx.CweName} |");
        sb.AppendLine($"| CVSS 3.1 | **{ctx.CvssScore:0.0} {ctx.CvssSeverity}** |");
        sb.AppendLine($"| CVSS Vector | `{ctx.Cvss.VectorString}` |");
        sb.AppendLine($"| Disclosure | {ctx.DisclosurePolicy} |");
        sb.AppendLine();

        // ----- Summary -----
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine(SummaryText(ctx));
        sb.AppendLine();

        // ----- Affected Product -----
        sb.AppendLine("## Affected Product");
        sb.AppendLine();
        if (!string.IsNullOrEmpty(ctx.Vendor))   sb.AppendLine($"- **Vendor**: {ctx.Vendor}");
        if (!string.IsNullOrEmpty(ctx.Product))  sb.AppendLine($"- **Product**: {ctx.Product}");
        if (!string.IsNullOrEmpty(ctx.Version))  sb.AppendLine($"- **Version tested**: {ctx.Version}");
        if (!string.IsNullOrEmpty(ctx.Architecture)) sb.AppendLine($"- **Architecture**: {ctx.Architecture}");
        if (!string.IsNullOrEmpty(ctx.PePath))   sb.AppendLine($"- **Tested binary**: `{ctx.PePath}`");
        if (!string.IsNullOrEmpty(ctx.InstallDirectory)) sb.AppendLine($"- **Install directory**: `{ctx.InstallDirectory}`");
        sb.AppendLine();

        // ----- Vulnerability Details -----
        sb.AppendLine("## Vulnerability Details");
        sb.AppendLine();
        sb.AppendLine(VulnDetailsText(ctx));
        sb.AppendLine();

        if (ctx.DirectoryLowPrivWritable)
        {
            sb.AppendLine("### Directory ACL");
            sb.AppendLine();
            sb.AppendLine($"The install directory `{ctx.InstallDirectory}` grants write access to low-privilege principals: {ctx.WritableByPrincipals}. ");
            sb.AppendLine("A local user without administrative rights can therefore drop a DLL into this location, " +
                          "which will be picked up by the privileged runner described above.");
            sb.AppendLine();
        }

        // ----- Privesc path -----
        if (ctx.Privesc != null && ctx.Privesc.Findings.Count > 0)
        {
            sb.AppendLine("### Privilege Escalation Vector");
            sb.AppendLine();
            var topFinding = ctx.Privesc.Findings
                .OrderByDescending(f => f.Severity)
                .First();
            sb.AppendLine($"- **Primary vector**: {topFinding.Vector} ({topFinding.Severity})");
            if (!string.IsNullOrEmpty(topFinding.PrivilegedProcessPath))
                sb.AppendLine($"- **Runner**: `{topFinding.PrivilegedProcessPath}`");
            if (!string.IsNullOrEmpty(topFinding.PrivilegedAccount))
                sb.AppendLine($"- **Running as**: {topFinding.PrivilegedAccount}");
            sb.AppendLine($"- **Detector**: {topFinding.DetectorName}");
            sb.AppendLine();
            sb.AppendLine("Full finding:");
            sb.AppendLine("```");
            sb.AppendLine(topFinding.Title);
            sb.AppendLine(topFinding.Evidence);
            sb.AppendLine("```");
            sb.AppendLine();
        }

        // ----- PoC -----
        sb.AppendLine("## Proof of Concept");
        sb.AppendLine();
        sb.AppendLine("### Reproduction steps");
        sb.AppendLine();
        sb.AppendLine("1. Build the sideload DLL (source included in the appendix below).");
        if (!string.IsNullOrEmpty(ctx.GeneratedDllPath))
            sb.AppendLine($"2. Drop the resulting `{Path.GetFileName(ctx.GeneratedDllPath)}` into `{ctx.InstallDirectory ?? Path.GetDirectoryName(ctx.GeneratedDllPath)}`.");
        else
            sb.AppendLine($"2. Drop `{ctx.PeFilename ?? "payload.dll"}` into `{ctx.InstallDirectory ?? "<install dir>"}`.");
        if (!string.IsNullOrEmpty(ctx.ImporterExe))
            sb.AppendLine($"3. Launch `{ctx.ImporterExe}` (or trigger it through its normal usage — e.g. opening a file, scheduled task firing, service starting).");
        else
            sb.AppendLine("3. Launch the affected application in its normal user workflow.");
        sb.AppendLine($"4. Observe the payload: {ctx.PayloadDescription}.");
        sb.AppendLine();

        if (!string.IsNullOrEmpty(ctx.GeneratedDllPath))
        {
            sb.AppendLine($"**Generated DLL**: `{ctx.GeneratedDllPath}`");
            sb.AppendLine();
        }

        // ----- Impact -----
        sb.AppendLine("## Impact");
        sb.AppendLine();
        sb.AppendLine(string.IsNullOrWhiteSpace(ctx.Impact) ? DefaultImpactText(ctx) : ctx.Impact);
        sb.AppendLine();

        // ----- Mitigation -----
        sb.AppendLine("## Recommended Mitigations");
        sb.AppendLine();
        sb.AppendLine("For the vendor:");
        sb.AppendLine();
        sb.AppendLine("- Set `DependentLoadFlags` to `LOAD_LIBRARY_SEARCH_SYSTEM32` (0x800) on the importing binary, or call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` early in the process startup.");
        sb.AppendLine("- Load DLLs by absolute path from a protected location.");
        sb.AppendLine("- Restrict the install directory ACLs to `BUILTIN\\Administrators` and `NT AUTHORITY\\SYSTEM` only — no write permission for low-privilege principals.");
        sb.AppendLine("- Sign all bundled DLLs and verify the signature at load time.");
        sb.AppendLine();

        // ----- Timeline -----
        sb.AppendLine("## Timeline");
        sb.AppendLine();
        sb.AppendLine($"- **{ctx.DiscoveredOn:yyyy-MM-dd}**: Vulnerability discovered during independent research.");
        if (ctx.ReportedOn.HasValue)
            sb.AppendLine($"- **{ctx.ReportedOn:yyyy-MM-dd}**: Reported to vendor.");
        else
            sb.AppendLine("- *TBD*: Reported to vendor.");
        if (ctx.DisclosedOn.HasValue)
            sb.AppendLine($"- **{ctx.DisclosedOn:yyyy-MM-dd}**: Public disclosure.");
        else
            sb.AppendLine("- *TBD*: Public disclosure (after vendor fix or disclosure window expiry).");
        sb.AppendLine();

        // ----- References -----
        sb.AppendLine("## References");
        sb.AppendLine();
        sb.AppendLine("- [CWE-427: Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)");
        sb.AppendLine("- [MITRE ATT&CK T1574.002 — Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)");
        sb.AppendLine("- [Microsoft: Dynamic-Link Library Search Order](https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order)");
        foreach (var r in ctx.References)
            sb.AppendLine($"- {r}");
        sb.AppendLine();

        // ----- CVE dedup note (informational) -----
        if (ctx.CveDedup != null && ctx.CveDedup.Matches.Count > 0)
        {
            sb.AppendLine("## Prior Art (NVD Dedup Check)");
            sb.AppendLine();
            if (ctx.CveDedup.HasExactMatch)
            {
                sb.AppendLine("> ⚠ **Possible duplicate** — the NVD dedup check returned at least one CVE whose description mentions this DLL. Verify the novelty of your finding before reporting.");
                sb.AppendLine();
            }
            foreach (var m in ctx.CveDedup.Matches.Take(5))
            {
                var cvss = m.CvssScore.HasValue ? $"CVSS {m.CvssScore:0.0} {m.CvssSeverity}" : "CVSS —";
                sb.AppendLine($"- [{m.CveId}]({m.NvdUrl}) — {cvss} — {ShortDesc(m.Description, 140)}");
            }
            sb.AppendLine();
        }

        // Footer
        sb.AppendLine("---");
        sb.AppendLine();
        sb.AppendLine($"*Generated by DllSidecar · {ctx.ResearcherBlog}*");

        return sb.ToString();
    }

    private static string SummaryText(AdvisoryContext ctx)
    {
        var vendor = ctx.Vendor ?? "The affected vendor";
        var product = ctx.Product ?? "the affected product";
        var target = ctx.PeFilename ?? "a bundled DLL";
        var pathHint = ctx.DirectoryLowPrivWritable
            ? $" The install directory ({ctx.InstallDirectory}) is writable by non-administrative principals, so a local user can drop a crafted replacement."
            : "";

        return $"{product} by {vendor} loads `{target}` from its install directory using the default Windows loader search order. " +
               $"Because the loader consults the install directory before System32, and because this DLL is not a KnownDLL, " +
               $"an attacker who can place a file with the same name in this directory achieves arbitrary code execution in the context of the loading process.{pathHint}";
    }

    private static string VulnDetailsText(AdvisoryContext ctx)
    {
        if (!string.IsNullOrWhiteSpace(ctx.AttackScenario)) return ctx.AttackScenario;
        var importer = ctx.ImporterExe ?? "the affected executable";
        var target = ctx.PeFilename ?? "the DLL";
        return $"On execution, `{importer}` calls `LoadLibrary` (or an import-table resolution) against `{target}` " +
               $"without specifying an absolute path and without restricting the search to System32. " +
               $"The loader walks the standard search order — starting with the application directory. " +
               $"A DLL with the same name placed in that directory is loaded in preference to any system copy, " +
               $"executing any code present in DllMain or in the resolved exports.";
    }

    /// <summary>
    /// Default Impact narrative used by every renderer when the user hasn't supplied
    /// a custom one in ctx.Impact. Internal so GhsaRenderer can reuse the same
    /// synthesizer instead of leaving italic GitHub placeholders behind.
    /// </summary>
    internal static string DefaultImpactText(AdvisoryContext ctx)
    {
        var hasPrivesc = ctx.Privesc?.HighestSeverity >= PrivescSeverity.High;
        if (hasPrivesc)
        {
            return "Arbitrary code execution in the context of the privileged runner, which according to the detected vector " +
                   "runs as **LocalSystem/SYSTEM** (or with HighestAvailable integrity). A local user without administrative rights " +
                   "achieves full administrative control through this chain.";
        }
        return "Arbitrary code execution in the context of the user running the application. Does not cross integrity boundaries by itself " +
               "but can be chained with other vulnerabilities for privilege escalation.";
    }

    /// <summary>
    /// Default Technical-details narrative — same shape as <see cref="VulnDetailsText"/>
    /// but exposed for cross-renderer reuse.
    /// </summary>
    internal static string DefaultVulnDetailsText(AdvisoryContext ctx) => VulnDetailsText(ctx);

    /// <summary>
    /// Vendor-side mitigation block, ready to drop into a renderer's "Patches" or
    /// "Recommended Mitigations" section when ctx.ProposedSolution is empty.
    /// Bullet list joined by newlines so the caller can wrap it however it likes.
    /// </summary>
    internal static string DefaultMitigationsText() =>
        "- Set `DependentLoadFlags` to `LOAD_LIBRARY_SEARCH_SYSTEM32` (0x800) on the importing binary, or call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` early in the process startup.\n" +
        "- Load DLLs by absolute path from a protected location.\n" +
        "- Restrict the install directory ACLs to `BUILTIN\\Administrators` and `NT AUTHORITY\\SYSTEM` only — no write permission for low-privilege principals.\n" +
        "- Sign all bundled DLLs and verify the signature at load time.";

    private static string ShortDesc(string s, int max) =>
        s.Length <= max ? s : s[..(max - 1)] + "…";
}
