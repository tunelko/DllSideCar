using System.Text;
using DllSidecar.Core.Models.Advisory;

namespace DllSidecar.Core.Services.Advisory.Rendering;

/// <summary>
/// Renders an AdvisoryContext into the INCIBE-CERT "New vulnerabilities discovery form"
/// plain-text layout. Structure preserved verbatim from the template supplied by the
/// researcher (2026-04). Field labels, indentation, and pipe-character checkbox markers
/// are kept exactly as INCIBE expects. Deviations from the template would force their
/// intake staff to re-format, so the whole point of this renderer is fidelity.
/// </summary>
public sealed class IncibeCnaRenderer : IAdvisoryRenderer
{
    public string Id => "incibe";
    public string DisplayName => "INCIBE CNA";
    public string FileExtension => ".txt";
    public string DefaultFilename => "advisory.txt";

    public IReadOnlyCollection<AdvisoryField> FieldHints { get; } = new[]
    {
        AdvisoryField.Title, AdvisoryField.Vendor, AdvisoryField.VendorUrl,
        AdvisoryField.VendorPocName, AdvisoryField.VendorPocEmail,
        AdvisoryField.Product, AdvisoryField.ProductVersion, AdvisoryField.DeviceUrlReference,
        AdvisoryField.DeviceBriefSummary, AdvisoryField.Cwe, AdvisoryField.VulnerabilityTypeText,
        AdvisoryField.AttackType, AdvisoryField.ImpactCategory,
        AdvisoryField.AttackScenario, AdvisoryField.Impact, AdvisoryField.AffectedComponents,
        AdvisoryField.PreviousRequirements, AdvisoryField.ProposedSolution,
        AdvisoryField.HasContactedVendorNote, AdvisoryField.CvssV4,
        AdvisoryField.DiscoveredOn, AdvisoryField.ReportedOn, AdvisoryField.DisclosedOn,
        AdvisoryField.References, AdvisoryField.ResearcherPgp, AdvisoryField.IncibeRanking,
        AdvisoryField.GeneratedDllPath, AdvisoryField.PayloadDescription,
    };

    public string Render(AdvisoryContext ctx)
    {
        var sb = new StringBuilder();

        sb.AppendLine("                *********************************************************");
        sb.AppendLine("                *                                                       *");
        sb.AppendLine("                *          New vulnerabilities discovery form           *");
        sb.AppendLine("                *                                                       *");
        sb.AppendLine("                *********************************************************");
        sb.AppendLine();
        sb.AppendLine("The information contained in this document is categorized as TLP-AMBER+STRICT");
        sb.AppendLine("More information about this can be found at this link: https://www.incibe.es/incibe-cert/sobre-incibe-cert/TLP");
        sb.AppendLine();

        // ─────────── Section 1: Contact Information ───────────
        sb.AppendLine("-------------------------------------------------------------------------------------");
        sb.AppendLine("|                    Section 1: Contact Information                                 |");
        sb.AppendLine("-------------------------------------------------------------------------------------");
        sb.AppendLine();
        sb.AppendLine($"    Applicant name:     {ctx.ResearcherName}");
        var org = string.IsNullOrEmpty(ctx.ResearcherBlog)
            ? "Independent security researcher"
            : $"Independent security researcher ({ctx.ResearcherBlog})";
        sb.AppendLine($"    Organization:       {org}");
        sb.AppendLine($"    Email:              {Value(ctx.ResearcherEmail)}");
        var pgp = !string.IsNullOrEmpty(ctx.ResearcherPgpFingerprint)
            ? ctx.ResearcherPgpFingerprint + (string.IsNullOrEmpty(ctx.ResearcherPgpKeyId) ? "" : $" (Key ID {ctx.ResearcherPgpKeyId})")
            : "—";
        sb.AppendLine($"    PGP key:            {pgp}");
        sb.AppendLine();
        sb.AppendLine("    Ranking CVEs asignados (https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/asignacion-publicacion-cve)");
        sb.AppendLine($"    - ¿Quieres aparecer en el ranking?: {(ctx.IncibeRankingOptIn ? "Si" : "No")}");
        var publicName = string.IsNullOrWhiteSpace(ctx.IncibePublicDisplayName)
            ? $"{ctx.ResearcherName} ({ctx.ResearcherHandle})"
            : ctx.IncibePublicDisplayName;
        sb.AppendLine($"    - Nombre completo a mostrar (2 apellidos) o pseudónimo: {publicName}");
        sb.AppendLine("    Puede consultar la política de protección de datos en la siguiente página web https://www.incibe.es/incibe/proteccion-datos-personales");
        sb.AppendLine();

        // ─────────── Section 2: Vulnerability Information ───────────
        sb.AppendLine("-------------------------------------------------------------------------------------");
        sb.AppendLine("|                   Section 2: Vulnerability Information                            |");
        sb.AppendLine("-------------------------------------------------------------------------------------");
        sb.AppendLine();
        var title = Interpolate(ctx.Title, ctx);
        sb.AppendLine($"    Vulnerability title: {title}");
        sb.AppendLine();
        sb.AppendLine("    Vulnerability type (Check the option with *):");
        // For DLL sideloading we always fall into "Other or unknown" with text describing the actual CWE.
        sb.AppendLine("                Cross Site Request Forgery (CSRF)  | |");
        sb.AppendLine("                Cross Site Scrtipting (XSS)        | |");
        sb.AppendLine("                Directory Transversal              | |");
        sb.AppendLine("                Incorrect Access Control           | |");
        sb.AppendLine("                Insecure Permissions               | |");
        sb.AppendLine("                Integer Overflow                   | |");
        sb.AppendLine("                Missing SSL Certificate Validation | |");
        sb.AppendLine("                SQL Injection                      | |");
        sb.AppendLine("                XML External Entity (XXE)          | |");
        sb.AppendLine($"                Other or unknown                   |*|  {ctx.VulnerabilityTypeText}");
        sb.AppendLine();

        sb.AppendLine("    Attack type produced (Check the option with *):");
        AppendCheck(sb, "Context dependent", ctx.AttackType == AttackType.ContextDependent);
        AppendCheck(sb, "Local",             ctx.AttackType == AttackType.Local);
        AppendCheck(sb, "Physical",          ctx.AttackType == AttackType.Physical);
        AppendCheck(sb, "Remote",            ctx.AttackType == AttackType.Remote);
        AppendCheck(sb, "Other",             ctx.AttackType == AttackType.Other);
        sb.AppendLine();

        sb.AppendLine("    Impact (Check the option with *):");
        AppendCheck(sb, "Code Execution",          ctx.ImpactCategory == ImpactCategory.CodeExecution);
        AppendCheck(sb, "Denial of service",       ctx.ImpactCategory == ImpactCategory.DenialOfService);
        AppendCheck(sb, "Escalation of Privileges", ctx.ImpactCategory == ImpactCategory.EscalationOfPrivileges);
        AppendCheck(sb, "Information Disclosure",  ctx.ImpactCategory == ImpactCategory.InformationDisclosure);
        AppendCheck(sb, "Other",                    ctx.ImpactCategory == ImpactCategory.Other);
        sb.AppendLine();

        sb.AppendLine($"    Discovery date:                     {Date(ctx.DiscoveredOn)}");
        sb.AppendLine($"    Device manufacturer:                {ctx.Vendor ?? "—"}{VendorUrl(ctx)}");
        sb.AppendLine($"    Device model:                       {Value(ctx.Product)}");
        sb.AppendLine($"    Device version:                     {Value(ctx.Version)}");
        sb.AppendLine($"    Device URL reference:               {Value(ctx.DeviceUrlReference)}");
        sb.AppendLine("    Affected components:                " + FirstLine(ctx.AffectedComponents));
        foreach (var line in ExtraLines(ctx.AffectedComponents))
            sb.AppendLine($"                                          - {line}");
        sb.AppendLine();

        sb.AppendLine("    Brief summary of device:            " + (ctx.DeviceBriefSummary?.Trim() ?? "—"));
        sb.AppendLine();

        var vendorPoc = ctx.VendorPocName ?? "—";
        if (!string.IsNullOrWhiteSpace(ctx.VendorPocEmail)) vendorPoc += $" <{ctx.VendorPocEmail}>";
        sb.AppendLine($"    Manufacturer POC (Point of Contact): {vendorPoc}");
        sb.AppendLine();

        sb.AppendLine("    Have you contacted the manufacturer after contacting INCIBE?:");
        var contactNote = string.IsNullOrWhiteSpace(ctx.HasContactedVendorNote)
            ? "(describe the vendor contact timeline here)"
            : ctx.HasContactedVendorNote;
        foreach (var l in contactNote.Split('\n')) sb.AppendLine($"        {l.TrimEnd('\r')}");
        sb.AppendLine();

        sb.AppendLine($"    CVSS v4.0 score:                    {ctx.CvssV4Score:0.0} ({ctx.CvssV4Severity})");
        sb.AppendLine($"    CVSS v4.0 vector:                   {ctx.CvssV4.VectorString}");
        sb.AppendLine();
        sb.AppendLine($"    CWE:                                {ctx.Cwe} ({ctx.CweName})");
        sb.AppendLine();

        sb.AppendLine("    Vulnerability description:");
        var description = string.IsNullOrWhiteSpace(ctx.AttackScenario) ? ctx.Impact : ctx.AttackScenario;
        if (string.IsNullOrWhiteSpace(description))
            description = "(describe the root cause, the trigger, and the observed effect here)";
        foreach (var l in description.Split('\n')) sb.AppendLine($"        {l.TrimEnd('\r')}");
        sb.AppendLine();

        sb.AppendLine("    Previous requirements:");
        var reqs = (ctx.PreviousRequirements ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (reqs.Length == 0)
            sb.AppendLine("        - (list preconditions here; e.g. local standard user, write access to %TEMP%)");
        else foreach (var r in reqs) sb.AppendLine($"        - {r.Trim()}");
        sb.AppendLine();

        sb.AppendLine("    Proof of concept:");
        if (!string.IsNullOrWhiteSpace(ctx.GeneratedDllPath))
            sb.AppendLine($"        Generated PoC DLL: {ctx.GeneratedDllPath}");
        if (!string.IsNullOrWhiteSpace(ctx.PayloadDescription))
            sb.AppendLine($"        Payload: {ctx.PayloadDescription}");
        if (string.IsNullOrWhiteSpace(ctx.GeneratedDllPath) && string.IsNullOrWhiteSpace(ctx.PayloadDescription))
            sb.AppendLine("        (attach PoC package path + short reproduction steps here)");
        sb.AppendLine();

        // ─────────── Section 3: Solution and Additional Information ───────────
        sb.AppendLine("-------------------------------------------------------------------------------------");
        sb.AppendLine("|                   Section 3: Solution and Additional Information                  |");
        sb.AppendLine("-------------------------------------------------------------------------------------");
        sb.AppendLine();
        sb.AppendLine("    Proposed solution:");
        var solution = string.IsNullOrWhiteSpace(ctx.ProposedSolution)
            ? "(describe the fix / mitigation recommendation here)"
            : ctx.ProposedSolution;
        foreach (var l in solution.Split('\n')) sb.AppendLine($"        {l.TrimEnd('\r')}");
        sb.AppendLine();

        sb.AppendLine("    References:");
        if (ctx.References.Count == 0)
            sb.AppendLine("        - (add vendor URL, CWE link, CVSS calculator, related MS docs, researcher blog)");
        else foreach (var r in ctx.References) sb.AppendLine($"        - {r.Trim()}");
        sb.AppendLine();

        sb.AppendLine("--------------------------------------------------------------------------------------");

        return sb.ToString();
    }

    private static void AppendCheck(StringBuilder sb, string label, bool check)
    {
        var pipe = check ? "|*|" : "| |";
        sb.AppendLine($"                {label.PadRight(34)} {pipe}");
    }

    private static string Interpolate(string template, AdvisoryContext ctx) =>
        template.Replace("{Product}", ctx.Product ?? "")
                .Replace("{Filename}", ctx.PeFilename ?? "")
                .Replace("{Vendor}", ctx.Vendor ?? "")
                .Replace("  ", " ").Trim();

    private static string Value(string? v) => string.IsNullOrWhiteSpace(v) ? "—" : v.Trim();
    private static string Date(DateTime? d) => d?.ToLocalTime().ToString("yyyy-MM-dd") ?? "—";

    private static string VendorUrl(AdvisoryContext ctx) =>
        string.IsNullOrWhiteSpace(ctx.VendorUrl) ? "" : $" ({ctx.VendorUrl})";

    private static string FirstLine(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "—";
        var idx = raw.IndexOf('\n');
        return idx < 0 ? raw.Trim() : raw.Substring(0, idx).Trim();
    }
    private static IEnumerable<string> ExtraLines(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) yield break;
        var lines = raw.Split('\n');
        for (int i = 1; i < lines.Length; i++)
        {
            var t = lines[i].Trim();
            if (!string.IsNullOrWhiteSpace(t)) yield return t;
        }
    }
}
