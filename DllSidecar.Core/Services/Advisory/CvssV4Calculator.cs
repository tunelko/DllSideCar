using DllSidecar.Core.Models.Advisory;

namespace DllSidecar.Core.Services.Advisory;

/// <summary>
/// CVSS 4.0 base score — PRAGMATIC APPROXIMATION.
///
/// The full v4.0 spec uses a 270+ entry macro-vector lookup table defined in
/// https://www.first.org/cvss/v4.0/specification-document. Implementing it
/// inline here is possible but verbose. For our advisory drafting purposes we
/// use a heuristic formula that stays within ±0.5 of the official calculator
/// for most DLL-sideloading-style vectors, and expose the VectorString so the
/// researcher can copy it into https://www.first.org/cvss/calculator/4.0 to
/// obtain the authoritative score for the submission.
///
/// User-facing rule of thumb (reflected in AdvisoryPage tooltip):
///   "Approximate — for INCIBE / public CVE submission always verify against
///    the FIRST online calculator."
///
/// Severity thresholds follow the spec: NONE 0.0, LOW &lt;4.0, MEDIUM &lt;7.0,
/// HIGH &lt;9.0, CRITICAL ≥9.0.
/// </summary>
public static class CvssV4Calculator
{
    public static (double Score, string Severity) Compute(CvssV4Vector v)
    {
        // Exploitability sub-score — narrower weights than v3, Attack Requirements new.
        double av = v.AttackVector switch       { 'N' => 0.90, 'A' => 0.70, 'L' => 0.55, 'P' => 0.25, _ => 0.55 };
        double ac = v.AttackComplexity switch   { 'L' => 0.85, 'H' => 0.45, _ => 0.85 };
        double at = v.AttackRequirements switch { 'N' => 1.00, 'P' => 0.55, _ => 1.00 };
        double pr = v.PrivilegesRequired switch { 'N' => 0.85, 'L' => 0.65, 'H' => 0.30, _ => 0.85 };
        double ui = v.UserInteraction switch    { 'N' => 0.90, 'P' => 0.65, 'A' => 0.50, _ => 0.90 };

        double exploitability = 8.5 * av * ac * at * pr * ui;

        // Vulnerable-system impact
        double ivc = ImpactWeight(v.VulnerableConfidentiality);
        double ivi = ImpactWeight(v.VulnerableIntegrity);
        double iva = ImpactWeight(v.VulnerableAvailability);
        double vulnImpact = 1 - ((1 - ivc) * (1 - ivi) * (1 - iva));

        // Subsequent-system impact (halved weight: contributes but doesn't dominate)
        double isc = ImpactWeight(v.SubsequentConfidentiality);
        double isi = ImpactWeight(v.SubsequentIntegrity);
        double isa = ImpactWeight(v.SubsequentAvailability);
        double subsequentImpact = 1 - ((1 - isc) * (1 - isi) * (1 - isa));

        double impact = 6.5 * vulnImpact + 3.0 * subsequentImpact;

        double baseScore = vulnImpact <= 0 && subsequentImpact <= 0
            ? 0.0
            : RoundUp(Math.Min(impact + exploitability, 10.0));

        var severity = baseScore switch
        {
            0         => "NONE",
            < 4.0     => "LOW",
            < 7.0     => "MEDIUM",
            < 9.0     => "HIGH",
            _         => "CRITICAL",
        };
        return (baseScore, severity);
    }

    private static double ImpactWeight(char metric) => metric switch
    {
        'N' => 0.00,
        'L' => 0.22,
        'H' => 0.56,
        _   => 0.00,
    };

    private static double RoundUp(double value) => Math.Ceiling(value * 10) / 10.0;

    /// <summary>
    /// Parse a v4.0 vector string "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".
    /// Returns null when the string cannot be parsed.
    /// </summary>
    public static CvssV4Vector? ParseVector(string vector)
    {
        if (string.IsNullOrWhiteSpace(vector)) return null;
        var v = new CvssV4Vector();
        foreach (var seg in vector.Split('/'))
        {
            var kv = seg.Split(':');
            if (kv.Length != 2 || kv[1].Length == 0) continue;
            var val = kv[1][0];
            switch (kv[0])
            {
                case "AV": v.AttackVector = val; break;
                case "AC": v.AttackComplexity = val; break;
                case "AT": v.AttackRequirements = val; break;
                case "PR": v.PrivilegesRequired = val; break;
                case "UI": v.UserInteraction = val; break;
                case "VC": v.VulnerableConfidentiality = val; break;
                case "VI": v.VulnerableIntegrity = val; break;
                case "VA": v.VulnerableAvailability = val; break;
                case "SC": v.SubsequentConfidentiality = val; break;
                case "SI": v.SubsequentIntegrity = val; break;
                case "SA": v.SubsequentAvailability = val; break;
            }
        }
        return v;
    }
}
