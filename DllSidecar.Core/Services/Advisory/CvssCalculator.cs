using DllSidecar.Core.Models.Advisory;

namespace DllSidecar.Core.Services.Advisory;

/// <summary>
/// Minimal CVSS 3.1 base score calculator. Implements the published formulas at
/// https://www.first.org/cvss/v3.1/specification-document. Enough for base score + severity;
/// temporal/environmental metrics are out of scope for the initial advisory pass.
/// </summary>
public static class CvssCalculator
{
    public static (double Score, string Severity) Compute(CvssVector v)
    {
        double av  = v.AttackVector switch       { 'N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.20, _ => 0.55 };
        double ac  = v.AttackComplexity switch   { 'L' => 0.77, 'H' => 0.44, _ => 0.77 };
        double ui  = v.UserInteraction switch    { 'N' => 0.85, 'R' => 0.62, _ => 0.85 };
        bool scopeChanged = v.Scope == 'C';
        double pr = v.PrivilegesRequired switch
        {
            'N' => 0.85,
            'L' => scopeChanged ? 0.68 : 0.62,
            'H' => scopeChanged ? 0.50 : 0.27,
            _   => 0.85,
        };
        double c = v.Confidentiality switch { 'N' => 0, 'L' => 0.22, 'H' => 0.56, _ => 0 };
        double i = v.Integrity        switch { 'N' => 0, 'L' => 0.22, 'H' => 0.56, _ => 0 };
        double a = v.Availability     switch { 'N' => 0, 'L' => 0.22, 'H' => 0.56, _ => 0 };

        // Impact sub-score
        double iscBase = 1 - ((1 - c) * (1 - i) * (1 - a));
        double impact = scopeChanged
            ? 7.52 * (iscBase - 0.029) - 3.25 * Math.Pow(iscBase - 0.02, 15)
            : 6.42 * iscBase;

        // Exploitability sub-score
        double exploitability = 8.22 * av * ac * pr * ui;

        double baseScore;
        if (impact <= 0)
            baseScore = 0;
        else if (scopeChanged)
            baseScore = RoundUp(Math.Min(1.08 * (impact + exploitability), 10));
        else
            baseScore = RoundUp(Math.Min(impact + exploitability, 10));

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

    /// <summary>Round up to one decimal per CVSS 3.1 spec.</summary>
    private static double RoundUp(double value) => Math.Ceiling(value * 10) / 10.0;

    /// <summary>
    /// Parse a CVSS 3.1 vector string like "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    /// into a CvssVector. Returns null when the string cannot be parsed.
    /// </summary>
    public static CvssVector? ParseVector(string vector)
    {
        if (string.IsNullOrWhiteSpace(vector)) return null;
        var v = new CvssVector();
        foreach (var seg in vector.Split('/'))
        {
            var kv = seg.Split(':');
            if (kv.Length != 2 || kv[1].Length == 0) continue;
            var val = kv[1][0];
            switch (kv[0])
            {
                case "AV": v.AttackVector = val; break;
                case "AC": v.AttackComplexity = val; break;
                case "PR": v.PrivilegesRequired = val; break;
                case "UI": v.UserInteraction = val; break;
                case "S":  v.Scope = val; break;
                case "C":  v.Confidentiality = val; break;
                case "I":  v.Integrity = val; break;
                case "A":  v.Availability = val; break;
            }
        }
        return v;
    }
}
