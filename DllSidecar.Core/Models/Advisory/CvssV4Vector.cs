namespace DllSidecar.Core.Models.Advisory;

/// <summary>
/// CVSS 4.0 Base metrics. Spec: https://www.first.org/cvss/v4.0/specification-document
/// Only the base (mandatory) dimensions are modeled here — Threat / Environmental /
/// Supplemental can be layered on later if needed.
///
/// Defaults reflect a typical DLL-sideloading scenario:
///  AV:L  AC:L  AT:N  PR:L  UI:N  VC:H VI:H VA:H  SC:N SI:N SA:N
/// </summary>
public class CvssV4Vector
{
    public char AttackVector { get; set; } = 'L';        // N, A, L, P
    public char AttackComplexity { get; set; } = 'L';    // L, H
    public char AttackRequirements { get; set; } = 'N';  // N, P (new in v4)
    public char PrivilegesRequired { get; set; } = 'L';  // N, L, H
    public char UserInteraction { get; set; } = 'N';     // N, P, A (v4 splits "Required" into Passive / Active)

    // Vulnerable-system impact
    public char VulnerableConfidentiality { get; set; } = 'H'; // N, L, H
    public char VulnerableIntegrity { get; set; } = 'H';
    public char VulnerableAvailability { get; set; } = 'H';

    // Subsequent-system impact (v4 replaces v3's Scope)
    public char SubsequentConfidentiality { get; set; } = 'N';
    public char SubsequentIntegrity { get; set; } = 'N';
    public char SubsequentAvailability { get; set; } = 'N';

    /// <summary>
    /// Canonical v4.0 vector string:
    /// "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    /// </summary>
    public string VectorString =>
        $"CVSS:4.0/AV:{AttackVector}/AC:{AttackComplexity}/AT:{AttackRequirements}" +
        $"/PR:{PrivilegesRequired}/UI:{UserInteraction}" +
        $"/VC:{VulnerableConfidentiality}/VI:{VulnerableIntegrity}/VA:{VulnerableAvailability}" +
        $"/SC:{SubsequentConfidentiality}/SI:{SubsequentIntegrity}/SA:{SubsequentAvailability}";
}
