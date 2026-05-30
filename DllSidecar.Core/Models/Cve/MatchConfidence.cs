namespace DllSidecar.Core.Models.Cve;

/// <summary>How closely a CVE matches the target being analyzed.</summary>
public enum MatchConfidence
{
    /// <summary>No meaningful connection — keyword coincidence only.</summary>
    Unrelated,
    /// <summary>Same CWE family (e.g. CWE-427) and same category of product, no name match.</summary>
    Related,
    /// <summary>Vendor + product name match, CWE-427 or sideloading keyword present.</summary>
    Likely,
    /// <summary>Same vendor + product + the specific DLL filename mentioned in the description.
    /// Treat as a DUPLICATE unless you verify otherwise.</summary>
    Exact,
}
