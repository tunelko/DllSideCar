namespace DllSidecar.Core.Models.Advisory;

/// <summary>CVSS 3.1 base metrics (8 inputs).</summary>
public class CvssVector
{
    public char AttackVector { get; set; } = 'L';      // Local is default for sideloading
    public char AttackComplexity { get; set; } = 'L';
    public char PrivilegesRequired { get; set; } = 'L';
    public char UserInteraction { get; set; } = 'N';
    public char Scope { get; set; } = 'U';
    public char Confidentiality { get; set; } = 'H';
    public char Integrity { get; set; } = 'H';
    public char Availability { get; set; } = 'H';

    /// <summary>CVSS 3.1 vector string like CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</summary>
    public string VectorString =>
        $"CVSS:3.1/AV:{AttackVector}/AC:{AttackComplexity}/PR:{PrivilegesRequired}/UI:{UserInteraction}/S:{Scope}/C:{Confidentiality}/I:{Integrity}/A:{Availability}";
}
