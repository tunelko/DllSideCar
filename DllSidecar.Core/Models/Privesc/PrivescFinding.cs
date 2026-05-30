namespace DllSidecar.Core.Models.Privesc;

/// <summary>Single privesc finding attached by a detector; highest severity becomes the Context's summary.</summary>
public class PrivescFinding
{
    public required PrivescVector Vector { get; set; }
    public required PrivescSeverity Severity { get; set; }
    public required string DetectorName { get; set; }   // e.g. "ServicesDetector"
    public required string Title { get; set; }          // one-liner for UI
    public required string Evidence { get; set; }       // registry key path / task name / manifest XML fragment

    /// <summary>Optional cross-reference: the privileged process that loads this DLL/EXE.</summary>
    public string? PrivilegedProcessPath { get; set; }
    public string? PrivilegedAccount { get; set; }      // LocalSystem / NT AUTHORITY\SYSTEM / etc.
    public Dictionary<string, string> Extras { get; set; } = [];
}
