namespace DllSidecar.Core.Models.Privesc;

/// <summary>
/// Per-candidate aggregation of privesc findings. Attached to SideloadCandidate and
/// PhantomCandidate as an optional property — presence means at least one detector
/// identified a privilege escalation vector for this DLL/EXE.
/// </summary>
public class PrivescContext
{
    public List<PrivescFinding> Findings { get; set; } = [];

    /// <summary>
    /// Structured chain for UI — built by ChainBuilder after the candidate is fully scored.
    /// Stays empty until the scorer populates it so legacy callers are unaffected.
    /// </summary>
    public List<ChainStep> ChainSteps { get; set; } = [];

    /// <summary>Human-readable one-liner derived from ChainSteps (UI convenience).</summary>
    public string ChainSummary { get; set; } = "";

    public PrivescSeverity HighestSeverity =>
        Findings.Count == 0 ? PrivescSeverity.None : Findings.Max(f => f.Severity);

    public PrivescVector PrimaryVector =>
        Findings.Count == 0 ? PrivescVector.None :
        Findings.OrderByDescending(f => f.Severity).First().Vector;

    public bool HasSystemPath =>
        Findings.Any(f => f.Vector is PrivescVector.ServiceSystem or PrivescVector.ScheduledTask
                       && f.Severity >= PrivescSeverity.High);

    public bool HasAutoElevatePath =>
        Findings.Any(f => f.Vector == PrivescVector.AutoElevate);

    /// <summary>Short label for grid display: SYSTEM / UAC / TASK / UPDATER / —</summary>
    public string ShortLabel => PrimaryVector switch
    {
        PrivescVector.ServiceSystem     => "SYSTEM",
        PrivescVector.ScheduledTask     => "TASK",
        PrivescVector.UpdaterHeuristic  => "UPDATER",
        PrivescVector.AutoElevate       => "UAC",
        PrivescVector.HighIntegrity     => "ADMIN",
        _ => "—",
    };
}
