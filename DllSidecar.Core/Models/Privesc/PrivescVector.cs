namespace DllSidecar.Core.Models.Privesc;

/// <summary>
/// Privilege escalation vector categories. One PE can match multiple vectors.
/// Ordered loosely from highest to lowest typical impact.
/// </summary>
public enum PrivescVector
{
    None,
    ServiceSystem,        // Loaded by a service running as LocalSystem / NT AUTHORITY\SYSTEM
    ScheduledTask,        // Executed by a scheduled task with HighestAvailable or SYSTEM principal
    UpdaterHeuristic,     // Heuristic match on updater/maintenance service binaries (gold targets)
    AutoElevate,          // EXE manifest declares autoElevate=true (UAC bypass class)
    HighIntegrity,        // EXE requires requestedExecutionLevel=requireAdministrator
}

public enum PrivescSeverity
{
    None,          // No privesc path
    Informational, // Context only — same user
    Low,           // Requires user interaction
    Medium,        // Auto-elevate / uiAccess
    High,          // SYSTEM via service or task (user→SYSTEM)
    Critical,      // SYSTEM + signed importer + user-writable dir (the jackpot)
}
