namespace DllSidecar.Core.Models.Privesc;

/// <summary>Attack-chain step kind, ordered primitive → outcome.</summary>
public enum ChainStepKind
{
    WritePrimitive,   // "Writable dir" / "Low-priv writable slot"
    LoadVector,       // "Signed importer" / "Phantom slot"
    Trigger,          // "Scheduled task HighestAvailable" / "Service auto-start"
    Privilege,        // "SYSTEM" / "Admin high-integrity"
    RuntimeEvidence,  // "ProcMon confirmed in dir" — only when Confidence is runtime-level
}

/// <summary>One step in the exploitation chain for a candidate.</summary>
public class ChainStep
{
    public required ChainStepKind Kind { get; set; }
    public required string Label { get; set; }  // short, UI-sized ("Writable dir", "SYSTEM")
    public string? Detail { get; set; }         // optional tooltip-level extra
}
