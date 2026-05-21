namespace DllSidecar.Core.Models;

/// <summary>Windows token integrity level, mapped from the RID in the IL SID
/// (S-1-16-{rid}). Captured by EtwDllTracer when a process is detected, used by
/// SandboxClassifier to decide whether a target is sandboxed enough to need the
/// SandboxEscape payload variant.</summary>
public enum IntegrityLevel
{
    Unknown = 0,
    Untrusted = 1,       // S-1-16-0
    Low = 2,             // S-1-16-4096 — AppContainer / IE / browser content
    Medium = 3,          // S-1-16-8192 — default user
    MediumPlus = 4,      // S-1-16-8448
    High = 5,            // S-1-16-12288 — elevated
    System = 6,          // S-1-16-16384 — SYSTEM / service
    ProtectedProcess = 7 // S-1-16-20480 — kernel-protected
}
