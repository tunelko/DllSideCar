namespace DllSidecar.Core.Models.Execution;

/// <summary>
/// Known command-line wrappers that Task Scheduler / service ImagePath entries commonly
/// use to launch their real target. The resolver peels exactly one level of wrapping
/// (Sprint 2 scope) — recursive resolution is out of scope.
/// </summary>
public enum WrapperKind
{
    None,
    Cmd,        // cmd.exe /c  |  cmd.exe /k
    PowerShell, // powershell.exe / pwsh.exe  (-File, -EncodedCommand)
    RunDll32,   // rundll32.exe path,Entry
    MsiExec,    // msiexec.exe  /i | /x | /a | /package
}

public enum ResolutionStatus
{
    Resolved,   // Target path pinned with high confidence
    Partial,    // Wrapper identified but target could not be pinned (e.g. -EncodedCommand with no literal path)
    Unresolved, // Could not parse at all — literal kept for evidence
}
