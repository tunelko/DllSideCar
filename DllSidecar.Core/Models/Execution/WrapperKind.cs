namespace DllSidecar.Core.Models.Execution;

/// <summary>Known command-line wrappers Task Scheduler / service ImagePath entries use to launch their target.</summary>
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
