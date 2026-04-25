namespace DllSidecar.Core.Models.Execution;

/// <summary>
/// Result of resolving a command line (task Command+Arguments or service ImagePath)
/// into a concrete runner. Shared between ScheduledTaskDetector and ServicesDetector
/// (Sprint 2). See <see cref="Services.Execution.ExecutionResolver"/> for the algorithm.
///
/// Sprint-3 consumers (targeted re-scan) should read <see cref="ResolvedPath"/> when
/// <see cref="Status"/> is Resolved; evidence and original command are kept for UI.
/// </summary>
public class ResolvedExecutionTarget
{
    /// <summary>Literal command line as it appeared in the source (task XML, registry).</summary>
    public required string OriginalCommand { get; set; }

    /// <summary>Concrete target path (EXE / DLL / script / MSI), or null when unresolved.</summary>
    public string? ResolvedPath { get; set; }

    /// <summary>Remaining arguments after the wrapper strip (for reference).</summary>
    public string? Arguments { get; set; }

    /// <summary>Task WorkingDirectory or service equivalent (preserved for context).</summary>
    public string? WorkingDirectory { get; set; }

    public WrapperKind Wrapper { get; set; } = WrapperKind.None;
    public ResolutionStatus Status { get; set; } = ResolutionStatus.Resolved;

    public bool ResolvedViaWrapper => Wrapper != WrapperKind.None;
}
