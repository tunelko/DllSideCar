namespace DllSidecar.Core.Models.Execution;

/// <summary>Result of resolving a command line (task or service ImagePath) into a concrete runner.</summary>
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
