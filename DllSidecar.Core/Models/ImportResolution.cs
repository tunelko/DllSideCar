namespace DllSidecar.Core.Models;

/// <summary>Static resolution outcome for one importer + DLL request.</summary>
public enum ImportResolutionKind
{
    ResolvedLocal,
    ResolvedSystem,
    Unresolved,
    Ambiguous,
}

public enum ImportSearchLocationKind
{
    ExplicitPath,
    KnownDll,
    ApiSet,
    LocalDirectory,
    SystemDirectory,
    OtherArchitectureSystemDirectory,
    OtherScannedDirectory,
}

public enum ImportSearchOutcome
{
    Found,
    NotFound,
    Skipped,
    Unknown,
}

/// <summary>One explainable step in the static DLL resolution baseline.</summary>
public sealed class ImportSearchStep
{
    public required ImportSearchLocationKind Location { get; init; }
    public required string CandidatePath { get; init; }
    public required ImportSearchOutcome Outcome { get; init; }
    public string? Architecture { get; init; }
    public string? Note { get; init; }
}

/// <summary>
/// Conservative static resolution. Dynamic process state such as SxS redirection,
/// loaded modules and AddDllDirectory remains outside this verdict.
/// </summary>
public sealed class ImportResolution
{
    public required string ImporterPath { get; init; }
    public required string DllName { get; init; }
    public required ImportResolutionKind Kind { get; init; }
    public string? ResolvedPath { get; init; }
    public required string Reason { get; init; }
    public List<ImportSearchStep> Steps { get; init; } = [];

    public bool IsExactLocal => Kind == ImportResolutionKind.ResolvedLocal
        && !string.IsNullOrWhiteSpace(ResolvedPath);
}
