using DllSidecar.Core.Helpers;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

internal sealed class ImportResolutionEnvironment
{
    public required string System32Directory { get; init; }
    public required string SysWow64Directory { get; init; }
    public required Func<string, bool> FileExists { get; init; }

    public static ImportResolutionEnvironment Current => new()
    {
        System32Directory = Environment.GetFolderPath(Environment.SpecialFolder.System),
        SysWow64Directory = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
        FileExists = File.Exists,
    };
}

/// <summary>
/// Resolves a static import against the importer's local directory and the matching
/// Windows system directory. It intentionally returns Ambiguous when static context
/// cannot prove which physical PE is used.
/// </summary>
public static class ImportResolutionService
{
    public static ImportResolution Resolve(
        PeAnalysis importer,
        ImportedDll import,
        IReadOnlyDictionary<string, PeAnalysis>? scannedFiles = null) =>
        Resolve(importer, import, scannedFiles, ImportResolutionEnvironment.Current);

    internal static ImportResolution Resolve(
        PeAnalysis importer,
        ImportedDll import,
        IReadOnlyDictionary<string, PeAnalysis>? scannedFiles,
        ImportResolutionEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(importer);
        ArgumentNullException.ThrowIfNull(import);
        ArgumentNullException.ThrowIfNull(environment);

        var dllName = import.DllName.Trim();
        var steps = new List<ImportSearchStep>();
        if (string.IsNullOrWhiteSpace(dllName))
            return Result(ImportResolutionKind.Ambiguous, null, "Empty DLL name", steps);

        var basename = Path.GetFileName(dllName);
        if (string.IsNullOrWhiteSpace(basename))
            return Result(ImportResolutionKind.Ambiguous, null, "Invalid DLL name", steps);

        if (IsApiSet(basename))
        {
            steps.Add(new ImportSearchStep
            {
                Location = ImportSearchLocationKind.ApiSet,
                CandidatePath = basename,
                Outcome = ImportSearchOutcome.Found,
                Note = "Resolved through the Windows API-set schema",
            });
            return Result(ImportResolutionKind.ResolvedSystem, null,
                "API-set contract is resolved by Windows", steps);
        }

        if (KnownDlls.IsKnown(basename))
        {
            var knownPath = CombineSafe(SystemDirectoryFor(importer.Arch, environment), basename);
            steps.Add(new ImportSearchStep
            {
                Location = ImportSearchLocationKind.KnownDll,
                CandidatePath = knownPath,
                Outcome = ImportSearchOutcome.Found,
                Architecture = importer.Arch,
                Note = "KnownDLLs is resolved before filesystem search locations",
            });
            return Result(ImportResolutionKind.ResolvedSystem, knownPath,
                "Windows KnownDLL", steps);
        }

        var importerDirectory = Path.GetDirectoryName(importer.Path);
        if (string.IsNullOrWhiteSpace(importerDirectory))
            return Result(ImportResolutionKind.Ambiguous, null,
                "Importer directory could not be determined", steps);

        if (Path.IsPathRooted(dllName) || ContainsDirectorySeparator(dllName))
        {
            var explicitPath = Path.IsPathRooted(dllName)
                ? NormalizePath(dllName)
                : NormalizePath(Path.Combine(importerDirectory, dllName));
            var exists = ExistsOrScanned(explicitPath, scannedFiles, environment);
            steps.Add(new ImportSearchStep
            {
                Location = ImportSearchLocationKind.ExplicitPath,
                CandidatePath = explicitPath,
                Outcome = exists ? ImportSearchOutcome.Found : ImportSearchOutcome.NotFound,
                Note = "Import contains an explicit or relative path",
            });
            if (!exists)
                return Result(ImportResolutionKind.Unresolved, null,
                    "Explicit import path does not exist", steps);

            if (TryGetScanned(explicitPath, scannedFiles, out var explicitPe)
                && !ArchitecturesMatch(importer.Arch, explicitPe.Arch))
                return Result(ImportResolutionKind.Ambiguous, explicitPath,
                    $"Explicit target architecture {explicitPe.Arch} does not match importer {importer.Arch}", steps);

            return Result(ImportResolutionKind.ResolvedLocal, explicitPath,
                "Explicit import path exists", steps);
        }

        var localPath = NormalizePath(Path.Combine(importerDirectory, basename));
        if (importer.Security.ForcesSystem32Only)
        {
            steps.Add(new ImportSearchStep
            {
                Location = ImportSearchLocationKind.LocalDirectory,
                CandidatePath = localPath,
                Outcome = ImportSearchOutcome.Skipped,
                Architecture = importer.Arch,
                Note = "DependentLoadFlags restricts dependency resolution to System32",
            });
        }
        else
        {
            var localExists = ExistsOrScanned(localPath, scannedFiles, environment);
            steps.Add(new ImportSearchStep
            {
                Location = ImportSearchLocationKind.LocalDirectory,
                CandidatePath = localPath,
                Outcome = localExists ? ImportSearchOutcome.Found : ImportSearchOutcome.NotFound,
                Architecture = importer.Arch,
                Note = "Importer-local static baseline",
            });
            if (localExists)
            {
                if (TryGetScanned(localPath, scannedFiles, out var localPe)
                    && !ArchitecturesMatch(importer.Arch, localPe.Arch))
                    return Result(ImportResolutionKind.Ambiguous, localPath,
                        $"Local target architecture {localPe.Arch} does not match importer {importer.Arch}", steps);

                return Result(ImportResolutionKind.ResolvedLocal, localPath,
                    "Import resolves to the exact local path", steps);
            }
        }

        var systemDirectory = SystemDirectoryFor(importer.Arch, environment);
        var systemPath = CombineSafe(systemDirectory, basename);
        var systemExists = !string.IsNullOrWhiteSpace(systemDirectory)
            && environment.FileExists(systemPath);
        steps.Add(new ImportSearchStep
        {
            Location = ImportSearchLocationKind.SystemDirectory,
            CandidatePath = systemPath,
            Outcome = systemExists ? ImportSearchOutcome.Found : ImportSearchOutcome.NotFound,
            Architecture = importer.Arch,
            Note = "Architecture-matching Windows system directory",
        });
        if (systemExists)
            return Result(ImportResolutionKind.ResolvedSystem, systemPath,
                "Import resolves from the architecture-matching system directory", steps);

        var alternateDirectory = AlternateSystemDirectoryFor(importer.Arch, environment);
        if (!string.IsNullOrWhiteSpace(alternateDirectory)
            && !PathsEqual(alternateDirectory, systemDirectory))
        {
            var alternatePath = CombineSafe(alternateDirectory, basename);
            if (environment.FileExists(alternatePath))
            {
                steps.Add(new ImportSearchStep
                {
                    Location = ImportSearchLocationKind.OtherArchitectureSystemDirectory,
                    CandidatePath = alternatePath,
                    Outcome = ImportSearchOutcome.Skipped,
                    Architecture = AlternateArchitectureFor(importer.Arch),
                    Note = "File exists only for a different architecture and cannot satisfy this import",
                });
            }
        }

        var otherMatches = FindOtherScannedCopies(basename, importerDirectory, scannedFiles);
        foreach (var other in otherMatches)
        {
            steps.Add(new ImportSearchStep
            {
                Location = ImportSearchLocationKind.OtherScannedDirectory,
                CandidatePath = other.Path,
                Outcome = ImportSearchOutcome.Unknown,
                Architecture = other.Arch,
                Note = "Same basename elsewhere in the scan; not proven reachable from this importer",
            });
        }

        if (importer.IsDll && otherMatches.Count > 0)
            return Result(ImportResolutionKind.Ambiguous, null,
                "DLL importer has matching copies in other application directories; host context is unknown", steps);

        return Result(ImportResolutionKind.Unresolved, null,
            "Not found in the evaluated local or architecture-matching system locations", steps);

        ImportResolution Result(
            ImportResolutionKind kind,
            string? resolvedPath,
            string reason,
            List<ImportSearchStep> resultSteps) => new()
        {
            ImporterPath = importer.Path,
            DllName = dllName,
            Kind = kind,
            ResolvedPath = resolvedPath,
            Reason = reason,
            Steps = resultSteps,
        };
    }

    public static bool PathsEqual(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right)) return false;
        return string.Equals(NormalizePath(left), NormalizePath(right), StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsApiSet(string name) =>
        name.StartsWith("api-ms-win-", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("ext-ms-win-", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsDirectorySeparator(string path) =>
        path.Contains(Path.DirectorySeparatorChar) || path.Contains(Path.AltDirectorySeparatorChar);

    private static string SystemDirectoryFor(string arch, ImportResolutionEnvironment environment) =>
        arch.Equals("x86", StringComparison.OrdinalIgnoreCase)
            ? environment.SysWow64Directory
            : environment.System32Directory;

    private static string AlternateSystemDirectoryFor(string arch, ImportResolutionEnvironment environment) =>
        arch.Equals("x86", StringComparison.OrdinalIgnoreCase)
            ? environment.System32Directory
            : environment.SysWow64Directory;

    private static string AlternateArchitectureFor(string arch) =>
        arch.Equals("x86", StringComparison.OrdinalIgnoreCase) ? "x64/arm64" : "x86";

    private static bool ArchitecturesMatch(string importerArch, string targetArch) =>
        importerArch.Equals(targetArch, StringComparison.OrdinalIgnoreCase)
        || importerArch.StartsWith("unknown_", StringComparison.OrdinalIgnoreCase)
        || targetArch.StartsWith("unknown_", StringComparison.OrdinalIgnoreCase);

    private static string CombineSafe(string directory, string filename) =>
        string.IsNullOrWhiteSpace(directory) ? filename : NormalizePath(Path.Combine(directory, filename));

    private static string NormalizePath(string path)
    {
        try { return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)); }
        catch { return Path.TrimEndingDirectorySeparator(path); }
    }

    private static bool ExistsOrScanned(
        string path,
        IReadOnlyDictionary<string, PeAnalysis>? scannedFiles,
        ImportResolutionEnvironment environment) =>
        TryGetScanned(path, scannedFiles, out _) || environment.FileExists(path);

    private static bool TryGetScanned(
        string path,
        IReadOnlyDictionary<string, PeAnalysis>? scannedFiles,
        out PeAnalysis pe)
    {
        pe = null!;
        if (scannedFiles == null) return false;
        if (scannedFiles.TryGetValue(path, out pe!)) return true;

        foreach (var item in scannedFiles.Values)
        {
            if (!PathsEqual(item.Path, path)) continue;
            pe = item;
            return true;
        }
        return false;
    }

    private static List<PeAnalysis> FindOtherScannedCopies(
        string basename,
        string importerDirectory,
        IReadOnlyDictionary<string, PeAnalysis>? scannedFiles)
    {
        if (scannedFiles == null) return [];
        return scannedFiles.Values
            .Where(pe => pe.IsDll
                && pe.Filename.Equals(basename, StringComparison.OrdinalIgnoreCase)
                && !PathsEqual(Path.GetDirectoryName(pe.Path), importerDirectory))
            .DistinctBy(pe => NormalizePath(pe.Path), StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
