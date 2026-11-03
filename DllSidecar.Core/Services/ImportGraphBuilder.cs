using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Reverse-dependency graph with path-aware resolution. Basename matches are only
/// potential edges until they resolve to the candidate's exact local path.
/// </summary>
public class ImportGraphBuilder
{
    public Dictionary<string, List<ImporterEdge>> DllToImporters { get; } =
        new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, PeAnalysis> PathToAnalysis { get; } =
        new(StringComparer.OrdinalIgnoreCase);

    public void Add(PeAnalysis pe)
    {
        PathToAnalysis[pe.Path] = pe;
        foreach (var imp in pe.Imports)
        {
            if (!DllToImporters.TryGetValue(imp.DllName, out var list))
            {
                list = [];
                DllToImporters[imp.DllName] = list;
            }
            list.Add(new ImporterEdge
            {
                ImporterPath = pe.Path,
                ImportedDllName = imp.DllName,
                IsDelayLoad = imp.IsDelayLoad,
            });
        }
    }

    public IReadOnlyList<ImporterEdge> GetImportersOf(PeAnalysis candidate)
    {
        if (!DllToImporters.TryGetValue(candidate.Filename, out var potential))
            return Array.Empty<ImporterEdge>();

        var resolved = new List<ImporterEdge>();
        foreach (var edge in potential)
        {
            if (!PathToAnalysis.TryGetValue(edge.ImporterPath, out var importer)) continue;
            var import = importer.Imports.FirstOrDefault(i =>
                i.DllName.Equals(edge.ImportedDllName, StringComparison.OrdinalIgnoreCase) &&
                i.IsDelayLoad == edge.IsDelayLoad);
            if (import == null) continue;

            var resolution = ImportResolutionService.Resolve(importer, import, PathToAnalysis);
            if (!resolution.IsExactLocal
                || !ImportResolutionService.PathsEqual(resolution.ResolvedPath, candidate.Path))
                continue;

            resolved.Add(new ImporterEdge
            {
                ImporterPath = edge.ImporterPath,
                ImportedDllName = edge.ImportedDllName,
                IsDelayLoad = edge.IsDelayLoad,
                Resolution = resolution,
            });
        }
        return resolved;
    }

    public class ImporterEdge
    {
        public required string ImporterPath { get; set; }
        public required string ImportedDllName { get; set; }
        public bool IsDelayLoad { get; set; }
        public ImportResolution? Resolution { get; set; }
    }
}
