using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Builds a reverse-dependency graph: DLL name (lowercase) → list of PEs in the scanned
/// directory that import that DLL. Used to filter sideload candidates to only those
/// actually loaded by some binary in the install dir.
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

    public IReadOnlyList<ImporterEdge> GetImportersOf(string dllName) =>
        DllToImporters.TryGetValue(dllName, out var list) ? list : Array.Empty<ImporterEdge>();

    public class ImporterEdge
    {
        public required string ImporterPath { get; set; }
        public required string ImportedDllName { get; set; }
        public bool IsDelayLoad { get; set; }
    }
}
