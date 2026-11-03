using DllSidecar.Core.Helpers;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>Finds imports unresolved by the shared static resolution baseline.</summary>
public static class PhantomDetector
{
    public class PhantomHit
    {
        public required string DllName { get; set; }
        public required string ImporterPath { get; set; }
        public required string ImporterDirectory { get; set; }
        public bool IsDelayLoad { get; set; }
        public List<string> SearchedLocations { get; set; } = [];
        public required ImportResolution Resolution { get; set; }
    }

    public static List<PhantomHit> Find(
        PeAnalysis importer,
        IReadOnlyDictionary<string, PeAnalysis>? scannedFiles = null) =>
        Find(importer, scannedFiles, ImportResolutionEnvironment.Current);

    internal static List<PhantomHit> Find(
        PeAnalysis importer,
        IReadOnlyDictionary<string, PeAnalysis>? scannedFiles,
        ImportResolutionEnvironment environment)
    {
        var hits = new List<PhantomHit>();
        var importerDir = Path.GetDirectoryName(importer.Path) ?? "";
        if (string.IsNullOrEmpty(importerDir)) return hits;

        foreach (var imp in importer.Imports)
        {
            var name = imp.DllName;
            if (string.IsNullOrEmpty(name)) continue;

            var resolution = ImportResolutionService.Resolve(importer, imp, scannedFiles, environment);
            var hasPlantableLocalSlot = resolution.Steps.Any(step =>
                step.Location == ImportSearchLocationKind.LocalDirectory
                && step.Outcome == ImportSearchOutcome.NotFound);
            var isSystemFallback = resolution.Kind == ImportResolutionKind.ResolvedSystem
                && hasPlantableLocalSlot;
            if (resolution.Kind != ImportResolutionKind.Unresolved && !isSystemFallback) continue;

            var searched = resolution.Steps
                .Where(step => step.Outcome == ImportSearchOutcome.NotFound)
                .Select(step => step.CandidatePath)
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            hits.Add(new PhantomHit
            {
                DllName = name,
                ImporterPath = importer.Path,
                ImporterDirectory = importerDir,
                IsDelayLoad = imp.IsDelayLoad,
                SearchedLocations = searched,
                Resolution = resolution,
            });
        }

        return hits;
    }
}
