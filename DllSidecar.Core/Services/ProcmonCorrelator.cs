using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Cross-references static scan results with a ProcMon CSV, attaching DynamicEvidence on name matches.
/// </summary>
public static class ProcmonCorrelator
{
    public class CorrelationReport
    {
        public int ExistingMatched { get; set; }
        public int PhantomMatched { get; set; }
        public int TotalEvents { get; set; }
    }

    public static CorrelationReport Correlate(ScanResults scan, ProcmonParser.ParseResult procmon)
    {
        if (procmon.Source == EvidenceSource.RuntimeTrace)
            return CorrelateRuntime(scan, procmon);
        var report = new CorrelationReport { TotalEvents = procmon.FilteredRows };

        // Index by DLL name for O(1) lookup (case-insensitive)
        var byName = procmon.ByDll.ToDictionary(a => a.DllName, a => a, StringComparer.OrdinalIgnoreCase);

        foreach (var c in scan.Existing)
        {
            if (byName.TryGetValue(c.Dll.Filename, out var agg))
            {
                c.Evidence = BuildEvidence(agg, matchedDir: agg.SearchedDirs.Contains(
                    Path.GetDirectoryName(c.Dll.Path) ?? "", StringComparer.OrdinalIgnoreCase));
                ExploitabilityScorer.ApplyDynamicEvidence(c.Score, c.Privesc, c.Evidence);
                report.ExistingMatched++;
            }
        }

        foreach (var p in scan.Phantoms)
        {
            if (byName.TryGetValue(p.DllName, out var agg))
            {
                p.Evidence = BuildEvidence(agg, matchedDir: agg.SearchedDirs.Contains(
                    p.DirectoryPath, StringComparer.OrdinalIgnoreCase));
                ExploitabilityScorer.ApplyDynamicEvidence(p.Score, p.Privesc, p.Evidence);
                report.PhantomMatched++;
            }
        }

        Log.Info("procmon.correlate",
            $"{report.ExistingMatched}/{scan.Existing.Count} existing + {report.PhantomMatched}/{scan.Phantoms.Count} phantom candidates dynamically verified");

        return report;
    }

    private static CorrelationReport CorrelateRuntime(ScanResults scan, ProcmonParser.ParseResult trace)
    {
        var report = new CorrelationReport { TotalEvents = trace.FilteredRows };
        foreach (var c in scan.Existing)
        {
            var ev = RuntimeEvidence(c.Dll.Filename, Path.GetDirectoryName(c.Dll.Path) ?? "", c.Importers, trace);
            if (ev == null) continue;
            c.Evidence = ev;
            ExploitabilityScorer.ApplyDynamicEvidence(c.Score, c.Privesc, ev);
            report.ExistingMatched++;
        }
        foreach (var p in scan.Phantoms)
        {
            var ev = RuntimeEvidence(p.DllName, p.DirectoryPath, p.Importers, trace);
            if (ev == null) continue;
            p.Evidence = ev;
            ExploitabilityScorer.ApplyDynamicEvidence(p.Score, p.Privesc, ev);
            report.PhantomMatched++;
        }
        return report;
    }

    private static DynamicEvidence? RuntimeEvidence(string dll, string dir, List<ImporterRef> importers,
        ProcmonParser.ParseResult trace)
    {
        var events = trace.Events.Where(e => e.DllName.Equals(dll, StringComparison.OrdinalIgnoreCase)
            && (e.Operation == "Load Image" || e.Result is "NAME NOT FOUND" or "PATH NOT FOUND")
            && (importers.Count == 0 || importers.Any(i =>
                !string.IsNullOrEmpty(e.ProcessImagePath) && Path.IsPathRooted(i.ExePath)
                    ? ImportResolutionService.PathsEqual(i.ExePath, e.ProcessImagePath)
                    : i.ExeFilename.Equals(e.ProcessName, StringComparison.OrdinalIgnoreCase)))).ToList();
        if (events.Count == 0) return null;
        var exact = events.Where(e => ImportResolutionService.PathsEqual(e.SearchDir, dir)).ToList();
        // Evidence from a different directory must not strengthen this directory's match.
        var selected = exact.Count > 0 ? exact : events;
        return new DynamicEvidence
        {
            DllName = dll, EventCount = selected.Count, Source = EvidenceSource.RuntimeTrace,
            MatchedByName = true, MatchedByDirectory = exact.Count > 0,
            Processes = selected.Select(e => e.ProcessName).Distinct().ToList(),
            SearchedDirs = selected.Select(e => e.SearchDir).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            LoaderLikeEventCount = selected.Count(e => e.Access == AccessClass.LoaderLike),
            MetadataProbeEventCount = selected.Count(e => e.Access == AccessClass.MetadataProbe),
            ImageLoadEventCount = selected.Count(e => e.Operation == "Load Image"),
            VerifiedMissEventCount = selected.Count(e => e.Result is "NAME NOT FOUND" or "PATH NOT FOUND"),
        };
    }

    private static DynamicEvidence BuildEvidence(ProcmonAggregation agg, bool matchedDir) => new()
    {
        DllName = agg.DllName,
        EventCount = agg.EventCount,
        Processes = agg.Processes.ToList(),
        SearchedDirs = agg.SearchedDirs.ToList(),
        MatchedByName = true,
        MatchedByDirectory = matchedDir,
        LoaderLikeEventCount = agg.LoaderLikeCount,
        MetadataProbeEventCount = agg.MetadataProbeCount,
    };

}
