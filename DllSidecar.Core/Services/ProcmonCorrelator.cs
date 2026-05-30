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
