using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

public static class EtwResultConverter
{
    public static List<PhantomCandidate> ToPhantomCandidates(EtwTraceResult result)
    {
        var phantoms = new List<PhantomCandidate>();

        // Deduplicate by (DllName, Directory) — collapse multiple events into one candidate
        var groups = result.Events
            .GroupBy(e => (Dll: e.DllName.ToLowerInvariant(), Dir: e.Directory.ToLowerInvariant()));

        foreach (var g in groups)
        {
            var first = g.First();
            var dir = first.Directory;
            var dirPerms = DirectoryAclChecker.Check(dir);

            // Collect distinct process images that attempted this load
            var processImages = g
                .Select(e => e.ProcessImagePath ?? e.ProcessName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var importers = processImages
                .Select(proc => new ImporterRef
                {
                    ExePath = proc,
                    ExeFilename = Path.GetFileName(proc),
                })
                .ToList();

            var phantom = new PhantomCandidate
            {
                DllName = first.DllName,
                DirectoryPath = dir,
                Dir = dirPerms,
                Importers = importers,
                Evidence = new DynamicEvidence
                {
                    DllName = first.DllName,
                    EventCount = g.Count(),
                    Processes = processImages,
                    SearchedDirs = g.Select(e => e.Directory).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                    MatchedByName = true,
                    MatchedByDirectory = true,
                    MissInWritableDir = dirPerms.IsUserWritable,
                    Source = EvidenceSource.RuntimeTrace,
                },
            };

            phantom.Score = ExploitabilityScorer.ScorePhantom(phantom);
            ExploitabilityScorer.ApplyDynamicEvidence(phantom.Score, phantom.Privesc, phantom.Evidence);

            phantoms.Add(phantom);
        }

        Log.Info("etw.convert",
            $"Converted {result.ByDll.Count} ETW DLLs into {phantoms.Count} phantom candidates " +
            $"(deduped by DllName+Directory)");

        return phantoms;
    }

    public static ProcmonParser.ParseResult ToProcmonResult(EtwTraceResult result)
    {
        var pr = new ProcmonParser.ParseResult
        {
            TotalRows = result.TotalEventsReceived,
            FilteredRows = result.FilteredEvents,
        };

        foreach (var ev in result.Events)
        {
            pr.Events.Add(new ProcmonEvent
            {
                ProcessName = ev.ProcessName,
                Operation = "CreateFile",
                Result = "NAME NOT FOUND",
                Path = ev.FilePath,
                Pid = ev.ProcessId,
                Timestamp = ev.Timestamp,
            });
        }

        pr.ByDll.AddRange(result.ByDll);
        return pr;
    }

    /// <summary>
    /// Deduplicated summary: unique (ProcessImage, DllName, Directory) triples.
    /// Useful for UI display before promotion to full phantom candidates.
    /// </summary>
    public static List<(string ProcessImage, string DllName, string Directory, int EventCount, bool DirWritable)>
        DeduplicatedSummary(EtwTraceResult result) => DeduplicatedSummary(result.Events);

    public static List<(string ProcessImage, string DllName, string Directory, int EventCount, bool DirWritable)>
        DeduplicatedSummary(IEnumerable<EtwTraceEvent> events)
    {
        return events
            .GroupBy(e => (
                Proc: (e.ProcessImagePath ?? e.ProcessName).ToLowerInvariant(),
                Dll: e.DllName.ToLowerInvariant(),
                Dir: e.Directory.ToLowerInvariant()))
            .Select(g =>
            {
                var first = g.First();
                return (
                    ProcessImage: first.ProcessImagePath ?? first.ProcessName,
                    DllName: first.DllName,
                    Directory: first.Directory,
                    EventCount: g.Count(),
                    DirWritable: IsLikelyUserWritable(first.Directory));
            })
            .OrderByDescending(x => x.DirWritable)
            .ThenByDescending(x => x.EventCount)
            .ToList();
    }

    private static bool IsLikelyUserWritable(string dir)
    {
        if (string.IsNullOrEmpty(dir)) return false;
        var lower = dir.ToLowerInvariant();
        if (lower.StartsWith(@"c:\windows")) return false;
        if (lower.StartsWith(@"c:\program files")) return false;
        return true;
    }
}
