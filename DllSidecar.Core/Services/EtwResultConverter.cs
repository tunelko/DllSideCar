using DllSidecar.Core.Helpers;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

public static class EtwResultConverter
{
    public static List<PhantomCandidate> ToPhantomCandidates(EtwTraceResult result)
    {
        var phantoms = new List<PhantomCandidate>();

        // The root target is the operator-launched binary; it goes to Craft's Host EXE.
        var rootPath = result.RootProcess?.ImagePath;
        var rootName = result.RootProcess?.Name;

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

            // Resolve basenames to full paths via the phantom directory or live processes.
            var importers = processImages
                .Select(proc => new ImporterRef
                {
                    ExePath = ResolveImporterFullPath(proc, dir),
                    ExeFilename = Path.GetFileName(proc),
                })
                .ToList();

            // Promote the root target to Importers[0] for downstream consumers.
            if (!string.IsNullOrEmpty(rootPath))
            {
                var rootBasename = Path.GetFileName(rootPath);
                var existingIdx = importers.FindIndex(i =>
                    string.Equals(i.ExeFilename, rootBasename, StringComparison.OrdinalIgnoreCase) ||
                    (rootName != null && string.Equals(i.ExeFilename, rootName, StringComparison.OrdinalIgnoreCase)));
                if (existingIdx > 0)
                {
                    var rootImp = importers[existingIdx];
                    importers.RemoveAt(existingIdx);
                    importers.Insert(0, rootImp);
                }
                else if (existingIdx < 0)
                {
                    importers.Insert(0, new ImporterRef
                    {
                        ExePath = ResolveImporterFullPath(rootPath, dir),
                        ExeFilename = rootBasename,
                    });
                }
                // existingIdx == 0 → already at the front, nothing to do.
            }

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
                    LoaderLikeEventCount    = g.Count(e => e.Access == AccessClass.LoaderLike),
                    MetadataProbeEventCount = g.Count(e => e.Access == AccessClass.MetadataProbe),
                },
            };

            phantom.Score = ExploitabilityScorer.ScorePhantom(phantom);
            ExploitabilityScorer.ApplyDynamicEvidence(phantom.Score, phantom.Privesc, phantom.Evidence);

            // Sandbox classification across every importer + traced process; strongest non-None wins.
            SandboxKind staticKind = SandboxKind.None;
            foreach (var imp in phantom.Importers)
            {
                var k = SandboxClassifier.Classify(imp.ExePath);
                staticKind = SandboxClassifier.Combine(staticKind, k);
                if (staticKind != SandboxKind.None) break;
            }

            SandboxKind dynamicKind = SandboxKind.None;
            foreach (var proc in result.ProcessTree)
            {
                var k = SandboxClassifier.FromTokenInfo(proc.IsAppContainer, proc.IntegrityLevel);
                if (k == SandboxKind.None) continue;
                // First non-None wins.
                dynamicKind = k;
                break;
            }

            phantom.SandboxKind = SandboxClassifier.Combine(staticKind, dynamicKind);

            phantoms.Add(phantom);
        }

        Log.Info("etw.convert",
            $"Converted {result.ByDll.Count} ETW DLLs into {phantoms.Count} phantom candidates " +
            $"(deduped by DllName+Directory)");

        return phantoms;
    }

    /// <summary>
    /// Resolve a basename to a full disk path via phantom directory or live process lookup (QueryFullProcessImageName).
    /// </summary>
    private static string ResolveImporterFullPath(string raw, string phantomDir)
    {
        if (string.IsNullOrWhiteSpace(raw)) return raw;
        if (Path.IsPathRooted(raw) && File.Exists(raw)) return raw;

        var basename = Path.GetFileName(raw);
        if (string.IsNullOrEmpty(basename)) return raw;

        if (!string.IsNullOrEmpty(phantomDir))
        {
            var candidate = Path.Combine(phantomDir, basename);
            if (File.Exists(candidate)) return candidate;
        }

        // Best-effort live-process lookup via QueryFullProcessImageName.
        var noExt = Path.GetFileNameWithoutExtension(basename);
        var live = ProcessImagePath.TryGetByName(noExt);
        if (!string.IsNullOrEmpty(live) && File.Exists(live)) return live;

        return raw;
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
                Access = ev.Access, // forward ETW classification into the unified ProcmonEvent view
            });
        }

        pr.ByDll.AddRange(result.ByDll);

        // IL map from ETW process tree gates the heuristic against same-name launchers
        // (Battle.net etc.) that spawn children without ever elevating.
        var pidIl = result.ProcessTree
            .GroupBy(p => p.Pid)
            .ToDictionary(g => g.Key, g => g.First().IntegrityLevel);
        pr.Transitions = ElevationTransitionDetector.RunFullPipeline(pr.Events, pr.ByDll, pidIl);

        return pr;
    }

    /// <summary>
    /// Deduplicated summary: unique (ProcessImage, DllName, Directory) triples with load/probe counts.
    /// </summary>
    public static List<(string ProcessImage, string DllName, string Directory, int EventCount, bool DirWritable, int LoadCount, int ProbeCount)>
        DeduplicatedSummary(EtwTraceResult result) => DeduplicatedSummary(result.Events);

    public static List<(string ProcessImage, string DllName, string Directory, int EventCount, bool DirWritable, int LoadCount, int ProbeCount)>
        DeduplicatedSummary(IEnumerable<EtwTraceEvent> events)
    {
        return events
            .GroupBy(e => (
                Proc: (e.ProcessImagePath ?? e.ProcessName).ToLowerInvariant(),
                Dll: NormalizeDllName(e.DllName),
                Dir: e.Directory.ToLowerInvariant()))
            .Select(g =>
            {
                var first = g.First();
                return (
                    ProcessImage: first.ProcessImagePath ?? first.ProcessName,
                    DllName: NormalizeDllNameDisplay(first.DllName),
                    Directory: first.Directory,
                    EventCount: g.Count(),
                    DirWritable: IsLikelyUserWritable(first.Directory),
                    LoadCount: g.Count(e => e.Access == AccessClass.LoaderLike),
                    ProbeCount: g.Count(e => e.Access == AccessClass.MetadataProbe));
            })
            .OrderByDescending(x => x.DirWritable)
            .ThenByDescending(x => x.EventCount)
            .ToList();
    }

    // Windows loader probes both "foo.dll" and "foo.dll.DLL" (double-extension fallback).
    private static string NormalizeDllName(string dllName)
    {
        var s = dllName.ToLowerInvariant();
        if (s.EndsWith(".dll.dll")) s = s[..^4];
        return s;
    }
    private static string NormalizeDllNameDisplay(string dllName)
    {
        if (dllName.EndsWith(".dll.DLL", StringComparison.OrdinalIgnoreCase)) return dllName[..^4];
        return dllName;
    }

    /// <summary>
    /// Coarse path-prefix guess; not an ACL probe. Callers needing a verdict must use <see cref="DirAclCache.Get"/>.
    /// </summary>
    private static bool IsLikelyUserWritable(string dir)
    {
        if (string.IsNullOrEmpty(dir)) return false;
        var lower = dir.ToLowerInvariant();
        if (lower.StartsWith(@"c:\windows")) return false;
        if (lower.StartsWith(@"c:\program files")) return false;
        return true;
    }
}
