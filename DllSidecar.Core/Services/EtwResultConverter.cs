using DllSidecar.Core.Helpers;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

public static class EtwResultConverter
{
    public static List<PhantomCandidate> ToPhantomCandidates(EtwTraceResult result)
    {
        var phantoms = new List<PhantomCandidate>();

        // The root target is the binary the OPERATOR launched / attached / watched
        // from RuntimeTracePage. Even when a child process (agent.exe, AcroCEF.exe,
        // …) physically performs the LoadLibrary, the operator delivers and victim
        // runs the root — that's what should land in Craft's Host EXE field.
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

            // ETW's ProcessImagePath is frequently just the basename ("Battle.net.exe")
            // because TraceEvent can't always normalise the kernel device path, and
            // Process.GetProcessById().MainModule fails for x86 children of an x64
            // tracer. Fix it up by checking if the basename resolves to a real file
            // in the phantom's directory — that's where 99% of sideload importers
            // live. This single change feeds the full path forward to CraftStage's
            // Host EXE field and AttackPath's Analyze handoff in one shot.
            var importers = processImages
                .Select(proc => new ImporterRef
                {
                    ExePath = ResolveImporterFullPath(proc, dir),
                    ExeFilename = Path.GetFileName(proc),
                })
                .ToList();

            // Promote the root target to Importers[0] so every consumer that reads
            // `Importers.FirstOrDefault()` (CraftStage.Host, ReportStage.ImporterExe,
            // AttackPath.OpenFocusInAnalyze) gets the operator-facing binary — not
            // the grandchild that happened to do the actual file probe.
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

            // Sandbox classification for the primary importer (Importers[0] = root
            // target after the prepend above). Combine static heuristic (filename +
            // PE ProductName) with the dynamic token signal captured during ETW —
            // dynamic wins on disagreement. CraftStage / GeneratePage filter the
            // Payload picker on this field.
            var primary = phantom.Importers.FirstOrDefault();
            if (primary != null)
            {
                var staticKind = SandboxClassifier.Classify(primary.ExePath);
                var rootProc = result.RootProcess;
                var dynamicKind = rootProc != null
                    ? SandboxClassifier.FromTokenInfo(rootProc.IsAppContainer, rootProc.IntegrityLevel)
                    : SandboxKind.None;
                phantom.SandboxKind = SandboxClassifier.Combine(staticKind, dynamicKind);
            }

            phantoms.Add(phantom);
        }

        Log.Info("etw.convert",
            $"Converted {result.ByDll.Count} ETW DLLs into {phantoms.Count} phantom candidates " +
            $"(deduped by DllName+Directory)");

        return phantoms;
    }

    /// <summary>
    /// Turn an importer-process string into a full disk path when ETW only handed us
    /// a basename. Heuristic ladder: rooted-and-exists → trust it · basename + phantom
    /// directory → use if file exists · running process with that name → MainModule.FileName
    /// via Win32 QueryFullProcessImageName (works across x86↔x64). Last resort: return
    /// the original string so downstream code at least has *something* to show.
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

        // Best-effort live-process lookup. ProcessImagePath uses
        // QueryFullProcessImageName which works cross-arch where MainModule fails.
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
        return pr;
    }

    /// <summary>
    /// Deduplicated summary: unique (ProcessImage, DllName, Directory) triples.
    /// Useful for UI display before promotion to full phantom candidates.
    /// LoadCount / ProbeCount let the UI surface whether each (proc,dll,dir) was
    /// the loader actually attempting an open or just app-internal probes.
    /// </summary>
    public static List<(string ProcessImage, string DllName, string Directory, int EventCount, bool DirWritable, int LoadCount, int ProbeCount)>
        DeduplicatedSummary(EtwTraceResult result) => DeduplicatedSummary(result.Events);

    public static List<(string ProcessImage, string DllName, string Directory, int EventCount, bool DirWritable, int LoadCount, int ProbeCount)>
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
                    DirWritable: IsLikelyUserWritable(first.Directory),
                    LoadCount: g.Count(e => e.Access == AccessClass.LoaderLike),
                    ProbeCount: g.Count(e => e.Access == AccessClass.MetadataProbe));
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
