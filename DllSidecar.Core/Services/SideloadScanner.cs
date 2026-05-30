using System.Collections.Concurrent;
using DllSidecar.Core.Helpers;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;
using DllSidecar.Core.Services.Privesc;

namespace DllSidecar.Core.Services;

public class ScanProgressInfo
{
    public int Scanned { get; set; }
    public int Total { get; set; }
    public int Candidates { get; set; }
    public string CurrentFile { get; set; } = "";
    public string Phase { get; set; } = "";   // "enumerate" / "analyze" / "crossref" / "score"
}

public class ScanOptions
{
    public bool IncludeDelayLoad { get; set; } = true;
    public bool RequireImporter { get; set; } = true;       // exclude DLLs nobody imports
    public int MinScore { get; set; } = 0;                  // filter by derived Total (back-compat)
    public int MinExploitability { get; set; } = 0;         // per-axis min — Sprint 1
    public int MinImpact { get; set; } = 0;                 // per-axis min — Sprint 1
    public int MinConfidence { get; set; } = 0;             // per-axis min — Sprint 1
    public bool OnlyUserWritable { get; set; } = false;
    public bool OnlySignedExe { get; set; } = false;
    public bool IncludePhantoms { get; set; } = true;        // Fase 2: detect phantom slots
    public bool AnalyzePrivesc { get; set; } = true;         // Fase 6: enrich with privesc vectors
    public int MaxParallelism { get; set; } = Environment.ProcessorCount;
}

public class ScanResults
{
    public List<SideloadCandidate> Existing { get; set; } = [];
    public List<PhantomCandidate> Phantoms { get; set; } = [];
    public int ExistingCount => Existing.Count;
    public int PhantomCount => Phantoms.Count;
}

public class SideloadScanner
{
    /// <summary>
    /// Full static scan. Runs in parallel. Safe to call from a background Task.
    /// Returns existing-DLL candidates and phantom drop-points.
    /// </summary>
    public ScanResults Scan(
        string directory,
        ScanOptions options,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken ct)
    {
        if (!Directory.Exists(directory)) return new ScanResults();

        // Phase 1: enumerate PE files
        progress?.Report(new ScanProgressInfo { Phase = "enumerate", CurrentFile = "Enumerating files..." });
        var files = EnumeratePeFiles(directory, ct);

        // Phase 2: analyze in parallel
        var analyses = new ConcurrentBag<PeAnalysis>();
        int scanned = 0;
        int skipped = 0;
        var parallelOpts = new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Max(1, options.MaxParallelism),
            CancellationToken = ct,
        };
        try
        {
            Parallel.ForEach(files, parallelOpts, file =>
            {
                try
                {
                    var a = PeAnalyzer.Analyze(file);
                    analyses.Add(a);
                }
                catch (Exception ex)
                {
                    // Skip one bad file rather than fail the scan.
                    Interlocked.Increment(ref skipped);
                    Log.Debug("scan.pe", $"Skipped {file}: {ex.GetType().Name}: {ex.Message}");
                }

                var done = Interlocked.Increment(ref scanned);
                if (done % 4 == 0 || done == files.Count)
                {
                    progress?.Report(new ScanProgressInfo
                    {
                        Phase = "analyze",
                        Scanned = done,
                        Total = files.Count,
                        CurrentFile = TrimPath(file),
                    });
                }
            });
        }
        catch (OperationCanceledException) { throw; /* propagate cancellation to caller */ }

        if (skipped > 0)
            Log.Info("scan.pe", $"Parsed {analyses.Count}/{files.Count} PE files ({skipped} skipped due to errors)");

        // Phase 3: build reverse-import graph
        progress?.Report(new ScanProgressInfo
        {
            Phase = "crossref",
            Scanned = files.Count,
            Total = files.Count,
            CurrentFile = "Building import graph...",
        });
        var graph = new ImportGraphBuilder();
        foreach (var a in analyses) graph.Add(a);

        // Phase 4: directory permissions (one call per unique dir)
        var dirPerms = new Dictionary<string, DirectoryPermissions>(StringComparer.OrdinalIgnoreCase);
        foreach (var a in analyses)
        {
            var dir = Path.GetDirectoryName(a.Path) ?? directory;
            if (!dirPerms.ContainsKey(dir))
                dirPerms[dir] = DirectoryAclChecker.Check(dir);
            ct.ThrowIfCancellationRequested();
        }

        // Phase 5a: prepare privesc detector pipeline (needs full PE list before scoring)
        PrivescAnalyzer? privesc = null;
        if (options.AnalyzePrivesc)
        {
            progress?.Report(new ScanProgressInfo
            {
                Phase = "privesc.prep",
                Scanned = files.Count,
                Total = files.Count,
                CurrentFile = "Preparing privesc detectors (services, tasks, manifests)...",
            });
            privesc = new PrivescAnalyzer();
            try { privesc.Prepare(directory, analyses, ct); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                Log.Error("privesc", "Prepare failed — continuing scan without privesc analysis", ex);
                privesc = null;
            }
        }

        // Phase 5b: assemble candidates and score
        progress?.Report(new ScanProgressInfo
        {
            Phase = "score",
            Scanned = files.Count,
            Total = files.Count,
            CurrentFile = "Scoring candidates...",
        });
        var candidates = new ConcurrentBag<SideloadCandidate>();
        var dllAnalyses = analyses.Where(a => a.IsDll && !KnownDlls.IsKnown(a.Filename)).ToList();

        Parallel.ForEach(dllAnalyses, parallelOpts, dll =>
        {
            try
            {
                var importers = graph.GetImportersOf(dll.Filename)
                    .Where(e => !string.Equals(e.ImporterPath, dll.Path, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (options.RequireImporter && importers.Count == 0) return;
                if (!options.IncludeDelayLoad && importers.All(i => i.IsDelayLoad)) return;

                var candidate = new SideloadCandidate
                {
                    Dll = dll,
                    DllSigning = AuthenticodeVerifier.Verify(dll.Path),
                    Dir = dirPerms.TryGetValue(Path.GetDirectoryName(dll.Path) ?? "", out var p)
                        ? p
                        : new DirectoryPermissions { Path = Path.GetDirectoryName(dll.Path) ?? "" },
                };

                foreach (var edge in importers)
                {
                    var imp = graph.PathToAnalysis[edge.ImporterPath];
                    candidate.Importers.Add(new ImporterRef
                    {
                        ExePath = imp.Path,
                        ExeFilename = imp.Filename,
                        Signing = AuthenticodeVerifier.Verify(imp.Path),
                        Subsystem = imp.Subsystem,
                        ForcesSystem32Only = imp.Security.ForcesSystem32Only,
                        IsDelayLoad = edge.IsDelayLoad,
                    });
                }

                // Privesc annotation: analyze both the DLL itself AND all importers;
                // the importer vector is what drives elevation (e.g. service loads our DLL).
                if (privesc != null)
                {
                    candidate.Privesc = BuildCombinedPrivescContext(privesc, dll, candidate.Importers, graph, ct);
                }

                candidate.Score = ExploitabilityScorer.Score(candidate);

                // Static sandbox classification across EVERY importer. Scanning the
                // first one alone misses the common case where the user-launched
                // root (Acrobat.exe) is High IL but a grandchild (AcroCEF.exe) is
                // the actual sandboxed loader. Trace-time dynamic signal isn't
                // available here (cold static scan); heuristic-only, but enough
                // to flag AcroCEF / RdrCEF / msedgewebview2 chains in the Scan grid.
                candidate.SandboxKind = SandboxKind.None;
                foreach (var imp in candidate.Importers)
                {
                    var k = SandboxClassifier.Classify(imp.ExePath);
                    if (k != SandboxKind.None) { candidate.SandboxKind = k; break; }
                }

                // Apply filters — per-axis first, then derived Total (back-compat)
                if (candidate.Score.Exploitability < options.MinExploitability) return;
                if (candidate.Score.Impact < options.MinImpact) return;
                if (candidate.Score.Confidence < options.MinConfidence) return;
                if (candidate.Score.Total < options.MinScore) return;
                if (options.OnlyUserWritable && !candidate.Dir.IsUserWritable) return;
                if (options.OnlySignedExe && !candidate.AnyImporterSigned) return;

                candidates.Add(candidate);
            }
            catch (Exception ex)
            {
                Log.Warn("scan.score", $"Failed to build candidate for {dll.Path}", ex);
            }

            progress?.Report(new ScanProgressInfo
            {
                Phase = "score",
                Candidates = candidates.Count,
                Scanned = files.Count,
                Total = files.Count,
            });
        });

        // Phase 6: phantom detection (Fase 2)
        var phantoms = new List<PhantomCandidate>();
        if (options.IncludePhantoms)
        {
            progress?.Report(new ScanProgressInfo
            {
                Phase = "phantom",
                Scanned = files.Count,
                Total = files.Count,
                CurrentFile = "Detecting phantom imports...",
            });

            // Collect all phantom hits, group by (directory, dll name)
            var hitsByKey = new Dictionary<string, List<PhantomDetector.PhantomHit>>(StringComparer.OrdinalIgnoreCase);
            foreach (var pe in analyses)
            {
                ct.ThrowIfCancellationRequested();
                var hits = PhantomDetector.Find(pe);
                foreach (var h in hits)
                {
                    var key = $"{h.ImporterDirectory}|{h.DllName.ToLowerInvariant()}";
                    if (!hitsByKey.TryGetValue(key, out var list))
                    {
                        list = [];
                        hitsByKey[key] = list;
                    }
                    list.Add(h);
                }
            }

            foreach (var (key, list) in hitsByKey)
            {
                ct.ThrowIfCancellationRequested();
                var first = list[0];
                var ph = new PhantomCandidate
                {
                    DllName = first.DllName,
                    DirectoryPath = first.ImporterDirectory,
                    Dir = dirPerms.TryGetValue(first.ImporterDirectory, out var p)
                        ? p
                        : DirectoryAclChecker.Check(first.ImporterDirectory),
                    SearchedLocations = first.SearchedLocations,
                };
                foreach (var h in list)
                {
                    var impPe = graph.PathToAnalysis[h.ImporterPath];
                    ph.Importers.Add(new ImporterRef
                    {
                        ExePath = impPe.Path,
                        ExeFilename = impPe.Filename,
                        Signing = AuthenticodeVerifier.Verify(impPe.Path),
                        Subsystem = impPe.Subsystem,
                        ForcesSystem32Only = impPe.Security.ForcesSystem32Only,
                        IsDelayLoad = h.IsDelayLoad,
                    });
                }
                if (privesc != null)
                {
                    ph.Privesc = BuildCombinedPrivescContext(privesc, pe: null, ph.Importers, graph, ct);
                }

                ph.Score = ExploitabilityScorer.ScorePhantom(ph);

                // Static sandbox classification across EVERY importer (same scan
                // strategy as the Existing-candidate branch above). Dynamic signal
                // arrives later if this phantom is also surfaced via runtime trace
                // + Promote, and the converter then re-evaluates including tokens.
                ph.SandboxKind = SandboxKind.None;
                foreach (var imp in ph.Importers)
                {
                    var k = SandboxClassifier.Classify(imp.ExePath);
                    if (k != SandboxKind.None) { ph.SandboxKind = k; break; }
                }

                if (ph.Score.Exploitability < options.MinExploitability) continue;
                if (ph.Score.Impact < options.MinImpact) continue;
                if (ph.Score.Confidence < options.MinConfidence) continue;
                if (ph.Score.Total < options.MinScore) continue;
                if (options.OnlyUserWritable && !ph.Dir.IsUserWritable) continue;
                if (options.OnlySignedExe && !ph.AnyImporterSigned) continue;

                phantoms.Add(ph);
            }
        }

        var results = new ScanResults
        {
            Existing = candidates
                .OrderByDescending(c => c.Score.Total)
                .ThenByDescending(c => c.Importers.Count)
                .ToList(),
            Phantoms = phantoms
                .OrderByDescending(ph => ph.Score.Total)
                .ThenByDescending(ph => ph.Importers.Count)
                .ToList(),
        };

        // Phase 7 (Sprint 3): targeted re-scan of privesc-resolved targets. One pass,
        // no recursion — findings produced by these new candidates are not fed back in.
        if (options.AnalyzePrivesc)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report(new ScanProgressInfo
            {
                Phase = "privesc.rescan",
                Scanned = files.Count,
                Total = files.Count,
                CurrentFile = "Re-scanning privesc-resolved targets...",
            });
            var alreadyKnown = new HashSet<string>(
                results.Existing.Select(c => c.Dll.Path.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);
            var discovered = Privesc.PrivescRescanner.CollectResolvedTargets(results, alreadyKnown);
            if (discovered.Count > 0)
            {
                var extra = Privesc.PrivescRescanner.Expand(discovered);
                // Append (do not re-sort aggressively — keep top Directly-enumerated
                // candidates first; discovered targets slot in by Total)
                results.Existing = results.Existing.Concat(extra)
                    .OrderByDescending(c => c.Score.Total)
                    .ThenBy(c => c.Discovery) // DirectEnumeration=0 wins ties
                    .ThenByDescending(c => c.Importers.Count)
                    .ToList();
                Log.Info("scan.privesc.rescan",
                    $"Targeted re-scan added {extra.Count} candidate(s) from {discovered.Count} resolved target(s)");
            }
        }

        return results;
    }

    private static List<string> EnumeratePeFiles(string dir, CancellationToken ct)
    {
        var result = new List<string>();
        int accessErrors = 0;
        int pathErrors = 0;
        try
        {
            // Using EnumerationOptions to log inaccessible subtrees without aborting the walk.
            // Directory.EnumerateFiles does NOT provide per-entry errors, so wrap in try/catch
            // around the whole iteration and let caller know via Log how many were missed.
            foreach (var f in Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (ext == ".dll" || ext == ".exe" || ext == ".sys" || ext == ".ocx")
                    result.Add(f);
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            accessErrors++;
            Log.Warn("scan.enum", $"Access denied while enumerating {dir} (partial results)", ex);
        }
        catch (PathTooLongException ex)
        {
            pathErrors++;
            Log.Warn("scan.enum", $"Path too long encountered in {dir} (partial results)", ex);
        }
        return result;
    }

    private static string TrimPath(string path)
    {
        const int max = 90;
        return path.Length <= max ? path : "..." + path[^(max - 3)..];
    }

    /// <summary>
    /// Combine privesc findings from: the candidate PE itself (if any) and all its importers.
    /// Phantoms pass pe=null since the phantom DLL doesn't exist on disk. The merged context
    /// carries the strongest signal across all involved binaries.
    /// </summary>
    private static PrivescContext BuildCombinedPrivescContext(
        PrivescAnalyzer analyzer,
        PeAnalysis? pe,
        List<ImporterRef> importers,
        ImportGraphBuilder graph,
        CancellationToken ct)
    {
        var combined = new PrivescContext();

        void AddFindings(PrivescContext ctx, string sourcePath)
        {
            foreach (var f in ctx.Findings)
            {
                // Decorate the finding with which PE produced it (for UI clarity)
                f.Extras["SourcePE"] = sourcePath;
                combined.Findings.Add(f);
            }
        }

        if (pe != null)
        {
            try { AddFindings(analyzer.Analyze(pe, ct), pe.Path); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Log.Debug("privesc", $"Analyze failed for {pe.Path}", ex); }
        }

        foreach (var imp in importers)
        {
            if (!graph.PathToAnalysis.TryGetValue(imp.ExePath, out var impPe)) continue;
            try { AddFindings(analyzer.Analyze(impPe, ct), impPe.Path); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Log.Debug("privesc", $"Analyze failed for importer {impPe.Path}", ex); }
        }

        return combined;
    }
}
