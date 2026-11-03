using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Services.Privesc;

/// <summary>
/// Orchestrates the privesc detector pipeline; applies cross-detector escalation rules.
/// </summary>
public class PrivescAnalyzer
{
    private readonly List<IPrivescDetector> _detectors;
    private PrivescDetectorContext? _ctx;
    private bool _prepared;

    public PrivescAnalyzer(IEnumerable<IPrivescDetector>? detectors = null)
    {
        _detectors = detectors?.ToList() ?? DefaultDetectors();
    }

    public static List<IPrivescDetector> DefaultDetectors() =>
    [
        new ServicesDetector(),
        new AutoElevateDetector(),
        new ScheduledTaskDetector(),
        new UpdaterHeuristicDetector(),
    ];

    /// <summary>Build caches. Call once before any Annotate.</summary>
    public void Prepare(string scanRoot, IEnumerable<PeAnalysis> allPes, CancellationToken ct)
    {
        var pathMap = new Dictionary<string, PeAnalysis>(StringComparer.OrdinalIgnoreCase);
        var pathSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pe in allPes)
        {
            try
            {
                var full = Path.GetFullPath(pe.Path);
                pathMap[full] = pe;
                pathSet.Add(full);
            }
            catch (Exception ex)
            {
                Log.Debug("privesc", $"Could not normalize path {pe.Path}", ex);
            }
        }

        _ctx = new PrivescDetectorContext
        {
            ScanRoot = scanRoot,
            PathToPe = pathMap,
            AllScannedPaths = pathSet,
        };

        foreach (var det in _detectors)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                det.Prepare(_ctx, ct);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                Log.Error("privesc", $"Detector {det.Name} failed during Prepare", ex);
            }
        }
        _prepared = true;
    }

    /// <summary>Annotate a candidate with detected privesc vectors. Safe to call repeatedly.</summary>
    public PrivescContext Analyze(PeAnalysis pe, CancellationToken ct)
    {
        if (!_prepared || _ctx == null)
            throw new InvalidOperationException("PrivescAnalyzer.Prepare must be called before Analyze");

        var context = new PrivescContext();
        foreach (var det in _detectors)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var finding in det.Detect(pe, _ctx, ct))
                    context.Findings.Add(finding);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                Log.Warn("privesc", $"Detector {det.Name} failed for {pe.Path}", ex);
            }
        }

        ApplyCrossDetectorEscalation(context);
        return context;
    }

    /// <summary>
    /// Cross-detector rules; combined findings synthesize higher-severity entries.
    /// </summary>
    private static void ApplyCrossDetectorEscalation(PrivescContext ctx)
    {
        bool isUpdater = ctx.Findings.Any(f => f.Vector == PrivescVector.UpdaterHeuristic);
        // autoElevate + updater: not SYSTEM directly but UAC-free admin execution
        bool autoElevate = ctx.Findings.Any(f => f.Vector == PrivescVector.AutoElevate);
        if (isUpdater && autoElevate)
        {
            ctx.Findings.Add(new PrivescFinding
            {
                Vector = PrivescVector.AutoElevate,
                Severity = PrivescSeverity.High,
                DetectorName = "PrivescAnalyzer",
                Title = "Updater binary with autoElevate — silent admin elevation path",
                Evidence = "Updater filename + manifest autoElevate — sideload yields admin without UAC prompt.",
            });
        }
    }

    /// <summary>
    /// Promote a SYSTEM updater finding to Critical only when the candidate supplies the
    /// complete sideload chain: a user-writable plant directory and a trusted, load-time
    /// importer that is the same PE identified by both the updater and SYSTEM findings.
    /// </summary>
    public static void ApplyVerifiedCandidateEscalation(
        PrivescContext? ctx,
        DirectoryPermissions directory,
        IReadOnlyList<ImporterRef> importers)
    {
        if (ctx == null) return;

        const string ruleId = "VerifiedSystemUpdaterChain";

        // Scoring can be repeated after correlation or session restoration.
        ctx.Findings.RemoveAll(f =>
            (f.Extras.TryGetValue("Rule", out var rule) && rule == ruleId) ||
            (f.DetectorName == nameof(PrivescAnalyzer) &&
             f.Severity == PrivescSeverity.Critical &&
             f.Vector == PrivescVector.UpdaterHeuristic &&
             f.Title.StartsWith("JACKPOT:", StringComparison.Ordinal)));

        if (!directory.IsUserWritable || importers.Count == 0) return;

        var systemFindings = ctx.Findings.Where(f =>
            (f.Vector is PrivescVector.ServiceSystem or PrivescVector.ScheduledTask) &&
            f.Severity >= PrivescSeverity.High);

        foreach (var systemFinding in systemFindings)
        {
            if (!TryGetSourcePe(systemFinding, out var sourcePe)) continue;

            var samePeIsUpdater = ctx.Findings.Any(f =>
                f.Vector == PrivescVector.UpdaterHeuristic &&
                TryGetSourcePe(f, out var updaterSource) &&
                PathsEqual(updaterSource, sourcePe));
            if (!samePeIsUpdater) continue;

            var importer = importers.FirstOrDefault(i => PathsEqual(i.ExePath, sourcePe));
            if (importer == null ||
                !importer.Signing.IsTrusted ||
                importer.IsDelayLoad ||
                importer.ForcesSystem32Only)
                continue;

            var extras = new Dictionary<string, string>(systemFinding.Extras)
            {
                ["Rule"] = ruleId,
                ["SourcePE"] = sourcePe,
                ["WritableDirectory"] = directory.Path,
                ["TrustedImporter"] = importer.ExePath,
            };

            ctx.Findings.Add(new PrivescFinding
            {
                Vector = systemFinding.Vector,
                Severity = PrivescSeverity.Critical,
                DetectorName = nameof(PrivescAnalyzer),
                Title = "JACKPOT: writable DLL path loaded by signed SYSTEM updater",
                Evidence = $"User-writable directory '{directory.Path}' + trusted load-time importer " +
                           $"'{importer.ExeFilename}' + SYSTEM service/task trigger on the same PE.",
                PrivilegedProcessPath = systemFinding.PrivilegedProcessPath ?? sourcePe,
                PrivilegedAccount = systemFinding.PrivilegedAccount,
                Extras = extras,
            });
            return;
        }
    }

    private static bool TryGetSourcePe(PrivescFinding finding, out string sourcePe)
    {
        if (finding.Extras.TryGetValue("SourcePE", out var value) &&
            !string.IsNullOrWhiteSpace(value))
        {
            sourcePe = value;
            return true;
        }

        sourcePe = "";
        return false;
    }

    private static bool PathsEqual(string left, string right)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(left),
                Path.GetFullPath(right),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }
    }
}
