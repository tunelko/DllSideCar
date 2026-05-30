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
        bool runsAsSystem = ctx.Findings.Any(f =>
            f.Vector is PrivescVector.ServiceSystem or PrivescVector.ScheduledTask
            && f.Severity >= PrivescSeverity.High);

        if (isUpdater && runsAsSystem)
        {
            ctx.Findings.Add(new PrivescFinding
            {
                Vector = PrivescVector.UpdaterHeuristic,
                Severity = PrivescSeverity.Critical,
                DetectorName = "PrivescAnalyzer",
                Title = "JACKPOT: updater-pattern binary runs as SYSTEM",
                Evidence = "Updater filename + SYSTEM service/task combined — classic auto-update-as-SYSTEM privesc chain (Adobe/Chrome/Forticlient pattern).",
            });
        }

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
}
