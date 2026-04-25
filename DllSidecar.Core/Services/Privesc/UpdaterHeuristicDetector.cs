using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Services.Privesc;

/// <summary>
/// Heuristic marker for "updater / maintenance / helper" binaries — these are the gold
/// targets in the sideloading research methodology because they almost always run as
/// SYSTEM (to update privileged files) and are triggered automatically on a schedule.
///
/// Fires as Informational by itself; severity escalates when combined with ServicesDetector
/// or ScheduledTaskDetector findings on the same PE. The PrivescAnalyzer handles that
/// escalation after all detectors have run.
/// </summary>
public class UpdaterHeuristicDetector : IPrivescDetector
{
    public string Name => "UpdaterHeuristicDetector";

    // Patterns derived from observed updater/helper binaries across Adobe, Chrome,
    // Mozilla, Forticlient, Dropbox, OneDrive, and similar vendors.
    private static readonly string[] Patterns =
    [
        "update", "updater", "autoupdate", "autoupdater",
        "maintenance", "helper", "elevator", "installer",
        "patcher", "setup",
    ];

    public void Prepare(PrivescDetectorContext ctx, CancellationToken ct) { /* stateless */ }

    public IEnumerable<PrivescFinding> Detect(PeAnalysis pe, PrivescDetectorContext ctx, CancellationToken ct)
    {
        var filename = pe.Filename.ToLowerInvariant();
        var matched = Patterns.FirstOrDefault(p => filename.Contains(p));
        if (matched == null) yield break;

        // Only flag EXEs — a "helper DLL" is not a privileged runner by itself
        if (!filename.EndsWith(".exe")) yield break;

        yield return new PrivescFinding
        {
            Vector = PrivescVector.UpdaterHeuristic,
            Severity = PrivescSeverity.Informational,
            DetectorName = Name,
            Title = $"Filename pattern '{matched}' suggests updater/maintenance binary",
            Evidence = $"Filename: {pe.Filename}",
            Extras =
            {
                ["MatchedPattern"] = matched,
                ["Note"] = "Severity escalates if paired with a Service/Task finding on this PE.",
            },
        };
    }
}
