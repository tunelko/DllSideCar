using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Services.Privesc;

/// <summary>
/// Heuristic marker for updater/maintenance/helper binaries; Informational alone, escalates with Services/ScheduledTask findings.
/// </summary>
public class UpdaterHeuristicDetector : IPrivescDetector
{
    public string Name => "UpdaterHeuristicDetector";

    // Patterns observed across Adobe/Chrome/Mozilla/Forticlient/Dropbox/OneDrive updaters.
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
