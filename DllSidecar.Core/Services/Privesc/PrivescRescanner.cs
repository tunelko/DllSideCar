using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Services.Privesc;

/// <summary>
/// Sprint-3 targeted re-scan. Collects <c>ResolvedTarget</c> paths emitted by
/// ScheduledTaskDetector / ServicesDetector (via <c>PrivescFinding.Extras</c>), filters
/// them (existing, PE, not already scanned, deduped), and analyses each ONCE as a
/// <see cref="SideloadCandidate"/> flagged with <see cref="DiscoveryOrigin.PrivescResolvedTarget"/>.
///
/// Deliberate limits (out of Sprint 3 scope):
///   - no recursion — findings produced by re-scanned candidates are NOT fed back in.
///   - no wrapper recursion — a wrapped target resolved to a .bat/.ps1 is skipped (not a PE).
///   - no multi-hop discovery.
///   - Exploitability is NOT inflated by this discovery path: the normal scorer runs
///     and the absence of an importer graph will honestly dampen the score. Impact
///     (from the inherited privesc context) and the chain steps carry the signal.
/// </summary>
public static class PrivescRescanner
{
    public class DiscoveredTarget
    {
        public required string NormalizedPath { get; set; }
        public required PrivescFinding SourceFinding { get; set; }
        public required string ViaLabel { get; set; }
    }

    /// <summary>
    /// Walk every finding across Existing+Phantoms, extract ResolvedTarget paths that
    /// are status=Resolved, exist on disk, have a PE extension, and aren't already in
    /// the known-paths set. Returns deduplicated entries (first source finding wins).
    /// </summary>
    public static List<DiscoveredTarget> CollectResolvedTargets(
        ScanResults scan, IReadOnlySet<string> alreadyKnownLowercased)
    {
        var seen = new HashSet<string>(alreadyKnownLowercased, StringComparer.OrdinalIgnoreCase);
        var result = new List<DiscoveredTarget>();

        foreach (var f in AllFindings(scan))
        {
            if (!f.Extras.TryGetValue("ResolvedTarget", out var target)) continue;
            if (string.IsNullOrWhiteSpace(target)) continue;
            if (!f.Extras.TryGetValue("ResolutionStatus", out var status) ||
                status != "Resolved") continue;

            string normalized;
            try { normalized = Path.GetFullPath(target).ToLowerInvariant(); }
            catch { continue; }

            if (!IsPe(normalized)) continue;
            if (!File.Exists(normalized)) continue;
            if (!seen.Add(normalized)) continue; // dedup

            result.Add(new DiscoveredTarget
            {
                NormalizedPath = normalized,
                SourceFinding = f,
                ViaLabel = BuildViaLabel(f),
            });
        }
        return result;
    }

    /// <summary>
    /// Analyse each discovered target and produce a SideloadCandidate. The source
    /// finding is attached as the candidate's PrivescContext so Impact flows naturally
    /// and the chain renders end-to-end.
    ///
    /// Failures are soft — one bad target must not abort the re-scan.
    /// </summary>
    public static List<SideloadCandidate> Expand(IEnumerable<DiscoveredTarget> targets)
    {
        var produced = new List<SideloadCandidate>();
        foreach (var t in targets)
        {
            try
            {
                var pe = PeAnalyzer.Analyze(t.NormalizedPath);
                var dir = DirectoryAclChecker.Check(Path.GetDirectoryName(t.NormalizedPath) ?? "");
                var signing = AuthenticodeVerifier.Verify(t.NormalizedPath);

                var candidate = new SideloadCandidate
                {
                    Dll = pe,
                    DllSigning = signing,
                    Dir = dir,
                    Importers = [],                                   // no cross-ref in targeted re-scan
                    Discovery = DiscoveryOrigin.PrivescResolvedTarget,
                    DiscoveredViaLabel = t.ViaLabel,
                    Privesc = new PrivescContext { Findings = { t.SourceFinding } },
                };
                candidate.Score = ExploitabilityScorer.Score(candidate);
                produced.Add(candidate);
            }
            catch (Exception ex)
            {
                Log.Debug("privesc.rescan", $"Could not expand {t.NormalizedPath}: {ex.Message}");
            }
        }
        return produced;
    }

    // ─────────── helpers ───────────

    private static IEnumerable<PrivescFinding> AllFindings(ScanResults scan)
    {
        foreach (var c in scan.Existing)
            if (c.Privesc != null)
                foreach (var f in c.Privesc.Findings) yield return f;
        foreach (var p in scan.Phantoms)
            if (p.Privesc != null)
                foreach (var f in p.Privesc.Findings) yield return f;
    }

    private static bool IsPe(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".exe" or ".dll";
    }

    private static string BuildViaLabel(PrivescFinding f)
    {
        return f.Vector switch
        {
            PrivescVector.ScheduledTask =>
                f.Extras.TryGetValue("TaskName", out var name) && !string.IsNullOrEmpty(name)
                    ? $"Task '{name}'"
                    : "Scheduled task",
            PrivescVector.ServiceSystem =>
                f.Extras.TryGetValue("ServiceName", out var name) && !string.IsNullOrEmpty(name)
                    ? $"Service '{name}'"
                    : "Service",
            _ => f.Vector.ToString(),
        };
    }
}
