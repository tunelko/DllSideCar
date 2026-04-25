using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Services.Privesc;

/// <summary>
/// Contract for a privesc vector detector. Each implementation scans one specific
/// source of privilege escalation (services, tasks, manifests, etc.) and returns
/// findings for PE files matched against that source.
/// </summary>
public interface IPrivescDetector
{
    /// <summary>Human-readable name for logging and evidence attribution.</summary>
    string Name { get; }

    /// <summary>
    /// Called once per scan, before Detect. Let the detector build any expensive cache
    /// (e.g. enumerate the service registry, parse all scheduled tasks) up front rather
    /// than per-candidate. Implementations MUST be cancel-aware and fail-soft.
    /// </summary>
    void Prepare(PrivescDetectorContext ctx, CancellationToken ct);

    /// <summary>
    /// Return findings for a specific PE. Called once per candidate. Implementations
    /// must query pre-built caches from Prepare — no I/O per call where avoidable.
    /// </summary>
    IEnumerable<PrivescFinding> Detect(PeAnalysis pe, PrivescDetectorContext ctx, CancellationToken ct);
}

/// <summary>Shared state passed to detectors. Holds the current scan root and a lookup
/// of all analyzed PEs in the scan.</summary>
public class PrivescDetectorContext
{
    public required string ScanRoot { get; set; }
    public required IReadOnlyDictionary<string, PeAnalysis> PathToPe { get; set; }

    /// <summary>Paths (lowercased) of all PEs in the scan — O(1) membership test.</summary>
    public required HashSet<string> AllScannedPaths { get; set; }
}
