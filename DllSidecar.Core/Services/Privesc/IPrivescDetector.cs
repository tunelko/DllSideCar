using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Services.Privesc;

/// <summary>
/// Contract for a privesc vector detector (services, tasks, manifests, etc.).
/// </summary>
public interface IPrivescDetector
{
    /// <summary>Human-readable name for logging and evidence attribution.</summary>
    string Name { get; }

    /// <summary>
    /// Called once per scan to build caches; cancel-aware and fail-soft.
    /// </summary>
    void Prepare(PrivescDetectorContext ctx, CancellationToken ct);

    /// <summary>
    /// Return findings for one PE; should query pre-built caches.
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
