namespace DllSidecar.Core.Models;

/// <summary>
/// Evidence quality for a candidate. Lives on its own axis — it must not contaminate
/// Exploitability (how feasible) or Impact (what privilege is gained).
/// </summary>
public enum ConfidenceLevel
{
    StaticOnly,       // IAT / manifest / ACL only — no runtime signal
    RuntimeNameMatch, // Runtime source observed the loader resolving this DLL name
    RuntimeDirMatch,  // Runtime source observed it in THIS directory — ground truth
}

/// <summary>Which scoring axis a factor contributes to.</summary>
public enum ScoreAxis
{
    Exploitability, // write primitive + load certainty + proxy/sideload ease
    Impact,         // user → restricted service → admin → SYSTEM
    Confidence,     // evidence quality only
}

public class ScoreFactor
{
    public required ScoreAxis Axis { get; set; }
    public required string Name { get; set; }
    public required int Points { get; set; } // can be negative
    public required string Reason { get; set; }
}

/// <summary>
/// Three-axis scoring introduced in Sprint 1. Each axis is 0..10 and captured
/// independently so the UI can rank/filter per axis and never lets one contaminate
/// another. Total is derived.
/// </summary>
public class ScoreBreakdown
{
    // --- Weights for Total ---
    // Exploitability 50%  → the tool must prioritize "actually exploitable" first
    // Impact          30% → then "what privilege is gained"
    // Confidence      20% → evidence quality influences ranking but must not eclipse
    //                       a high-exploit finding that has not been dynamically validated yet
    public const double WeightExploitability = 0.50;
    public const double WeightImpact         = 0.30;
    public const double WeightConfidence     = 0.20;

    public int Exploitability { get; set; }
    public int Impact { get; set; }
    public int Confidence { get; set; }

    /// <summary>Machine-readable confidence tier (drives the Confidence axis value).</summary>
    public ConfidenceLevel ConfidenceLevel { get; set; } = ConfidenceLevel.StaticOnly;

    /// <summary>Per-axis factor log for explainability — drill-down in UI.</summary>
    public List<ScoreFactor> Factors { get; set; } = [];

    public int Total => (int)Math.Round(
        Math.Clamp(Exploitability, 0, 10) * WeightExploitability +
        Math.Clamp(Impact,         0, 10) * WeightImpact +
        Math.Clamp(Confidence,     0, 10) * WeightConfidence);

    public string Severity => Total switch
    {
        >= 9 => "Critical",
        >= 7 => "High",
        >= 4 => "Medium",
        >= 1 => "Low",
        _    => "None",
    };

    public IEnumerable<ScoreFactor> FactorsFor(ScoreAxis axis) =>
        Factors.Where(f => f.Axis == axis);
}
