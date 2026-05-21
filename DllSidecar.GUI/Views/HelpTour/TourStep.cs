namespace DllSidecar.GUI.Views.HelpTour;

/// <summary>
/// Where the callout balloon prefers to sit relative to the spotlighted target.
/// The overlay clamps to the visible area, so if there isn't room on the preferred
/// side it falls back to the opposite side automatically.
/// </summary>
public enum BalloonPlacement
{
    Bottom,
    Top,
    Left,
    Right,
    Auto,
}

/// <summary>
/// One step of the Help Wizard Tour. <see cref="TargetName"/> is the x:Name of the
/// element on the active page (ConfigPage today) that the overlay will spotlight.
/// </summary>
public sealed record TourStep(
    string TargetName,
    string Title,
    string Body,
    BalloonPlacement Placement = BalloonPlacement.Auto);
