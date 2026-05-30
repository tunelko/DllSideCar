namespace DllSidecar.GUI.Views.HelpTour;

/// <summary>Where the callout balloon prefers to sit relative to the spotlighted target.</summary>
public enum BalloonPlacement
{
    Bottom,
    Top,
    Left,
    Right,
    Auto,
}

/// <summary>One step of the Help Wizard Tour. <see cref="TargetName"/> is the x:Name to spotlight.</summary>
public sealed record TourStep(
    string TargetName,
    string Title,
    string Body,
    BalloonPlacement Placement = BalloonPlacement.Auto);
