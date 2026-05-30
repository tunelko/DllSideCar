using System.Windows;
using System.Windows.Controls;
using DllSidecar.Core.Services.Exploitability;
using Brush = System.Windows.Media.Brush;

namespace DllSidecar.GUI.Controls;

/// <summary>Renders an <see cref="ExploitabilityVerdict"/> as a colored chip + pros/cons tooltip.</summary>
public partial class VerdictBadge : System.Windows.Controls.UserControl
{
    public VerdictBadge() { InitializeComponent(); }

    public static readonly DependencyProperty VerdictProperty =
        DependencyProperty.Register(
            nameof(Verdict),
            typeof(ExploitabilityVerdict),
            typeof(VerdictBadge),
            new PropertyMetadata(null, OnVerdictChanged));

    public ExploitabilityVerdict? Verdict
    {
        get => (ExploitabilityVerdict?)GetValue(VerdictProperty);
        set => SetValue(VerdictProperty, value);
    }

    private static void OnVerdictChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is VerdictBadge badge) badge.Refresh();
    }

    private void Refresh()
    {
        var v = Verdict;
        if (v == null)
        {
            BadgeBorder.Visibility = Visibility.Collapsed;
            return;
        }
        BadgeBorder.Visibility = Visibility.Visible;
        BadgeText.Text = $"{v.TierLabel}  {v.Score}/10";

        // Tier -> palette.
        var (bgKey, fgKey) = v.Tier switch
        {
            ExploitabilityTier.Real          => ("Phosphor", "Base"),
            ExploitabilityTier.Likely        => ("Yellow",   "Base"),
            ExploitabilityTier.Theoretical   => ("Overlay",  "Text"),
            ExploitabilityTier.NotApplicable => ("Red",      "Base"),
            _ => ("Overlay", "Text"),
        };
        BadgeBorder.Background = (Brush)FindResource(bgKey);
        BadgeText.Foreground   = (Brush)FindResource(fgKey);

        TipTitle.Text = $"Exploitability: {v.TierLabel} ({v.Score}/10)";
        if (!string.IsNullOrEmpty(v.BlockingFactor))
        {
            TipBlocker.Text = "Blocker: " + v.BlockingFactor;
            TipBlocker.Visibility = Visibility.Visible;
        }
        else
        {
            TipBlocker.Visibility = Visibility.Collapsed;
        }

        TipPros.ItemsSource = v.Pros.ToList();
        TipCons.ItemsSource = v.Cons.ToList();
    }
}
