using System.Windows;
using System.Windows.Controls;
using DllSidecar.Core.Models;

namespace DllSidecar.GUI.Views;

/// <summary>
/// Radial visualization of the full discovery → exploitability flow for the
/// candidate currently focused in MainWindow.CurrentAttackFocus. Step 2 wires
/// the empty state and the candidate summary; rings, connectors, score sectors
/// and animation land in subsequent steps.
/// </summary>
public partial class AttackPathPage : Page
{
    private readonly MainWindow _main;
    private MainWindow.AttackPathFocus? _focus;

    public AttackPathPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        Loaded += (_, _) => Refresh();
    }

    /// <summary>
    /// Read CurrentAttackFocus from MainWindow and decide what to render.
    /// Empty state when null. Candidate summary + diagram host when set.
    /// </summary>
    public void Refresh()
    {
        _focus = _main.CurrentAttackFocus;
        if (_focus == null)
        {
            EmptyState.Visibility = Visibility.Visible;
            DiagramHost.Visibility = Visibility.Collapsed;
            FocusSummary.Visibility = Visibility.Collapsed;
            SourceBadge.Visibility = Visibility.Collapsed;
            return;
        }

        EmptyState.Visibility = Visibility.Collapsed;
        DiagramHost.Visibility = Visibility.Visible;
        FocusSummary.Visibility = Visibility.Visible;
        SourceBadge.Visibility = Visibility.Visible;

        SourceBadgeText.Text = _focus.Source switch
        {
            MainWindow.AttackFocusSource.Scan         => "FROM SCAN",
            MainWindow.AttackFocusSource.RuntimeTrace => "FROM RUNTIME TRACE",
            _                                         => "FOCUSED",
        };

        FocusDllName.Text = _focus.DllName;
        FocusDllPath.Text = _focus.DllPath ?? "";

        // Severity badge: pull from the score breakdown if we have a candidate, else
        // mark the focus as DEGRADED so the user knows the diagram won't be complete.
        var score = _focus.Candidate?.Score ?? _focus.Phantom?.Score;
        if (score != null)
        {
            SeverityBadgeText.Text = $"{score.Total}/10  {score.Severity.ToUpperInvariant()}";
            // Colour by severity bucket
            var (bg, fg) = score.Severity switch
            {
                "Critical" => ("#33FF5B4F", "#FF5B4F"),
                "High"     => ("#33F5A524", "#F5A524"),
                "Medium"   => ("#330A72EF", "#0A72EF"),
                "Low"      => ("#3300CA4E", "#00CA4E"),
                _          => ("#33737373", "#737373"),
            };
            SeverityBadge.Background = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString(bg)!;
            SeverityBadgeText.Foreground = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString(fg)!;
        }
        else
        {
            SeverityBadgeText.Text = "DEGRADED";
            SeverityBadge.Background = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#33737373")!;
            SeverityBadgeText.Foreground = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#737373")!;
        }

        // Step 3 will draw the rings here. For now the host is just the empty
        // canvas inside a Viewbox so the page lays out correctly.
        DiagramCanvas.Children.Clear();
    }

    private void GoScan_Click(object sender, RoutedEventArgs e) =>
        _main.NavigateTo(new ScanPage(_main));

    private void GoRuntime_Click(object sender, RoutedEventArgs e) =>
        _main.NavigateTo(new RuntimeTracePage(_main));
}
