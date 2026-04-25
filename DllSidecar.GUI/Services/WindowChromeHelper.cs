using System.Windows.Shell;
using Application = System.Windows.Application;
using Brush = System.Windows.Media.Brush;
using Style = System.Windows.Style;
using Grid = System.Windows.Controls.Grid;
using RowDefinition = System.Windows.Controls.RowDefinition;
using ColumnDefinition = System.Windows.Controls.ColumnDefinition;
using Thickness = System.Windows.Thickness;
using WindowStyle = System.Windows.WindowStyle;
using CornerRadius = System.Windows.CornerRadius;
using Window = System.Windows.Window;
using UIElement = System.Windows.UIElement;
using GridLength = System.Windows.GridLength;
using GridUnitType = System.Windows.GridUnitType;
using FontWeights = System.Windows.FontWeights;
using VerticalAlignment = System.Windows.VerticalAlignment;
using TextTrimming = System.Windows.TextTrimming;
using Button = System.Windows.Controls.Button;
using TextBlock = System.Windows.Controls.TextBlock;
using Border = System.Windows.Controls.Border;

namespace DllSidecar.GUI.Services;

/// <summary>
/// Applies the MainWindow chrome look (WindowStyle=None + WindowChrome + themed Ring
/// border + caption bar with close button) to any Window, programmatically. Call once
/// in the dialog ctor after InitializeComponent.
///
/// This avoids duplicating ~30 lines of XAML across every modal. The existing Window
/// content is wrapped in a Grid with the caption bar on top; the original Content is
/// moved untouched into row 1 so layouts/bindings stay intact.
/// </summary>
public static class WindowChromeHelper
{
    public static void Apply(Window window, string? captionTitle = null)
    {
        // Idempotent — safe to call multiple times.
        if (window.Tag as string == "dllsidecar-chromed") return;
        window.Tag = "dllsidecar-chromed";

        window.WindowStyle = WindowStyle.None;
        var chrome = new WindowChrome
        {
            CaptionHeight = 32,
            ResizeBorderThickness = new Thickness(6),
            CornerRadius = new CornerRadius(0),
            GlassFrameThickness = new Thickness(0),
            UseAeroCaptionButtons = false,
        };
        WindowChrome.SetWindowChrome(window, chrome);

        var title = string.IsNullOrEmpty(captionTitle) ? window.Title : captionTitle;
        var existing = window.Content as UIElement;
        window.Content = null;

        var border = new Border
        {
            BorderBrush = (Brush)Application.Current.Resources["Ring"],
            BorderThickness = new Thickness(1),
        };
        var grid = new Grid();
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        var caption = new Grid
        {
            Background = (Brush)Application.Current.Resources["Mantle"],
        };
        caption.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        caption.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var titleText = new TextBlock
        {
            Text = title ?? "",
            FontSize = 13,
            FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)Application.Current.Resources["Text"],
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(16, 0, 0, 0),
            TextTrimming = TextTrimming.CharacterEllipsis,
        };
        Grid.SetColumn(titleText, 0);
        caption.Children.Add(titleText);

        var close = new Button
        {
            Content = "✕",
            Style = (Style)Application.Current.Resources["IconButton"],
            Margin = new Thickness(8, 4, 8, 4),
            IsCancel = true,
            ToolTip = "Close",
        };
        close.Click += (_, _) => window.Close();
        WindowChrome.SetIsHitTestVisibleInChrome(close, true);
        Grid.SetColumn(close, 1);
        caption.Children.Add(close);

        Grid.SetRow(caption, 0);
        grid.Children.Add(caption);

        if (existing != null)
        {
            Grid.SetRow(existing, 1);
            grid.Children.Add(existing);
        }

        border.Child = grid;
        window.Content = border;
    }
}
