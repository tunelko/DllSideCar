using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace DllSidecar.GUI.Views.HelpTour;

/// <summary>Full-window dim + spotlight + callout balloon driven by <see cref="ShowStep"/>.</summary>
public partial class HelpTourOverlay : UserControl
{
    public event System.Action? NextClicked;
    public event System.Action? BackClicked;
    public event System.Action? SkipClicked;
    public event System.Action? CloseClicked;

    private FrameworkElement? _currentTarget;
    private TourStep? _currentStep;
    private int _currentIndex;
    private int _totalSteps;

    public HelpTourOverlay()
    {
        InitializeComponent();
    }

    public void ShowStep(FrameworkElement target, TourStep step, int index, int total)
    {
        _currentTarget = target;
        _currentStep = step;
        _currentIndex = index;
        _totalSteps = total;

        StepCounter.Text = $"STEP {index + 1} / {total}";
        BalloonTitle.Text = step.Title;
        BalloonBody.Text = step.Body;
        BackBtn.IsEnabled = index > 0;
        NextBtn.Content = index == total - 1 ? "Finish ✓" : "Next →";

        Visibility = Visibility.Visible;
        Balloon.Visibility = Visibility.Visible;

        // Defer: TransformToVisual needs a completed layout pass on both ends.
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, new System.Action(Relayout));
    }

    public void Hide()
    {
        Visibility = Visibility.Collapsed;
        Balloon.Visibility = Visibility.Collapsed;
        _currentTarget = null;
        _currentStep = null;
    }

    private void OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (Visibility == Visibility.Visible && _currentTarget != null) Relayout();
    }

    private void Relayout()
    {
        if (_currentTarget == null || _currentStep == null) return;
        if (ActualWidth < 1 || ActualHeight < 1) return;
        if (_currentTarget.ActualWidth < 1 || _currentTarget.ActualHeight < 1) return;

        // Align target's TOP edge to viewport top in its parent ScrollViewer (BringIntoView alone bottom-aligns tall sections).
        var scroller = FindParentScrollViewer(_currentTarget);
        if (scroller != null)
        {
            try
            {
                var pos = _currentTarget.TransformToAncestor(scroller).Transform(new System.Windows.Point(0, 0));
                var desired = scroller.VerticalOffset + pos.Y;
                desired = System.Math.Max(0, System.Math.Min(desired, scroller.ScrollableHeight));
                scroller.ScrollToVerticalOffset(desired);
                scroller.UpdateLayout();
            }
            catch (System.InvalidOperationException) { }
        }
        else
        {
            _currentTarget.BringIntoView();
        }
        UpdateLayout();

        Rect targetRect;
        try
        {
            var transform = _currentTarget.TransformToVisual(this);
            targetRect = transform.TransformBounds(new Rect(_currentTarget.RenderSize));
        }
        catch (System.InvalidOperationException)
        {
            // Target not in the same visual tree (page swapped under us).
            return;
        }

        // Clip cutout to ScrollViewer viewport so the spotlight doesn't bleed into header/footer.
        Rect visible = targetRect;
        if (scroller != null)
        {
            try
            {
                var svRect = scroller.TransformToVisual(this).TransformBounds(new Rect(scroller.RenderSize));
                visible = Rect.Intersect(targetRect, svRect);
            }
            catch (System.InvalidOperationException) { }
        }
        if (visible.IsEmpty) return;

        // Pad cutout so spotlight reads as a halo, not a flush frame.
        const double pad = 6;
        var cutout = new Rect(
            visible.X - pad,
            visible.Y - pad,
            visible.Width + 2 * pad,
            visible.Height + 2 * pad);

        // Clamp to overlay bounds.
        cutout.Intersect(new Rect(0, 0, ActualWidth, ActualHeight));
        if (cutout.IsEmpty) return;

        // Position the four dim rectangles around the cutout.
        Canvas.SetLeft(DimTop, 0); Canvas.SetTop(DimTop, 0);
        DimTop.Width = ActualWidth; DimTop.Height = System.Math.Max(0, cutout.Top);

        Canvas.SetLeft(DimBottom, 0); Canvas.SetTop(DimBottom, cutout.Bottom);
        DimBottom.Width = ActualWidth; DimBottom.Height = System.Math.Max(0, ActualHeight - cutout.Bottom);

        Canvas.SetLeft(DimLeft, 0); Canvas.SetTop(DimLeft, cutout.Top);
        DimLeft.Width = System.Math.Max(0, cutout.Left); DimLeft.Height = cutout.Height;

        Canvas.SetLeft(DimRight, cutout.Right); Canvas.SetTop(DimRight, cutout.Top);
        DimRight.Width = System.Math.Max(0, ActualWidth - cutout.Right); DimRight.Height = cutout.Height;

        // Spotlight outline.
        Canvas.SetLeft(Spotlight, cutout.Left); Canvas.SetTop(Spotlight, cutout.Top);
        Spotlight.Width = cutout.Width; Spotlight.Height = cutout.Height;

        // Position balloon: prefer below (centred), fall back to above; clamp to overlay edges.
        Balloon.Measure(new System.Windows.Size(double.PositiveInfinity, double.PositiveInfinity));
        var balloonW = Balloon.DesiredSize.Width;
        var balloonH = Balloon.DesiredSize.Height;
        const double gap = 14;

        double bx, by;
        var placement = _currentStep.Placement;
        var roomBelow = ActualHeight - cutout.Bottom;
        var roomAbove = cutout.Top;
        var roomRight = ActualWidth - cutout.Right;
        var roomLeft = cutout.Left;

        bool placedHorizontally = placement == BalloonPlacement.Left || placement == BalloonPlacement.Right;
        if (placement == BalloonPlacement.Auto)
        {
            // Prefer vertical; switch to horizontal only when neither side has room.
            if (roomBelow < balloonH + gap && roomAbove < balloonH + gap)
                placedHorizontally = true;
        }

        if (placedHorizontally)
        {
            by = cutout.Top + (cutout.Height - balloonH) / 2;
            // Right of the target if there's room; else left.
            if ((placement == BalloonPlacement.Right || placement == BalloonPlacement.Auto)
                && roomRight >= balloonW + gap)
                bx = cutout.Right + gap;
            else if (roomLeft >= balloonW + gap)
                bx = cutout.Left - balloonW - gap;
            else
                bx = cutout.Right + gap; // overflow handled by clamp below
        }
        else
        {
            bx = cutout.Left + (cutout.Width - balloonW) / 2;
            if (placement == BalloonPlacement.Top
                || (placement == BalloonPlacement.Auto && roomBelow < balloonH + gap))
                by = cutout.Top - balloonH - gap;
            else
                by = cutout.Bottom + gap;
        }

        // Clamp inside the overlay.
        bx = System.Math.Max(8, System.Math.Min(bx, ActualWidth - balloonW - 8));
        by = System.Math.Max(8, System.Math.Min(by, ActualHeight - balloonH - 8));

        Canvas.SetLeft(Balloon, bx);
        Canvas.SetTop(Balloon, by);
    }

    private void Next_Click(object sender, RoutedEventArgs e) => NextClicked?.Invoke();
    private void Back_Click(object sender, RoutedEventArgs e) => BackClicked?.Invoke();
    private void Skip_Click(object sender, RoutedEventArgs e) => SkipClicked?.Invoke();
    private void Close_Click(object sender, RoutedEventArgs e) => CloseClicked?.Invoke();

    private static ScrollViewer? FindParentScrollViewer(DependencyObject? element)
    {
        while (element != null)
        {
            if (element is ScrollViewer sv) return sv;
            element = System.Windows.Media.VisualTreeHelper.GetParent(element);
        }
        return null;
    }
}
