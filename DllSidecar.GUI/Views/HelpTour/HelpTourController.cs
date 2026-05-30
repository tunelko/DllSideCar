using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace DllSidecar.GUI.Views.HelpTour;

/// <summary>Drives the spotlight overlay through <see cref="TourStep"/>s over ConfigPage, resolving targets by x:Name.</summary>
public sealed class HelpTourController
{
    public static IReadOnlyList<TourStep> ConfigPageSteps => _configSteps;

    private static readonly TourStep[] _configSteps =
    [
        new("MingwSection",
            "1 · MinGW toolchain",
            "REQUIRED: MinGW-w64 x64 bin (gcc + windres). " +
            "Typical path: C:\\msys64\\mingw64\\bin. " +
            "The x86 and MSYS rows are optional — fill them only if you'll target 32-bit binaries."),
        new("ToolsSection",
            "2 · Tools",
            "REQUIRED: ProcMon.exe. Easiest way: point the Sysinternals folder at your unzipped " +
            "SysinternalsSuite — ProcMon and sigcheck auto-resolve from it. Everything else here is optional."),
        new("ResearcherSection",
            "3 · Researcher identity",
            "REQUIRED for drafting advisories: your Name and Email. The rest (handle, blog, PGP) is " +
            "optional and only appears on the advisories that need it."),
        new("BehaviorSection",
            "4 · Behavior",
            "Optional. Skip unless you want NVD queries to fire automatically after every Scan."),
        new("PayloadSection",
            "5 · Payload defaults",
            "Optional — sensible defaults ship out of the box. Change Reverse-shell host/port only if you " +
            "already know which listener your PoCs will connect back to."),
        new("SaveConfigBtn",
            "6 · Save config",
            "Click Save config to write everything to %APPDATA%\\DllSidecar\\config.json. " +
            "You can revisit this page any time from the Tools menu.",
            BalloonPlacement.Top),
    ];

    private readonly MainWindow _main;
    private readonly HelpTourOverlay _overlay;
    private readonly IReadOnlyList<TourStep> _steps;
    private ConfigPage? _page;
    private int _index;
    private bool _running;

    public HelpTourController(MainWindow main, HelpTourOverlay overlay, IReadOnlyList<TourStep>? steps = null)
    {
        _main = main;
        _overlay = overlay;
        _steps = steps ?? ConfigPageSteps;
        _overlay.NextClicked  += () => Move(+1);
        _overlay.BackClicked  += () => Move(-1);
        _overlay.SkipClicked  += End;
        _overlay.CloseClicked += End;
    }

    public void Start()
    {
        if (_running) return;
        _running = true;
        _index = 0;

        // Navigate to ConfigPage so named elements exist in the visual tree.
        var page = new ConfigPage(_main);
        page.Loaded += OnConfigLoaded;
        _main.NavigateTo(page);
        _page = page;
    }

    private void OnConfigLoaded(object sender, RoutedEventArgs e)
    {
        if (_page == null) return;
        _page.Loaded -= OnConfigLoaded;
        // One more layout tick so ToolPathRow contents have measured/arranged.
        _page.Dispatcher.BeginInvoke(DispatcherPriority.Background, new System.Action(ShowCurrent));
    }

    private void Move(int delta)
    {
        var next = _index + delta;
        if (next < 0) return;
        if (next >= _steps.Count) { End(); return; }
        _index = next;
        ShowCurrent();
    }

    private void ShowCurrent()
    {
        if (_page == null || !_running) return;
        var step = _steps[_index];
        var target = ResolveTarget(_page, step.TargetName);
        if (target == null)
        {
            // Unknown name — skip so a renamed element doesn't stall the tour.
            Move(+1);
            return;
        }
        _overlay.ShowStep(target, step, _index, _steps.Count);
    }

    private static FrameworkElement? ResolveTarget(FrameworkElement scope, string name)
    {
        // FindName covers page NameScope; LogicalTreeHelper covers templated controls.
        if (scope.FindName(name) is FrameworkElement fe) return fe;
        if (LogicalTreeHelper.FindLogicalNode(scope, name) is FrameworkElement le) return le;
        return null;
    }

    public void End()
    {
        _running = false;
        _overlay.Hide();
    }
}
