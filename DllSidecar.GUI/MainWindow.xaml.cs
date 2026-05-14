using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;
using DllSidecar.GUI.Views;
using CoreLog = DllSidecar.Core.Logging.Log;
using LogEntry = DllSidecar.Core.Logging.LogEntry;
using LogLevel = DllSidecar.Core.Logging.LogLevel;

namespace DllSidecar.GUI;

public partial class MainWindow : Window
{
    public Core.Models.PeAnalysis? CurrentAnalysis { get; set; }
    public string? CurrentDllPath { get; set; }

    // Set by ScanPage's "Generate Sideload" on a phantom; consumed by GeneratePage
    // when it builds the TemplateConfig (so the resulting .bat deploys + runs + cleans).
    // Null when generating from non-phantom flows (manual nav).
    // SystemOrigPath is the canonical system copy (System32/SysWOW64) when the phantom
    // matched a well-known DLL — the .bat copies it as <base>_orig.dll for Proxy forwards.
    public DeployContext? PendingDeployContext { get; set; }
    public record DeployContext(
        string TargetDir,
        string TargetName,
        string HostExePath,
        string? SystemOrigPath = null,
        Core.Models.GenerationMode? AutoMode = null,
        int AutoExportCount = 0);

    // Session state preserved across navigation. Without this, every nav away from
    // ScanPage would clear the grid and force a re-scan.
    public DllSidecar.Core.Services.ScanResults? LastScanResults { get; set; }
    public string? LastScanDir { get; set; }
    public DllSidecar.Core.Models.EtwTraceResult? LastEtwResult { get; set; }
    // Parsed ProcMon CSV survives navigation. ProcmonPage parks both the
    // result and the source path here so reopening the page after a detour
    // (e.g. to Analyze, Config, or Toolkit) doesn't drop the parse — same
    // pattern as LastScanResults / LastEtwResult above. Cleared only when
    // the user explicitly re-parses a different CSV.
    public DllSidecar.Core.Services.ProcmonParser.ParseResult? LastProcmonResult { get; set; }
    public string? LastProcmonCsvPath { get; set; }
    // Last EXE path the user typed/picked in RuntimeTrace's Launch mode. Persisted here
    // so the field survives navigation away and back (same pattern as LastScanDir).
    public string? LastRuntimeLaunchExe { get; set; }

    // Live wizard session — non-null while a wizard is open and NOT finished/discarded.
    // Survives navigation: WizardPage ctor adopts it, RuntimeTracePage reads it to show
    // the "← Back to Wizard" button. Cleared on FinishWizard or Discard.
    public DllSidecar.Core.Models.Wizard.WizardSession? CurrentWizardSession { get; set; }

    // Handoff from Wizard's ReportStage to AdvisoryPage. Wizard builds an AdvisoryContext
    // and draft markdown as part of Report; on Finish we navigate to AdvisoryPage which
    // would otherwise rebuild from scratch — losing the user's edits AND failing for
    // phantom-only flows where CurrentAnalysis is null. AdvisoryPage adopts these on
    // arrival and clears them.
    public DllSidecar.Core.Models.Advisory.AdvisoryContext? PendingAdvisoryContext { get; set; }
    public string? PendingAdvisoryMarkdown { get; set; }

    // Set when the user opens an advisory from AdvisoryLibraryPage → AdvisoryPage knows
    // to update the existing record on "Save to Library" instead of creating a new row.
    public string? PendingAdvisoryRecordId { get; set; }

    // Selection focus consumed by AttackPathPage. ScanPage sets it on row selection
    // (full SideloadCandidate / PhantomCandidate available); RuntimeTracePage sets
    // it on row selection (looks up the matching candidate from LastScanResults if
    // present, otherwise focus carries DLL name + runtime evidence only and the
    // attack-path renders a degraded view). Null → AttackPathPage shows empty state.
    public AttackPathFocus? CurrentAttackFocus { get; set; }
    public enum AttackFocusSource { Scan, RuntimeTrace }
    public record AttackPathFocus(
        AttackFocusSource Source,
        string DllName,
        string? DllPath,
        Core.Models.SideloadCandidate? Candidate,
        Core.Models.PhantomCandidate? Phantom,
        string? RuntimeProcess = null,
        int RuntimeEventCount = 0);

    // Active renderer id ("markdown" / "incibe" / "ghsa") to restore when reopening an
    // advisory. Without this, AdvisoryPage always boots with Markdown selected and any
    // RerenderEditor() (Template Fields apply, Vendor edit, combo change) silently
    // overwrites the editor with Markdown — losing INCIBE/GHSA bodies.
    public string? PendingAdvisoryTemplateId { get; set; }

    // Sidebar collapse state — bound via RelativeSource in XAML to toggle label visibility.
    public static readonly DependencyProperty IsSidebarExpandedProperty =
        DependencyProperty.Register(nameof(IsSidebarExpanded), typeof(bool), typeof(MainWindow),
            new PropertyMetadata(true));

    public bool IsSidebarExpanded
    {
        get => (bool)GetValue(IsSidebarExpandedProperty);
        set => SetValue(IsSidebarExpandedProperty, value);
    }

    private const double SidebarExpandedWidth = 220;
    private const double SidebarCollapsedWidth = 56;

    // Log row sizing memory — lets the expand button toggle between user's chosen size and
    // a full-height view of the log panel.
    private GridLength? _savedLogHeight;
    private int _logLineCount;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Closing += OnClosing;
        // Route every Core log entry into the UI panel. Warn+ is visible; Debug stays in
        // the event stream only (inspectable if needed for diagnostics).
        CoreLog.Emitted += OnLogEmitted;
        Closed += (_, _) => CoreLog.Emitted -= OnLogEmitted;

        // Ctrl+B toggles the sidebar
        var toggleBinding = new KeyBinding(
            new RelayCommand(_ => SidebarToggle_Click(this, new RoutedEventArgs())),
            Key.B, ModifierKeys.Control);
        InputBindings.Add(toggleBinding);

        // Wizard is the recommended starting point — guided pipeline that hands
        // off to Analyze/Scan/Runtime as needed. Power users with a specific
        // tool in mind navigate directly via the sidebar.
        NavigateTo(new Views.Wizard.WizardPage(this));
    }

    private void OnLogEmitted(LogEntry entry)
    {
        if (entry.Level < LogLevel.Info) return;
        var prefix = entry.Level switch
        {
            LogLevel.Error => "ERR",
            LogLevel.Warn => "WRN",
            LogLevel.Info => "INF",
            _ => "DBG",
        };
        var msg = $"[{prefix}][{entry.Category}] {entry.Message}";
        if (entry.Exception != null) msg += $"  — {entry.Exception.GetType().Name}: {entry.Exception.Message}";
        Log(msg);
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Restore console panel height from persisted UI state. Default in
        // AppConfig is 32 (collapsed) so first-run users see the console as
        // a thin bottom strip, not an oversized sink.
        var saved = ConfigManager.Current.UiState.ConsoleHeight;
        if (saved >= 32 && saved < ActualHeight) // sanity bound
            LogRow.Height = new GridLength(saved);

        // Sidebar attribution — prefix with the configured researcher handle when set
        // ("@johndoe · BugAInters 2026"), otherwise drop the prefix so a fresh install
        // doesn't show the maintainer's identity. The project name stays as the
        // anchor in either case.
        var handle = ConfigManager.Current.Researcher.Handle?.Trim();
        SidebarAttribution.Text = string.IsNullOrEmpty(handle)
            ? "BugAInters 2026"
            : $"{handle} · BugAInters 2026";

        var gcc64 = BuildSystem.FindGcc("x64");
        var gcc32 = BuildSystem.FindGcc("x86");
        StatusGcc.Text = gcc64 != null ? "GCC X64 — OK" : gcc32 != null ? "GCC X86 — OK" : "GCC — MISSING";
        StatusGcc.Foreground = new SolidColorBrush(
            gcc64 != null || gcc32 != null ? Color.FromRgb(0x00, 0xCA, 0x4E) : Color.FromRgb(0xFF, 0x5B, 0x4F));

        var windres = BuildSystem.FindWindres("x64") ?? BuildSystem.FindWindres("x86");
        StatusWindres.Text = windres != null ? "WINDRES — OK" : "WINDRES — MISSING";
        StatusWindres.Foreground = new SolidColorBrush(
            windres != null ? Color.FromRgb(0x00, 0xCA, 0x4E) : Color.FromRgb(0xFF, 0x5B, 0x4F));

        Log("DllSidecar GUI started");

        // Proactive MinGW toolchain check. Fires once per session AFTER the
        // shell is visible so the warning dialog has a real owner. No-op
        // when both gcc x64 and x86 resolve; otherwise pops a modal that
        // links to the README's compiler-setup section. Researchers using
        // analysis-only features (Analyze, Scan, ETW, Advisories) can
        // dismiss and proceed — only Generate/Build paths actually need it.
        Dispatcher.BeginInvoke(new Action(() => CompilerHealthCheck.WarnIfMissing(this)),
            System.Windows.Threading.DispatcherPriority.ApplicationIdle);
    }

    // Suppresses the exit confirmation when we already asked the user once
    // in this close cycle (Cancel-then-no path) or when the close is being
    // forced programmatically. Reset implicit because the window is disposed
    // after a successful close, so there's no "next time" within this process.
    private bool _exitConfirmed;

    /// <summary>
    /// Two responsibilities on close:
    ///   1. Ask the user to confirm — accidental Alt+F4 / red-X clicks have
    ///      eaten enough in-progress wizard/scan state to warrant a prompt.
    ///   2. Persist the console panel height so the drag-resize choice (or
    ///      the collapsed default) survives across sessions.
    /// Confirmation runs first because there's no point persisting if the
    /// user is going to cancel and keep working.
    /// </summary>
    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_exitConfirmed)
        {
            var r = MessageBox.Show(this,
                "Are you sure you want to exit?\n\n" +
                "Unsaved scan results, wizard progress, and runtime trace events " +
                "will be lost. Configuration (paths, defaults) is already persisted.",
                "Exit DllSidecar",
                MessageBoxButton.YesNo, MessageBoxImage.Question,
                MessageBoxResult.No);
            if (r != MessageBoxResult.Yes)
            {
                e.Cancel = true;
                return;
            }
            _exitConfirmed = true;
        }

        try
        {
            // GridLength.Value is "*" weight or pixels. We always use absolute
            // pixels for LogRow so this is the height in DIPs.
            var h = LogRow.Height.IsAbsolute ? LogRow.Height.Value : LogRow.ActualHeight;
            if (h >= 32) ConfigManager.Current.UiState.ConsoleHeight = h;
            ConfigManager.Save();
        }
        catch { /* best-effort persist; never block close */ }
    }

    public void NavigateTo(System.Windows.Controls.Page page)
    {
        ContentFrame.Navigate(page);
        SetActiveNavForPage(page);
    }

    /// <summary>
    /// Light up the sidebar entry that corresponds to the navigated page.
    /// Pages reachable only from the Tools popup (Build, Config) intentionally
    /// fall through to "no match" — they're not part of the main rail and
    /// shouldn't activate any sidebar item.
    /// </summary>
    private void SetActiveNavForPage(System.Windows.Controls.Page page)
    {
        // FQN on Button — UseWindowsForms=true makes the bare 'Button' type
        // ambiguous between WPF and WinForms in this project.
        System.Windows.Controls.Button? active = page switch
        {
            Views.Wizard.WizardPage    => NavBtnWizard,
            AnalyzePage                => NavBtnAnalyze,
            ScanPage                   => NavBtnScan,
            ProcmonPage                => NavBtnProcmon,
            RuntimeTracePage           => NavBtnRuntime,
            PrivescPage                => NavBtnPrivesc,
            AttackPathPage             => NavBtnAttackPath,
            GeneratePage               => NavBtnDllTechniques,
            AdvisoryPage               => NavBtnAdvisory,
            AdvisoryLibraryPage        => NavBtnAdvisoryLibrary,
            _                          => null,
        };
        System.Windows.Controls.Button[] all =
        [
            NavBtnWizard, NavBtnAnalyze, NavBtnScan, NavBtnProcmon, NavBtnRuntime,
            NavBtnPrivesc, NavBtnAttackPath, NavBtnDllTechniques, NavBtnAdvisory, NavBtnAdvisoryLibrary
        ];
        foreach (var b in all) b.Tag = ReferenceEquals(b, active) ? "active" : null;
    }

    public void Log(string message)
    {
        Dispatcher.Invoke(() =>
        {
            LogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
            LogBox.ScrollToEnd();
            _logLineCount++;
            LogLineCount.Text = $"{_logLineCount} line{(_logLineCount == 1 ? "" : "s")}";
        });
    }

    // ---------- Sidebar toggle ----------

    private void SidebarToggle_Click(object sender, RoutedEventArgs e)
    {
        IsSidebarExpanded = !IsSidebarExpanded;
        SidebarCol.Width = new GridLength(IsSidebarExpanded ? SidebarExpandedWidth : SidebarCollapsedWidth);
        SidebarToggle.ToolTip = IsSidebarExpanded ? "Collapse sidebar (Ctrl+B)" : "Expand sidebar (Ctrl+B)";
    }

    // ---------- Log panel controls ----------

    private void LogExpand_Click(object sender, RoutedEventArgs e)
    {
        // Toggle between saved height and "max" (80% of window content area).
        // Column definition row 0 has MinHeight=160 so we can't consume it fully; go close.
        if (_savedLogHeight == null)
        {
            _savedLogHeight = LogRow.Height;
            LogRow.Height = new GridLength(ActualHeight * 0.7);
        }
        else
        {
            LogRow.Height = _savedLogHeight.Value;
            _savedLogHeight = null;
        }
    }

    private void LogClear_Click(object sender, RoutedEventArgs e)
    {
        LogBox.Clear();
        _logLineCount = 0;
        LogLineCount.Text = "0 lines";
    }

    private void ToolsDropdown_Click(object sender, RoutedEventArgs e)
    {
        ToolsPopup.IsOpen = !ToolsPopup.IsOpen;
    }

    private void HelpDropdown_Click(object sender, RoutedEventArgs e)
    {
        HelpPopup.IsOpen = !HelpPopup.IsOpen;
    }

    private void NavReadDocs_Click(object sender, RoutedEventArgs e)
    {
        HelpPopup.IsOpen = false;
        Helpers.SafeUrl.Open("https://github.com/tunelko/DllSideCar");
    }

    private void NavCheckUpdates_Click(object sender, RoutedEventArgs e)
    {
        HelpPopup.IsOpen = false;
        // Placeholder until the auto-update channel ships. Keeping the entry visible
        // so the menu shape stabilises now and we just wire the network call later.
        MessageBox.Show(this,
            "Update check is not implemented yet.\n\nLatest releases will be published at:\nhttps://github.com/tunelko/DllSideCar/releases",
            "Check for updates",
            MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void NavAbout_Click(object sender, RoutedEventArgs e)
    {
        HelpPopup.IsOpen = false;
        var dlg = new Views.AboutDialog { Owner = this };
        dlg.ShowDialog();
    }

    // ---------- Nav handlers ----------

    private void NavAnalyze_Click(object sender, RoutedEventArgs e) => NavigateTo(new AnalyzePage(this));
    private void NavScan_Click(object sender, RoutedEventArgs e) => NavigateTo(new ScanPage(this));
    private void NavProcmon_Click(object sender, RoutedEventArgs e) => NavigateTo(new ProcmonPage(this));
    private void NavDllTechniques_Click(object sender, RoutedEventArgs e) => NavigateTo(new GeneratePage(this));
    private void NavBuild_Click(object sender, RoutedEventArgs e) { ToolsPopup.IsOpen = false; NavigateTo(new BuildPage(this)); }
    private void NavPrivesc_Click(object sender, RoutedEventArgs e) => NavigateTo(new PrivescPage(this));
    private void NavAttackPath_Click(object sender, RoutedEventArgs e) => NavigateTo(new AttackPathPage(this));
    private void NavAdvisory_Click(object sender, RoutedEventArgs e) => NavigateTo(new AdvisoryPage(this));
    private void NavAdvisoryLibrary_Click(object sender, RoutedEventArgs e) => NavigateTo(new AdvisoryLibraryPage(this));
    private void NavWizard_Click(object sender, RoutedEventArgs e) => NavigateTo(new Views.Wizard.WizardPage(this));
    private void NavConfig_Click(object sender, RoutedEventArgs e) { ToolsPopup.IsOpen = false; NavigateTo(new ConfigPage(this)); }
    private void NavRuntimeTrace_Click(object sender, RoutedEventArgs e) => NavigateTo(new RuntimeTracePage(this));
    private void NavToolkit_Click(object sender, RoutedEventArgs e) { ToolsPopup.IsOpen = false; NavigateTo(new ToolkitPage(this)); }

    // Minimal ICommand impl for the Ctrl+B binding — avoids pulling in CommunityToolkit just for this.
    private sealed class RelayCommand : ICommand
    {
        private readonly Action<object?> _action;
        public RelayCommand(Action<object?> action) => _action = action;
        public bool CanExecute(object? parameter) => true;
        public void Execute(object? parameter) => _action(parameter);
        public event EventHandler? CanExecuteChanged { add { } remove { } }
    }

    // ---------- Frameless window controls ----------

    private void MinBtn_Click(object sender, RoutedEventArgs e)
        => WindowState = WindowState.Minimized;

    private void MaxBtn_Click(object sender, RoutedEventArgs e)
        => WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal : WindowState.Maximized;

    private void CloseBtn_Click(object sender, RoutedEventArgs e) => Close();

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        // □ maximize, ❐ restore glyph (U+2750)
        if (MaxBtnGlyph != null)
            MaxBtnGlyph.Text = WindowState == WindowState.Maximized ? "❐" : "□";
        if (MaxBtn != null)
            MaxBtn.ToolTip = WindowState == WindowState.Maximized ? "Restore" : "Maximize";
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == IntPtr.Zero) return;

        // Win11: request rounded window corners via DWM. No-op on Win10 (returns HRESULT
        // failure, which we ignore) — Win10 renders square corners on WindowStyle=None
        // which is acceptable until the user upgrades.
        try
        {
            int pref = DWMWCP_ROUND;
            DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref pref, sizeof(int));
        }
        catch { /* pre-Win11, DwmSetWindowAttribute returns error for this attribute */ }

        // WM_GETMINMAXINFO: clamp maximize to working area so the frameless window
        // doesn't cover the taskbar or spill past screen edges on multi-monitor setups.
        HwndSource.FromHwnd(hwnd)?.AddHook(WndProc);
    }

    private const int WM_GETMINMAXINFO = 0x0024;
    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWCP_ROUND = 2;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, int flags);

    [DllImport("user32.dll")]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    private const int MONITOR_DEFAULTTONEAREST = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public int dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X, Y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MINMAXINFO
    {
        public POINT ptReserved;
        public POINT ptMaxSize;
        public POINT ptMaxPosition;
        public POINT ptMinTrackSize;
        public POINT ptMaxTrackSize;
    }

    private static IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg != WM_GETMINMAXINFO) return IntPtr.Zero;

        var mi = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
        var hMon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        if (hMon == IntPtr.Zero || !GetMonitorInfo(hMon, ref mi)) return IntPtr.Zero;

        var mmi = Marshal.PtrToStructure<MINMAXINFO>(lParam);
        mmi.ptMaxPosition.X  = mi.rcWork.Left - mi.rcMonitor.Left;
        mmi.ptMaxPosition.Y  = mi.rcWork.Top  - mi.rcMonitor.Top;
        mmi.ptMaxSize.X      = mi.rcWork.Right  - mi.rcWork.Left;
        mmi.ptMaxSize.Y      = mi.rcWork.Bottom - mi.rcWork.Top;
        Marshal.StructureToPtr(mmi, lParam, true);
        handled = true;
        return IntPtr.Zero;
    }
}
