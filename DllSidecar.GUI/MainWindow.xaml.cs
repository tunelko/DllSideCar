using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Wizard;
using DllSidecar.Core.Services;
using DllSidecar.Core.Services.Wizard;
using DllSidecar.GUI.Views;
using CoreLog = DllSidecar.Core.Logging.Log;
using LogEntry = DllSidecar.Core.Logging.LogEntry;
using LogLevel = DllSidecar.Core.Logging.LogLevel;

namespace DllSidecar.GUI;

public partial class MainWindow : Window
{
    public Core.Models.PeAnalysis? CurrentAnalysis { get; set; }
    public string? CurrentDllPath { get; set; }

    // Deploy context for phantom-driven GeneratePage flows; null on manual nav.
    public DeployContext? PendingDeployContext { get; set; }
    public record DeployContext(
        string TargetDir,
        string TargetName,
        string HostExePath,
        string? SystemOrigPath = null,
        Core.Models.GenerationMode? AutoMode = null,
        int AutoExportCount = 0);

    // Carrier handoff from ProcmonPage/RuntimeTracePage banner to PrivescPage; null on manual nav.
    public PrivescCarrierHandoff? PendingPrivescHandoff { get; set; }
    public record PrivescCarrierHandoff(
        string SourceLabel,
        IReadOnlyList<DllSidecar.Core.Services.PrivescCarrier> Carriers,
        string TransitionSummary);

    // Session state preserved across navigation.
    public DllSidecar.Core.Services.ScanResults? LastScanResults { get; set; }
    public string? LastScanDir { get; set; }
    public DllSidecar.Core.Models.EtwTraceResult? LastEtwResult { get; set; }
    public DllSidecar.Core.Services.ProcmonParser.ParseResult? LastProcmonResult { get; set; }
    public string? LastProcmonCsvPath { get; set; }

    public DllSidecar.Core.Models.CallsiteScanResult? LastCallsiteResult { get; set; }
    public DllSidecar.Core.Services.Exploitability.ExploitabilityVerdict? LastExploitabilityVerdict { get; set; }
    public string? LastRuntimeLaunchExe { get; set; }

    // Live trace session owned by MainWindow so navigation doesn't kill it.
    public DllSidecar.Core.Services.EtwDllTracer? ActiveTracer { get; private set; }
    public CancellationTokenSource? ActiveTraceCts { get; private set; }
    public System.Diagnostics.Stopwatch? ActiveTraceStopwatch { get; private set; }
    public string? ActiveTraceMode { get; private set; }
    private int _activeTraceLiveCount;
    public int ActiveTraceLiveCount => _activeTraceLiveCount;
    public bool IsTraceActive => ActiveTracer != null;

    // Relay events; pages subscribe here to avoid leaking handlers into the tracer.
    public event Action<DllSidecar.Core.Models.EtwTraceEvent>? TraceEventCaptured;
    public event Action<DllSidecar.Core.Models.TracedProcess>? TraceProcessDetected;
    public event Action<string>? TraceStatusChanged;

    public void StartActiveTrace(DllSidecar.Core.Services.EtwDllTracer tracer,
                                 CancellationTokenSource cts, string mode)
    {
        ActiveTracer = tracer;
        ActiveTraceCts = cts;
        ActiveTraceMode = mode;
        ActiveTraceStopwatch = System.Diagnostics.Stopwatch.StartNew();
        System.Threading.Interlocked.Exchange(ref _activeTraceLiveCount, 0);
        tracer.EventCaptured += OnTracerEvent;
        tracer.ProcessDetected += OnTracerProcess;
        tracer.StatusChanged += OnTracerStatus;
    }

    public DllSidecar.Core.Models.EtwTraceResult? StopAndDisposeActiveTrace()
    {
        if (ActiveTracer == null) return null;
        var tracer = ActiveTracer;
        tracer.EventCaptured -= OnTracerEvent;
        tracer.ProcessDetected -= OnTracerProcess;
        tracer.StatusChanged -= OnTracerStatus;
        DllSidecar.Core.Models.EtwTraceResult? result = null;
        try { result = tracer.Stop(); }
        finally
        {
            tracer.Dispose();
            ActiveTracer = null;
            ActiveTraceCts?.Dispose();
            ActiveTraceCts = null;
            ActiveTraceStopwatch?.Stop();
            ActiveTraceStopwatch = null;
            ActiveTraceMode = null;
        }
        return result;
    }

    private void OnTracerEvent(DllSidecar.Core.Models.EtwTraceEvent ev)
    {
        System.Threading.Interlocked.Increment(ref _activeTraceLiveCount);
        TraceEventCaptured?.Invoke(ev);
    }
    private void OnTracerProcess(DllSidecar.Core.Models.TracedProcess p) => TraceProcessDetected?.Invoke(p);
    private void OnTracerStatus(string s) => TraceStatusChanged?.Invoke(s);

    // Live wizard session; cleared on FinishWizard or Discard.
    public DllSidecar.Core.Models.Wizard.WizardSession? CurrentWizardSession { get; set; }

    // Handoff from Wizard ReportStage to AdvisoryPage; adopted and cleared on arrival.
    public DllSidecar.Core.Models.Advisory.AdvisoryContext? PendingAdvisoryContext { get; set; }
    public string? PendingAdvisoryMarkdown { get; set; }

    // Set when opening an advisory from AdvisoryLibraryPage so Save updates instead of inserts.
    public string? PendingAdvisoryRecordId { get; set; }

    // Selection focus consumed by AttackPathPage.
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

    // Active renderer id ("markdown" / "ghsa") to restore when reopening an advisory.
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

    // Log row sizing memory for the expand toggle.
    private GridLength? _savedLogHeight;
    private int _logLineCount;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Closing += OnClosing;
        // Route Core log entries (Warn+) into the UI panel.
        CoreLog.Emitted += OnLogEmitted;
        Closed += (_, _) => CoreLog.Emitted -= OnLogEmitted;

        // Ctrl+B toggles the sidebar
        var toggleBinding = new KeyBinding(
            new RelayCommand(_ => SidebarToggle_Click(this, new RoutedEventArgs())),
            Key.B, ModifierKeys.Control);
        InputBindings.Add(toggleBinding);

        // Silent session restore on launch; falls back to Welcome or Wizard.
        var resumed = TryRestoreSession();
        if (resumed != null)
        {
            NavigateTo(resumed);
        }
        else if (!Core.Configuration.ConfigManager.Current.WelcomeSeen)
        {
            NavigateTo(new Views.WelcomePage(this));
        }
        else
        {
            NavigateTo(new Views.Wizard.WizardPage(this));
        }
    }

    // ---------- Session save / restore ----------

    /// <summary>Last navigated page name, written into the snapshot on close.</summary>
    public string? CurrentPageName { get; private set; }

    private static string? GetPageName(System.Windows.Controls.Page page) => page switch
    {
        Views.Wizard.WizardPage => "Wizard",
        AnalyzePage             => "Analyze",
        ScanPage                => "Scan",
        ProcmonPage             => "Procmon",
        RuntimeTracePage        => "RuntimeTrace",
        PrivescPage             => "Privesc",
        AttackPathPage          => "AttackPath",
        GeneratePage            => "Generate",
        AdvisoryPage            => "Advisory",
        AdvisoryLibraryPage     => "AdvisoryLibrary",
        ConfigPage              => "Config",
        ToolkitPage             => "Toolkit",
        Views.WelcomePage       => "Welcome",
        _                       => null,
    };

    private System.Windows.Controls.Page PageForName(string? name) => name switch
    {
        "Welcome"          => new Views.WelcomePage(this),
        "Analyze"          => new AnalyzePage(this),
        "Scan"             => new ScanPage(this),
        "Procmon"          => new ProcmonPage(this),
        "RuntimeTrace"     => new RuntimeTracePage(this),
        "Privesc"          => new PrivescPage(this),
        "AttackPath"       => new AttackPathPage(this),
        "Generate"         => new GeneratePage(this),
        "Advisory"         => new AdvisoryPage(this),
        "AdvisoryLibrary"  => new AdvisoryLibraryPage(this),
        "Config"           => new ConfigPage(this),
        "Toolkit"          => new ToolkitPage(this),
        _                  => new Views.Wizard.WizardPage(this),
    };

    /// <summary>Build a snapshot of the currently in-memory app state.</summary>
    private AppSessionSnapshot CaptureSnapshot() => new()
    {
        ActivePage = CurrentPageName,
        CurrentDllPath = CurrentDllPath,
        LastScanDir = LastScanDir,
        LastProcmonCsvPath = LastProcmonCsvPath,
        LastRuntimeLaunchExe = LastRuntimeLaunchExe,
        PendingAdvisoryMarkdown = PendingAdvisoryMarkdown,
        PendingAdvisoryRecordId = PendingAdvisoryRecordId,
        PendingAdvisoryTemplateId = PendingAdvisoryTemplateId,
    };

    /// <summary>Apply a snapshot to MainWindow state; loads wizard + heavy companion results.</summary>
    private void ApplySnapshot(AppSessionSnapshot snap)
    {
        CurrentDllPath = snap.CurrentDllPath;
        LastScanDir = snap.LastScanDir;
        LastProcmonCsvPath = snap.LastProcmonCsvPath;
        LastRuntimeLaunchExe = snap.LastRuntimeLaunchExe;
        PendingAdvisoryMarkdown = snap.PendingAdvisoryMarkdown;
        PendingAdvisoryRecordId = snap.PendingAdvisoryRecordId;
        PendingAdvisoryTemplateId = snap.PendingAdvisoryTemplateId;

        // ETW capture cannot be re-run silently; load from companion file.
        LastEtwResult = AppSessionStore.TryLoadEtwResult();

        // Promoted scan results survive restart via companion file.
        LastScanResults = AppSessionStore.TryLoadScanResults();

        // Adopt wizard state silently if auto-checkpoint present.
        var wsnap = WizardSessionStore.TryLoad();
        if (wsnap != null)
        {
            var restored = new WizardSession();
            WizardSessionStore.Apply(wsnap, restored);

            // Reattach scan results so wizard skips re-Survey.
            if (LastScanResults != null && restored.ScanResults == null)
                restored.ScanResults = LastScanResults;

            // Rematch chosen phantom / existing candidate (case-insensitive).
            if (LastScanResults != null)
            {
                if (!string.IsNullOrEmpty(wsnap.ChosenPhantomName)
                    && !string.IsNullOrEmpty(wsnap.ChosenPhantomDirectory))
                {
                    restored.ChosenPhantom = LastScanResults.Phantoms.FirstOrDefault(p =>
                        string.Equals(p.DllName, wsnap.ChosenPhantomName, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(p.DirectoryPath, wsnap.ChosenPhantomDirectory, StringComparison.OrdinalIgnoreCase));
                }
                if (restored.ChosenPhantom == null
                    && !string.IsNullOrEmpty(wsnap.ChosenExistingFilename)
                    && !string.IsNullOrEmpty(wsnap.ChosenExistingPath))
                {
                    restored.ChosenExisting = LastScanResults.Existing.FirstOrDefault(c =>
                        string.Equals(c.Dll.Filename, wsnap.ChosenExistingFilename, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(c.Dll.Path, wsnap.ChosenExistingPath, StringComparison.OrdinalIgnoreCase));
                }
            }

            CurrentWizardSession = restored;
        }
    }

    /// <summary>Returns the Page to navigate to on launch, or null when nothing to restore.</summary>
    private System.Windows.Controls.Page? TryRestoreSession()
    {
        try
        {
            var snap = AppSessionStore.TryLoad();
            // No app snapshot; wizard checkpoint may still exist.
            if (snap == null)
            {
                if (!WizardSessionStore.HasSession()) return null;
                ApplySnapshot(new AppSessionSnapshot()); // adopts wizard only
                CurrentPageName = "Wizard";
                Log($"Wizard checkpoint restored from {WizardSessionStore.FilePath}");
                return new Views.Wizard.WizardPage(this);
            }

            ApplySnapshot(snap);
            var page = PageForName(snap.ActivePage);
            CurrentPageName = GetPageName(page);
            var savedAt = snap.SavedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            var etw = LastEtwResult != null ? $", trace ({LastEtwResult.FilteredEvents} events)" : "";
            var scan = LastScanResults != null
                ? $", scan ({LastScanResults.ExistingCount} existing + {LastScanResults.PhantomCount} phantoms)"
                : "";
            Log($"Session restored from {AppSessionStore.FilePath} (saved {savedAt}{etw}{scan}) → {snap.ActivePage ?? "Wizard"}");
            return page;
        }
        catch (Exception ex)
        {
            CoreLog.Warn("session.restore", "Restore failed", ex);
            return null;
        }
    }

    /// <summary>Public hook for File→Open Session and File→Delete Session.</summary>
    public void RestoreSessionFromDisk()
    {
        if (!AppSessionStore.HasSession() && !WizardSessionStore.HasSession())
        {
            MessageBox.Show(this, "No saved session was found.",
                "Open session", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var page = TryRestoreSession();
        if (page != null) NavigateTo(page);
        Log("Session restored from disk.");
    }

    public void DeleteSavedSession()
    {
        // Wipes on-disk snapshot AND in-memory state.
        AppSessionStore.DeleteAll();
        CurrentWizardSession = null;
        CurrentAnalysis = null;
        CurrentDllPath = null;
        LastScanResults = null;
        LastScanDir = null;
        LastEtwResult = null;
        LastProcmonResult = null;
        LastProcmonCsvPath = null;
        LastCallsiteResult = null;
        LastExploitabilityVerdict = null;
        LastRuntimeLaunchExe = null;
        PendingAdvisoryContext = null;
        PendingAdvisoryMarkdown = null;
        PendingAdvisoryRecordId = null;
        PendingAdvisoryTemplateId = null;
        PendingDeployContext = null;
        PendingPrivescHandoff = null;
        CurrentAttackFocus = null;
        Log("Session deleted (in-memory state and saved snapshot cleared).");
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
        // Restore console panel height (default 32 = collapsed).
        var saved = ConfigManager.Current.UiState.ConsoleHeight;
        if (saved >= 32 && saved < ActualHeight) // sanity bound
            LogRow.Height = new GridLength(saved);

        SidebarVersion.Text = DllSidecar.Core.AppInfo.VersionDisplay;

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

        // Proactive MinGW toolchain check; fires once after shell is visible.
        Dispatcher.BeginInvoke(new Action(() => CompilerHealthCheck.WarnIfMissing(this)),
            System.Windows.Threading.DispatcherPriority.ApplicationIdle);
    }

    // Guards against re-entrant close prompts.
    private bool _exitConfirmed;

    /// <summary>Prompt on close to save / discard / cancel; persist console height.</summary>
    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_exitConfirmed)
        {
            var r = AppDialog.ShowCustom(this,
                "A session will be restored in the next application restart.",
                "Save the current session?",
                yesLabel: "Yes, Store",
                noLabel: "No, Discard",
                cancelLabel: "Cancel, Stay",
                MessageBoxImage.Question,
                MessageBoxResult.Yes);

            switch (r)
            {
                case MessageBoxResult.Yes:
                    try
                    {
                        AppSessionStore.Save(CaptureSnapshot());
                        AppSessionStore.SaveEtwResult(LastEtwResult);
                        AppSessionStore.SaveScanResults(LastScanResults);
                        // Final wizard checkpoint captures edits since last stage transition.
                        if (CurrentWizardSession != null)
                            WizardSessionStore.Save(CurrentWizardSession);
                        CoreLog.Info("session.save", $"Session saved to {AppSessionStore.FilePath}");
                    }
                    catch (Exception ex) { CoreLog.Warn("session.save", "Save failed", ex); }
                    break;
                case MessageBoxResult.No:
                    try { AppSessionStore.DeleteAll(); }
                    catch (Exception ex) { CoreLog.Warn("session.delete", "Delete failed", ex); }
                    break;
                default:
                    e.Cancel = true;
                    return;
            }
            _exitConfirmed = true;
        }

        try
        {
            var h = LogRow.Height.IsAbsolute ? LogRow.Height.Value : LogRow.ActualHeight;
            if (h >= 32) ConfigManager.Current.UiState.ConsoleHeight = h;
            ConfigManager.Save();
        }
        catch { /* best-effort persist; never block close */ }
    }

    public void NavigateTo(System.Windows.Controls.Page page)
    {
        CurrentPageName = GetPageName(page);
        ContentFrame.Navigate(page);
        SetActiveNavForPage(page);
    }

    /// <summary>Light up the sidebar entry for the navigated page.</summary>
    private void SetActiveNavForPage(System.Windows.Controls.Page page)
    {
        // FQN on Button — UseWindowsForms=true makes bare 'Button' ambiguous.
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
        // Toggle between saved height and ~70% of window.
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

    private void FileDropdown_Click(object sender, RoutedEventArgs e)
    {
        FilePopup.IsOpen = !FilePopup.IsOpen;
    }

    private void OpenSessionMenu_Click(object sender, RoutedEventArgs e)
    {
        FilePopup.IsOpen = false;
        RestoreSessionFromDisk();
    }

    private void DeleteSessionMenu_Click(object sender, RoutedEventArgs e)
    {
        FilePopup.IsOpen = false;
        var r = MessageBox.Show(this,
            "Delete the current session?\n\n" +
            "This clears the in-memory state (open PE, scan results, wizard progress, " +
            "advisory draft) and removes any saved snapshot. The action cannot be undone.",
            "Delete session",
            MessageBoxButton.YesNo, MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (r == MessageBoxResult.Yes) DeleteSavedSession();
    }

    private void NavReadDocs_Click(object sender, RoutedEventArgs e)
    {
        HelpPopup.IsOpen = false;
        Helpers.SafeUrl.Open("https://github.com/tunelko/DllSideCar");
    }

    private void NavCheckUpdates_Click(object sender, RoutedEventArgs e)
    {
        HelpPopup.IsOpen = false;
        // Placeholder until auto-update channel ships.
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

    private void NavReference_Click(object sender, RoutedEventArgs e)
    {
        HelpPopup.IsOpen = false;
        var dlg = new Views.ReferenceDialog { Owner = this };
        dlg.ShowDialog();
    }

    private void NavStartTour_Click(object sender, RoutedEventArgs e)
    {
        HelpPopup.IsOpen = false;
        // End any running tour before starting a fresh one.
        _tourController?.End();
        _tourController = new Views.HelpTour.HelpTourController(this, TourOverlay);
        _tourController.Start();
    }

    private Views.HelpTour.HelpTourController? _tourController;

    // ---------- Nav handlers ----------

    private void NavAnalyze_Click(object sender, RoutedEventArgs e) => NavigateTo(new AnalyzePage(this));
    private void NavScan_Click(object sender, RoutedEventArgs e) => NavigateTo(new ScanPage(this));
    private void NavProcmon_Click(object sender, RoutedEventArgs e) => NavigateTo(new ProcmonPage(this));
    private void NavDllTechniques_Click(object sender, RoutedEventArgs e) => NavigateTo(new GeneratePage(this));
    private void NavPrivesc_Click(object sender, RoutedEventArgs e) => NavigateTo(new PrivescPage(this));
    private void NavAttackPath_Click(object sender, RoutedEventArgs e) => NavigateTo(new AttackPathPage(this));
    private void NavAdvisory_Click(object sender, RoutedEventArgs e) => NavigateTo(new AdvisoryPage(this));
    private void NavAdvisoryLibrary_Click(object sender, RoutedEventArgs e) => NavigateTo(new AdvisoryLibraryPage(this));
    private void NavWizard_Click(object sender, RoutedEventArgs e) => NavigateTo(new Views.Wizard.WizardPage(this));
    private void NavConfig_Click(object sender, RoutedEventArgs e) { ToolsPopup.IsOpen = false; NavigateTo(new ConfigPage(this)); }
    private void NavRuntimeTrace_Click(object sender, RoutedEventArgs e) => NavigateTo(new RuntimeTracePage(this));
    private void NavToolkit_Click(object sender, RoutedEventArgs e) { ToolsPopup.IsOpen = false; NavigateTo(new ToolkitPage(this)); }

    // Minimal ICommand for the Ctrl+B binding.
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

        // Win11: request rounded corners via DwmSetWindowAttribute (no-op on Win10).
        try
        {
            int pref = DWMWCP_ROUND;
            DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref pref, sizeof(int));
        }
        catch { /* pre-Win11 returns error for this attribute */ }

        // WM_GETMINMAXINFO: clamp maximize to working area.
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
