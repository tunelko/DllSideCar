using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Microsoft.Win32;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

public partial class RuntimeTracePage : Page
{
    private readonly MainWindow _main;
    private EtwTraceResult? _lastResult;
    private readonly List<TraceRow> _allRows = [];
    private readonly List<TraceRow> _rows = [];
    private readonly List<ProcessTreeNode> _treeNodes = [];
    // When non-null, only DLL events whose ProcessId is in this set are shown.
    // Set by ProcessTree_Selected; cleared by the × chip.
    private HashSet<int>? _processFilterPids;
    private DispatcherTimer? _elapsedTimer;
    // Populated by ProcessPickerDialog; drives Attach-mode Start.
    private int? _attachPid;
    private string? _attachProcName;
    // True once we've wired ourselves to MainWindow's relay events. Guarded so
    // a re-Loaded page doesn't double-subscribe (e.g. if the user toggles to a
    // different tab and back within the same Frame).
    private bool _subscribedToLiveTrace;

    public RuntimeTracePage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        // Subscribe / unsubscribe with the page's actual Loaded/Unloaded lifecycle
        // so handlers are cleaned up when WPF navigates away. The tracer itself
        // lives on MainWindow and is NOT disposed here — that's why the REC pulse
        // and stats survive a detour to ConfigPage / AnalyzePage.
        Loaded   += (_, _) => AdoptLiveTraceIfRunning();
        Unloaded += (_, _) => ReleaseLiveTraceHandlers();

        // Fire-and-forget swallows exceptions on its own — guard the body with a
        // try/catch so any restore-time crash (deserialization mismatch, null in
        // a field PopulateResults touches) reaches the user-facing log instead
        // of leaving them staring at an empty page with no breadcrumb.
        _ = InitAsync().ContinueWith(t =>
        {
            if (t.IsFaulted && t.Exception != null)
                _main.Log($"RuntimeTrace init failed: {t.Exception.InnerException?.GetType().Name}: {t.Exception.InnerException?.Message}");
        }, TaskScheduler.FromCurrentSynchronizationContext());
    }

    /// <summary>If a live trace is in progress on MainWindow, restore the UI to
    /// the "recording" state and start consuming relay events again. Called on
    /// every page Load — when the user navigates to RuntimeTracePage and a
    /// trace is already running (started earlier, then nav'd away), the page
    /// re-attaches transparently.</summary>
    private void AdoptLiveTraceIfRunning()
    {
        if (!_main.IsTraceActive) return;
        if (!_subscribedToLiveTrace)
        {
            _main.TraceEventCaptured  += OnEventCaptured;
            _main.TraceProcessDetected += OnProcessDetected;
            _main.TraceStatusChanged  += OnStatusChanged;
            _subscribedToLiveTrace = true;
        }
        EnterRecordingUi();
    }

    private void ReleaseLiveTraceHandlers()
    {
        if (_subscribedToLiveTrace)
        {
            _main.TraceEventCaptured  -= OnEventCaptured;
            _main.TraceProcessDetected -= OnProcessDetected;
            _main.TraceStatusChanged  -= OnStatusChanged;
            _subscribedToLiveTrace = false;
        }
        _elapsedTimer?.Stop();
        _elapsedTimer = null;
        // NB: do not touch _main.ActiveTracer — the trace continues running
        // until the user clicks Stop (or closes the app).
    }

    private async Task InitAsync()
    {
        Overlay.Show("Loading", "Preparing trace page...");
        try
        {
            await Task.Delay(50);
            UpdateModeUi();

            // Restore Launch target. MainWindow memory wins if set (current session),
            // otherwise fall back to the cross-restart persisted path from AppConfig.
            if (!string.IsNullOrEmpty(_main.LastRuntimeLaunchExe))
                TargetBox.Text = _main.LastRuntimeLaunchExe;
            else if (!string.IsNullOrEmpty(ConfigManager.Current.UiState.LastRuntimeExePath))
                TargetBox.Text = ConfigManager.Current.UiState.LastRuntimeExePath;
            TargetBox.TextChanged += (_, _) =>
            {
                _main.LastRuntimeLaunchExe = TargetBox.Text;
                ConfigManager.Current.UiState.LastRuntimeExePath = TargetBox.Text?.Trim();
                ConfigManager.Save();
            };

            // "← Back to Wizard" only shows if the user got here from the wizard's
            // Runtime Trace entry point. Otherwise this is a standalone visit.
            ResumeWizardBtn.Visibility = _main.CurrentWizardSession != null
                ? Visibility.Visible : Visibility.Collapsed;
            // Same gate flips Promote's label: 'Promote to Wizard' when a wizard
            // session is alive (the action conceptually returns the user to it),
            // 'Promote to Scan' otherwise (the destination is just the Scan page).
            PromoteBtn.Content = _main.CurrentWizardSession != null
                ? "Promote to Wizard" : "Promote to Scan";

            if (_main.LastEtwResult != null)
            {
                _lastResult = _main.LastEtwResult;
                PopulateResults(_lastResult);
                var hasScan = _main.LastScanResults != null;
                PromoteBtn.IsEnabled = _allRows.Count > 0;
                CorrelateBtn.IsEnabled = _allRows.Count > 0 && hasScan;
                SetStatus(
                    $"Previous trace — {_lastResult.FilteredEvents} events, {_lastResult.ByDll.Count} DLLs, " +
                    $"{_lastResult.ProcessTree.Count} processes",
                    _lastResult.FilteredEvents > 0 ? StatusKind.Ok : StatusKind.Warn);
                _main.Log($"Runtime trace restored on page open — {_allRows.Count} aggregated rows");
            }
            else
            {
                _main.Log("RuntimeTrace opened with no in-memory trace — start a new capture or restore a saved session");
            }
        }
        finally { Overlay.Hide(); }
    }

    private void Mode_Changed(object sender, RoutedEventArgs e) => UpdateModeUi();

    private void UpdateModeUi()
    {
        if (TargetBox == null) return; // called during InitializeComponent before controls exist
        var isLaunch = ModeLaunch.IsChecked == true;
        var isAttach = ModeAttach.IsChecked == true;
        var isWatch  = ModeWatch.IsChecked == true;

        // Three swappable target editors, only one visible at a time.
        // WatchCmdRow now hosts both CMD and MATCH on a single line so a
        // single visibility toggle drives the whole Watch panel.
        TargetBox.Visibility    = isLaunch ? Visibility.Visible : Visibility.Collapsed;
        AttachPicker.Visibility = isAttach ? Visibility.Visible : Visibility.Collapsed;
        WatchNameBox.Visibility = isWatch  ? Visibility.Visible : Visibility.Collapsed;
        WatchCmdRow.Visibility  = isWatch  ? Visibility.Visible : Visibility.Collapsed;

        // Action buttons: Browse for Launch, PID picker for Attach, Service picker for Watch.
        BrowseBtn.Visibility   = isLaunch ? Visibility.Visible : Visibility.Collapsed;
        PickProcBtn.Visibility = isAttach ? Visibility.Visible : Visibility.Collapsed;
        PickSvcBtn.Visibility  = isWatch  ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "Executables|*.exe|All files|*.*",
            Title = "Select target EXE to launch and trace",
        };
        if (dlg.ShowDialog() == true) TargetBox.Text = dlg.FileName;
    }

    private static readonly string[] TraceExportHeader =
    { "Process", "DLL", "Directory", "Events", "Writable" };

    private List<string[]> BuildTraceExportRows() => _allRows.Select(r => new[]
    { r.ProcessName, r.DllName, r.Directory, r.EventCount.ToString(), r.IsWritable ? "Y" : "N" }).ToList();

    private void CopyList_Click(object sender, RoutedEventArgs e)
    {
        if (_allRows.Count == 0) { SetStatus("Nothing to copy — run a trace first", StatusKind.Warn); return; }
        if (Services.ListExporter.CopyTsv(TraceExportHeader, BuildTraceExportRows(), out var n))
            SetStatus($"Copied {n} trace rows to clipboard (TSV).", StatusKind.Ok);
        else
            SetStatus("Clipboard copy failed", StatusKind.Err);
    }

    private void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        if (_allRows.Count == 0) { SetStatus("Nothing to export — run a trace first", StatusKind.Warn); return; }
        var suggested = $"runtime-trace-{DateTime.Now:yyyyMMdd-HHmm}.csv";
        var path = Services.ListExporter.SaveCsv(TraceExportHeader, BuildTraceExportRows(), suggested);
        if (path != null)
        {
            SetStatus($"Exported {_allRows.Count} trace rows → {Path.GetFileName(path)}", StatusKind.Ok);
            _main.Log($"Runtime trace export: {path}");
        }
    }

    private void ExpandTraceDetails_Click(object sender, RoutedEventArgs e)
    {
        var host = TraceDetailsHost;
        if (host == null || host.Parent is not Border originalBorder) return;
        originalBorder.Child = null;
        ExpandTraceBtn.Visibility = Visibility.Collapsed;

        var modal = new DetailModalWindow("TRACE DETAILS", host, Window.GetWindow(this));
        modal.Closed += (_, _) =>
        {
            var content = modal.DetachContent();
            if (content is ScrollViewer back && originalBorder.Child == null)
                originalBorder.Child = back;
            ExpandTraceBtn.Visibility = Visibility.Visible;
        };
        modal.ShowDialog();
    }

    private void PickProc_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dlg = new ProcessPickerDialog { Owner = Window.GetWindow(this) };
            if (dlg.ShowDialog() != true || !dlg.SelectedPid.HasValue) return;
            _attachPid = dlg.SelectedPid;
            _attachProcName = dlg.SelectedName;
            PidChipText.Text = $"{_attachPid} · {_attachProcName}";
            PidChip.Visibility = Visibility.Visible;
        }
        catch (Exception ex)
        {
            _main.Log($"Process picker failed: {ex.GetType().Name}: {ex.Message}");
            MessageBox.Show($"{ex.GetType().Name}: {ex.Message}\n\n{ex.StackTrace}",
                "Process picker error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ClearPid_Click(object sender, RoutedEventArgs e)
    {
        _attachPid = null;
        _attachProcName = null;
        PidChip.Visibility = Visibility.Collapsed;
        PidChipText.Text = "";
    }

    private void PickSvc_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dlg = new ServicePickerDialog { Owner = Window.GetWindow(this) };
            if (dlg.ShowDialog() != true) return;
            if (string.IsNullOrEmpty(dlg.SelectedImageFile) || string.IsNullOrEmpty(dlg.SelectedServiceName))
                return;
            // Auto-fill the watch panel: image basename feeds the ETW match,
            // service name builds an idempotent restart command. Uses 'net'
            // because it's synchronous (waits for stop to finish before start),
            // and the '&' (not '&&') chain runs start even if stop failed
            // because the service was already stopped. Users can edit either.
            WatchNameBox.Text = dlg.SelectedImageFile;
            WatchCmdBox.Text = $"net stop {dlg.SelectedServiceName} & net start {dlg.SelectedServiceName}";
            // Cmd-line filter: non-empty for svchost-style shared hosts, blank
            // otherwise. Picker computes "-s ServiceName" for svchost; blank
            // means "match by image name only" which is correct for splunkd,
            // sshd, and any service with its own dedicated process.
            WatchMatchBox.Text = dlg.SelectedCmdLineFilter ?? "";
        }
        catch (Exception ex)
        {
            _main.Log($"Service picker failed: {ex.GetType().Name}: {ex.Message}");
            MessageBox.Show($"{ex.GetType().Name}: {ex.Message}\n\n{ex.StackTrace}",
                "Service picker error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Trace_Click(object sender, RoutedEventArgs e)
    {
        if (_main.IsTraceActive) { Stop_Click(sender, e); return; }
        Start_Click(sender, e);
    }

    /// <summary>
    /// True when the page or MainWindow holds the residue of an earlier trace —
    /// either an in-memory <see cref="EtwTraceResult"/> (this session) or a hydrated
    /// one restored from disk on launch, or scan results promoted from such a trace.
    /// Drives the Start_Click confirmation gate so a researcher doesn't accidentally
    /// stack a new capture on top of stale rows.
    /// </summary>
    private bool HasPreviousTraceData() =>
        _lastResult != null
        || _main.LastEtwResult != null
        || (_main.LastScanResults?.Phantoms.Count ?? 0) > 0
        || (_main.LastScanResults?.Existing.Count ?? 0) > 0;

    /// <summary>
    /// Atomic wipe of every trace-related residue: in-memory page state, the
    /// MainWindow-level handles, the persisted companion files. Wizard state
    /// is intentionally NOT touched here — that's File → Delete Session's job;
    /// a researcher mid-wizard who restarts a trace usually wants to replace
    /// the promoted candidate, not lose the rest of their wizard progress.
    /// </summary>
    private void ClearPreviousTraceData()
    {
        _lastResult = null;
        _main.LastEtwResult = null;
        _main.LastScanResults = null;
        try { Core.Services.AppSessionStore.SaveEtwResult(null); } catch { /* best effort */ }
        try { Core.Services.AppSessionStore.SaveScanResults(null); } catch { /* best effort */ }

        // Drop the page-level UI bindings too, otherwise the grids would keep
        // showing the old rows until the new tracer pushes its first event.
        _allRows.Clear();
        _rows.Clear();
        _treeNodes.Clear();
        DllGrid.ItemsSource = null;
        ProcessTree.ItemsSource = null;
        ResetStats();
    }

    private void Start_Click(object sender, RoutedEventArgs e)
    {
        // Destructive-action gate: if previous trace data (in-memory or restored
        // from disk) is present, warn before nuking it. The new trace would mix
        // with stale rows on the same page and leave a stale etw_result.json
        // sitting next to a fresh capture, so we wipe both halves atomically.
        if (HasPreviousTraceData())
        {
            var answer = MessageBox.Show(
                "Hay datos de una traza anterior cargados en la página " +
                "(eventos, árbol de procesos, candidatos promovidos a Scan).\n\n" +
                "Iniciar una nueva traza descartará todo eso para que solo " +
                "se muestre la sesión actual.\n\n¿Continuar?",
                "Descartar traza anterior",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning,
                MessageBoxResult.Cancel);
            if (answer != MessageBoxResult.OK) return;
            ClearPreviousTraceData();
        }

        var filter = new EtwTraceFilter
        {
            IncludeChildren = ChkChildren.IsChecked == true,
            DllOnly = ChkDllOnly.IsChecked == true,
            NameNotFoundOnly = ChkNotFoundOnly.IsChecked == true,
        };

        var cts = new CancellationTokenSource();
        var tracer = new EtwDllTracer(filter);

        var isLaunch = ModeLaunch.IsChecked == true;
        var isAttach = ModeAttach.IsChecked == true;
        var isWatch  = ModeWatch.IsChecked == true;
        Overlay.Show("Starting trace",
            isLaunch ? "Launching ETW session and target process..."
            : isAttach ? "Attaching to process..."
            : "Starting ETW session and firing trigger command...");

        try
        {
            if (isLaunch)
            {
                var (exePath, parsedArgs) = ParseCommandLine(TargetBox.Text);
                if (string.IsNullOrEmpty(exePath))
                {
                    SetStatus("Enter the path to an EXE", StatusKind.Err);
                    tracer.Dispose();
                    return;
                }
                if (!File.Exists(exePath))
                {
                    SetStatus($"File not found: {exePath}", StatusKind.Err);
                    tracer.Dispose();
                    return;
                }
                var args = ArgsBox.Text.Trim();
                if (string.IsNullOrEmpty(args) && !string.IsNullOrEmpty(parsedArgs))
                    args = parsedArgs;
                var launchMode = ParseLaunchMode();
                tracer.StartWithExe(exePath, string.IsNullOrEmpty(args) ? null : args, launchMode, cts.Token);
            }
            else if (isAttach)
            {
                if (!_attachPid.HasValue)
                {
                    SetStatus("Pick a process first (click 'Pick process...')", StatusKind.Err);
                    tracer.Dispose();
                    return;
                }
                try { Process.GetProcessById(_attachPid.Value); }
                catch
                {
                    SetStatus($"Process {_attachPid} no longer running — pick another", StatusKind.Err);
                    tracer.Dispose();
                    return;
                }
                tracer.AttachToPid(_attachPid.Value, cts.Token);
            }
            else // isWatch
            {
                var procName = WatchNameBox.Text?.Trim() ?? "";
                if (string.IsNullOrEmpty(procName))
                {
                    SetStatus("Enter a process name to watch (e.g. splunkd.exe)", StatusKind.Err);
                    tracer.Dispose();
                    return;
                }
                var cmd = WatchCmdBox.Text?.Trim();
                var match = WatchMatchBox.Text?.Trim();
                tracer.StartWatchByName(
                    procName,
                    string.IsNullOrEmpty(cmd) ? null : cmd,
                    cts.Token,
                    string.IsNullOrEmpty(match) ? null : match);
            }
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, StatusKind.Err);
            _main.Log($"Trace start failed: {ex.Message}");
            tracer.Dispose();
            return;
        }
        finally { Overlay.Hide(); }

        // Hand the tracer to MainWindow so it survives navigation. From here on
        // the page consults _main.ActiveTracer / _main.ActiveTraceStopwatch /
        // _main.ActiveTraceLiveCount — local fields are gone.
        var mode = isLaunch ? "Launch" : isAttach ? "Attach" : "Watch";
        _main.StartActiveTrace(tracer, cts, mode);

        // Wire ourselves to MainWindow's relay events. Loaded/Unloaded keep us
        // tidy across nav, but Start_Click here may fire on first Loaded too —
        // guard via the same flag.
        if (!_subscribedToLiveTrace)
        {
            _main.TraceEventCaptured  += OnEventCaptured;
            _main.TraceProcessDetected += OnProcessDetected;
            _main.TraceStatusChanged  += OnStatusChanged;
            _subscribedToLiveTrace = true;
        }

        _allRows.Clear();
        _rows.Clear();
        _treeNodes.Clear();
        DllGrid.ItemsSource = null;
        ProcessTree.ItemsSource = null;
        ResetStats();

        EnterRecordingUi();

        SetStatus(
            isWatch
                ? "[Watch] Capturing... trigger the target (or wait for restart cycles), then click STOP."
                : $"[{mode}] Tracing... interact with the target, then click STOP.",
            StatusKind.Info);
        _main.Log($"Runtime trace started ({mode})");

        if (isLaunch)
            Window.GetWindow(this)!.WindowState = WindowState.Minimized;
    }

    /// <summary>Apply the "recording in progress" look to the page: stop icon, REC
    /// badge pulsing, inputs disabled, elapsed-timer ticking from MainWindow's
    /// stopwatch. Called from both Start_Click (fresh trace) and AdoptLiveTrace
    /// (returning to the page mid-recording).</summary>
    private void EnterRecordingUi()
    {
        TraceBtn.Content = "■";
        TraceBtn.ToolTip = "Stop trace";
        RecBadge.Visibility = Visibility.Visible;
        StartRecPulse();

        TargetBox.IsEnabled = false;
        ArgsBox.IsEnabled = false;
        WatchNameBox.IsEnabled = false;
        WatchCmdBox.IsEnabled = false;
        WatchMatchBox.IsEnabled = false;
        IlAuto.IsEnabled = false;
        IlMedium.IsEnabled = false;
        IlSame.IsEnabled = false;
        BrowseBtn.IsEnabled = false;
        PickProcBtn.IsEnabled = false;
        PickSvcBtn.IsEnabled = false;
        ModeLaunch.IsEnabled = false;
        ModeAttach.IsEnabled = false;
        ModeWatch.IsEnabled = false;
        PromoteBtn.IsEnabled = false;
        CorrelateBtn.IsEnabled = false;

        _elapsedTimer?.Stop();
        _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _elapsedTimer.Tick += (_, _) =>
        {
            var sw = _main.ActiveTraceStopwatch;
            if (sw != null) ElapsedText.Text = $"{sw.Elapsed:mm\\:ss}";
            StatEvents.Text = _main.ActiveTraceLiveCount.ToString();
        };
        _elapsedTimer.Start();
    }

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        if (!_main.IsTraceActive) return;

        _elapsedTimer?.Stop();
        _elapsedTimer = null;

        Overlay.Show("Processing", "Aggregating trace results...");

        try
        {
            // Tracer lives on MainWindow; this call unhooks its handlers, calls
            // Stop, disposes, and clears the ActiveTracer / Stopwatch / Cts.
            _lastResult = _main.StopAndDisposeActiveTrace();
            _main.LastEtwResult = _lastResult;
        }
        finally
        {
            Overlay.Hide();
            if (_subscribedToLiveTrace)
            {
                _main.TraceEventCaptured  -= OnEventCaptured;
                _main.TraceProcessDetected -= OnProcessDetected;
                _main.TraceStatusChanged  -= OnStatusChanged;
                _subscribedToLiveTrace = false;
            }
        }

        if (_lastResult == null) return;

        TraceBtn.Content = "▶";
        TraceBtn.ToolTip = "Start trace";
        // Hide + stop the REC pulse — leaving the storyboard running on a hidden
        // element burns CPU on the compositor for nothing.
        StopRecPulse();
        RecBadge.Visibility = Visibility.Collapsed;
        TargetBox.IsEnabled = true;
        ArgsBox.IsEnabled = true;
        WatchNameBox.IsEnabled = true;
        WatchCmdBox.IsEnabled = true;
        WatchMatchBox.IsEnabled = true;
        IlAuto.IsEnabled = true;
        IlMedium.IsEnabled = true;
        IlSame.IsEnabled = true;
        BrowseBtn.IsEnabled = true;
        PickProcBtn.IsEnabled = true;
        PickSvcBtn.IsEnabled = true;
        ModeLaunch.IsEnabled = true;
        ModeAttach.IsEnabled = true;
        ModeWatch.IsEnabled = true;

        PopulateResults(_lastResult);

        var hasScan = _main.LastScanResults != null;
        PromoteBtn.IsEnabled = _allRows.Count > 0;
        CorrelateBtn.IsEnabled = _allRows.Count > 0 && hasScan;

        SetStatus(
            $"Trace complete — {_lastResult.FilteredEvents} events, {_lastResult.ByDll.Count} DLLs, " +
            $"{_lastResult.ProcessTree.Count} processes, {_lastResult.Duration.TotalSeconds:F1}s",
            _lastResult.FilteredEvents > 0 ? StatusKind.Ok : StatusKind.Warn);

        _main.Log($"Runtime trace stopped: {_lastResult.FilteredEvents} events, {_lastResult.ByDll.Count} DLLs, {_lastResult.ProcessTree.Count} processes");
    }

    private void PopulateResults(EtwTraceResult result)
    {
        _processFilterPids = null;
        FilterChip.Visibility = Visibility.Collapsed;
        RebuildAllRows(result);

        DllSearchBox.Text = "";
        ApplyDllFilter();
        BuildProcessTreeView(result);

        StatEvents.Text = result.FilteredEvents.ToString();
        StatDlls.Text = result.ByDll.Count.ToString();
        StatProcs.Text = result.ProcessTree.Count.ToString();
        StatWritable.Text = _allRows.Count(r => r.IsWritable).ToString();
    }

    /// <summary>Re-aggregates _allRows from _lastResult, optionally filtering events by _processFilterPids.</summary>
    private void RebuildAllRows(EtwTraceResult result)
    {
        IEnumerable<EtwTraceEvent> events = result.Events;
        if (_processFilterPids != null)
            events = events.Where(e => _processFilterPids.Contains(e.ProcessId));

        var summary = EtwResultConverter.DeduplicatedSummary(events);
        _allRows.Clear();
        foreach (var s in summary)
            _allRows.Add(new TraceRow(s.ProcessImage, s.DllName, s.Directory,
                s.EventCount, s.DirWritable, s.LoadCount, s.ProbeCount));
    }

    private void ClearProcessFilter_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult == null) return;
        _processFilterPids = null;
        FilterChip.Visibility = Visibility.Collapsed;
        RebuildAllRows(_lastResult);
        ApplyDllFilter();
        if (ProcessTree.SelectedItem is System.Windows.Controls.TreeViewItem tvi)
            tvi.IsSelected = false;
    }

    private void DllSearch_Changed(object sender, TextChangedEventArgs e) => ApplyDllFilter();

    private void ApplyDllFilter()
    {
        var q = DllSearchBox.Text.Trim();
        _rows.Clear();
        foreach (var r in _allRows)
        {
            if (q.Length > 0
                && !r.DllName.Contains(q, StringComparison.OrdinalIgnoreCase)
                && !r.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase)
                && !r.Directory.Contains(q, StringComparison.OrdinalIgnoreCase))
                continue;
            _rows.Add(r);
        }
        DllGrid.ItemsSource = null;
        DllGrid.ItemsSource = _rows;
    }

    private void BuildProcessTreeView(EtwTraceResult result)
    {
        _treeNodes.Clear();

        if (result.RootProcess != null)
            _treeNodes.Add(BuildNode(result.RootProcess));
        else
            foreach (var proc in result.ProcessTree.Where(p => p.IsRootTarget))
                _treeNodes.Add(BuildNode(proc));

        ProcessTree.ItemsSource = _treeNodes;
    }

    private static ProcessTreeNode BuildNode(TracedProcess proc)
    {
        var node = new ProcessTreeNode(proc);
        foreach (var child in proc.Children.OrderBy(c => c.StartTime))
            node.Children.Add(BuildNode(child));
        return node;
    }

    private void OnEventCaptured(EtwTraceEvent ev)
    {
        // Counter lives on MainWindow now (so it survives navigation away). The
        // elapsed-timer reads _main.ActiveTraceLiveCount directly. Nothing for
        // the page to do per-event.
    }

    private void OnProcessDetected(TracedProcess proc)
    {
        Dispatcher.BeginInvoke(() =>
        {
            StatProcs.Text = (_treeNodes.Sum(CountNodes)).ToString();
        });
    }

    private static int CountNodes(ProcessTreeNode n) => 1 + n.Children.Sum(CountNodes);

    private void OnStatusChanged(string msg)
    {
        Dispatcher.BeginInvoke(() => _main.Log($"[ETW] {msg}"));
    }

    private void ProcessTree_Selected(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is not ProcessTreeNode node || _lastResult == null)
        {
            DetailsEmpty.Visibility = Visibility.Visible;
            DetailsContent.Visibility = Visibility.Collapsed;
            return;
        }

        DetailsEmpty.Visibility = Visibility.Collapsed;
        DetailsContent.Visibility = Visibility.Visible;

        var proc = node.Process;
        DetailTitle.Text = $"{proc.Name}  (PID {proc.Pid})";
        DetailBody.Text =
            $"Image: {proc.ImagePath ?? "unknown"}\n" +
            $"Parent PID: {proc.ParentPid}\n" +
            $"Lifetime: {proc.LifetimeLabel}\n" +
            $"DLL misses: {proc.DllMissCount}\n" +
            $"Children: {proc.Children.Count}";

        var events = _lastResult.Events
            .Where(ev => ev.ProcessId == proc.Pid)
            .ToList();

        DetailPaths.ItemsSource = events.Select(ev => new
        {
            Path = ev.FilePath,
            Meta = $"@ {ev.Timestamp:HH:mm:ss.fff}",
        }).ToList();

        // Filter the DLL grid to this process and all its descendants
        var pidSet = new HashSet<int>();
        CollectPids(node, pidSet);
        _processFilterPids = pidSet;

        var descendantCount = pidSet.Count - 1;
        FilterChipText.Text = descendantCount > 0
            ? $"{proc.Name} [PID {proc.Pid}] + {descendantCount} children"
            : $"{proc.Name} [PID {proc.Pid}]";
        FilterChip.Visibility = Visibility.Visible;

        RebuildAllRows(_lastResult);
        ApplyDllFilter();
    }

    private static void CollectPids(ProcessTreeNode node, HashSet<int> into)
    {
        into.Add(node.Process.Pid);
        foreach (var child in node.Children)
            CollectPids(child, into);
    }

    private void DllGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (DllGrid.SelectedItem is not TraceRow row || _lastResult == null)
        {
            DetailsEmpty.Visibility = Visibility.Visible;
            DetailsContent.Visibility = Visibility.Collapsed;
            _main.CurrentAttackFocus = null;
            return;
        }

        DetailsEmpty.Visibility = Visibility.Collapsed;
        DetailsContent.Visibility = Visibility.Visible;

        DetailTitle.Text = $"{row.DllName}  —  {row.EventCount} events";
        DetailBody.Text =
            $"Process: {row.ProcessName}\n" +
            $"Directory: {row.Directory}\n" +
            $"Writable: {(row.IsWritable ? "YES" : "no")}";

        var events = _lastResult.Events
            .Where(ev => string.Equals(ev.DllName, row.DllName, StringComparison.OrdinalIgnoreCase))
            .ToList();

        DetailPaths.ItemsSource = events.Select(ev => new
        {
            Path = ev.FilePath,
            Meta = $"{ev.ProcessName}  (pid {ev.ProcessId})  @ {ev.Timestamp:HH:mm:ss.fff}" +
                   (ev.IsChildOfTarget ? "  [CHILD]" : ""),
        }).ToList();

        // Update AttackPathPage focus. If a scan exists and this DLL name matches
        // a known candidate, attach it so the chain/score render fully; otherwise
        // the focus carries DLL name + runtime metadata only and AttackPathPage
        // falls back to a degraded view.
        SideloadCandidate? sideMatch = null;
        PhantomCandidate? phantomMatch = null;
        if (_main.LastScanResults != null)
        {
            sideMatch = _main.LastScanResults.Existing
                .FirstOrDefault(c => string.Equals(c.Dll.Filename, row.DllName, StringComparison.OrdinalIgnoreCase));
            if (sideMatch == null)
                phantomMatch = _main.LastScanResults.Phantoms
                    .FirstOrDefault(p => string.Equals(p.DllName, row.DllName, StringComparison.OrdinalIgnoreCase));
        }
        _main.CurrentAttackFocus = new MainWindow.AttackPathFocus(
            MainWindow.AttackFocusSource.RuntimeTrace,
            DllName: row.DllName,
            DllPath: events.FirstOrDefault()?.FilePath,
            Candidate: sideMatch,
            Phantom: phantomMatch,
            RuntimeProcess: row.ProcessName,
            RuntimeEventCount: row.EventCount);
    }

    private void Promote_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult == null) return;

        Overlay.Show("Converting", "Building phantom candidates...");
        List<PhantomCandidate> phantoms;
        try { phantoms = EtwResultConverter.ToPhantomCandidates(_lastResult); }
        finally { Overlay.Hide(); }

        if (phantoms.Count == 0)
        {
            SetStatus("No phantom candidates to promote", StatusKind.Warn);
            return;
        }

        if (_main.LastScanResults == null)
            _main.LastScanResults = new ScanResults();

        var existing = _main.LastScanResults.Phantoms;
        var keys = new HashSet<string>(
            existing.Select(p => $"{p.DllName}|{p.DirectoryPath}".ToLowerInvariant()));
        var added = 0;
        foreach (var p in phantoms)
        {
            var key = $"{p.DllName}|{p.DirectoryPath}".ToLowerInvariant();
            if (keys.Add(key)) { existing.Add(p); added++; }
        }

        // Destination mirrors the button label set in Refresh(): if a wizard
        // session is alive the action returns the user to it (the wizard will
        // resume at Survey with the freshly-promoted phantoms loaded);
        // otherwise the Scan page is the natural landing spot.
        var resumingWizard = _main.CurrentWizardSession != null;
        if (resumingWizard)
        {
            // Tag the session as Runtime-originated and pre-fill its scan slot
            // so WizardPage ctor lands on Survey on the first promote. Without
            // this, a session created via the sidebar (EntryPoint=ScanFolder
            // default) would route the user to Input the first time and the
            // bug only resolved after the user manually re-entered via Input.
            var s = _main.CurrentWizardSession!;
            s.EntryPoint = Core.Models.Wizard.WizardEntryPoint.RuntimeTrace;
            if (s.ScanResults == null)
            {
                s.ScanResults = _main.LastScanResults;
                s.SurveyRootDir = _main.LastScanDir;
            }
        }
        // Count probe-only phantoms (every event was a metadata probe) — the
        // operator should know how many of the promoted candidates have weak
        // runtime evidence so they don't waste cycles on app-internal PATH
        // enumerations dressed up as sideload opportunities.
        var probeOnly = phantoms.Count(p => p.Evidence?.IsProbeOnly == true);
        var probeTag = probeOnly > 0 ? $", {probeOnly} probe-only" : "";

        _main.Log($"Promoted {added} runtime phantoms into scan results{probeTag}");
        SetStatus(
            resumingWizard
                ? $"Promoted {added} phantoms{probeTag} — returning to Wizard"
                : $"Promoted {added} phantoms{probeTag} — opening Scan page",
            StatusKind.Ok);
        if (resumingWizard)
            _main.NavigateTo(new Views.Wizard.WizardPage(_main));
        else
            _main.NavigateTo(new ScanPage(_main));
    }

    private void ResumeWizard_Click(object sender, RoutedEventArgs e)
    {
        // Just navigate back — WizardPage's ctor adopts _main.CurrentWizardSession
        // and decides whether to resume at Input or Survey based on whether the
        // user promoted phantoms to LastScanResults while here.
        _main.NavigateTo(new Views.Wizard.WizardPage(_main));
    }

    private void Correlate_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult == null || _main.LastScanResults == null) return;

        var procmonResult = EtwResultConverter.ToProcmonResult(_lastResult);
        var report = ProcmonCorrelator.Correlate(_main.LastScanResults, procmonResult);
        var total = report.ExistingMatched + report.PhantomMatched;

        SetStatus(
            $"Correlated: {report.ExistingMatched} existing + {report.PhantomMatched} phantom matched",
            total > 0 ? StatusKind.Ok : StatusKind.Warn);
        _main.Log($"ETW correlation: {report.ExistingMatched} existing, {report.PhantomMatched} phantom");
    }

    private void ResetStats()
    {
        StatEvents.Text = "0";
        StatDlls.Text = "0";
        StatProcs.Text = "0";
        StatWritable.Text = "0";
        ElapsedText.Text = "";
    }

    /// <summary>
    /// Looks up the RecPulse storyboard from RecBadge.Resources and begins it.
    /// Targets the RecDot ellipse's Opacity (1 → 0.25, AutoReverse, Forever).
    /// Resource lookup is delayed to runtime so a missing key fails soft.
    /// </summary>
    private void StartRecPulse()
    {
        if (RecBadge.Resources["RecPulse"] is Storyboard sb)
            sb.Begin(RecBadge, isControllable: true);
    }

    private void StopRecPulse()
    {
        if (RecBadge.Resources["RecPulse"] is Storyboard sb)
        {
            try { sb.Stop(RecBadge); } catch { /* never started — fine */ }
        }
        // Reset the dot to fully opaque so a new Start picks it up clean.
        RecDot.Opacity = 1.0;
    }

    private enum StatusKind { Info, Ok, Warn, Err }
    private void SetStatus(string text, StatusKind k)
    {
        Status.Text = text;
        Status.Foreground = new SolidColorBrush(k switch
        {
            StatusKind.Ok   => Color.FromRgb(0xA6, 0xE3, 0xA1),
            StatusKind.Warn => Color.FromRgb(0xF9, 0xE2, 0xAF),
            StatusKind.Err  => Color.FromRgb(0xF3, 0x8B, 0xA8),
            _               => Color.FromRgb(0x6C, 0x70, 0x86),
        });
    }

    private LaunchMode ParseLaunchMode()
    {
        if (IlMedium.IsChecked == true) return LaunchMode.MediumIntegrity;
        if (IlSame.IsChecked == true)   return LaunchMode.SameIntegrity;
        return LaunchMode.Auto;
    }

    /// <summary>
    /// Parses a command line into (exePath, arguments). Handles:
    ///   "C:\path to\app.exe" arg1 arg2
    ///   C:\path\app.exe arg1 arg2
    ///   C:\Program Files\...\app.exe C:\docs\file.pdf
    /// Falls back to splitting at first .exe boundary.
    /// </summary>
    private static (string ExePath, string? Args) ParseCommandLine(string input)
    {
        var text = input.Trim();
        if (string.IsNullOrEmpty(text)) return ("", null);

        // Case 1: quoted path — "C:\path\app.exe" args...
        if (text.StartsWith('"'))
        {
            var close = text.IndexOf('"', 1);
            if (close > 0)
            {
                var exe = text[1..close];
                var rest = text[(close + 1)..].Trim();
                return (exe, string.IsNullOrEmpty(rest) ? null : rest);
            }
            return (text.Trim('"'), null);
        }

        // Case 2: if the whole thing is a valid file, use it directly
        if (File.Exists(text)) return (text, null);

        // Case 3: find .exe boundary and split there
        var idx = text.IndexOf(".exe ", StringComparison.OrdinalIgnoreCase);
        if (idx > 0)
        {
            var exe = text[..(idx + 4)];
            var rest = text[(idx + 5)..].Trim();
            return (exe, string.IsNullOrEmpty(rest) ? null : rest);
        }

        // No split found — return as-is
        return (text, null);
    }

    // ── View models ──

    private class TraceRow
    {
        public string ProcessName { get; }
        public string DllName { get; }
        public string Directory { get; }
        public int EventCount { get; }
        public bool IsWritable { get; }
        public string WritableLabel => IsWritable ? "Y" : "";
        public int LoadCount { get; }
        public int ProbeCount { get; }

        // Compact LOAD/PROBE/MIXED label for the grid. Empty when neither bucket
        // has a count — corresponds to AccessClass.Unknown events only.
        public string AccessLabel => Core.Models.AccessClassLabels.FromCounts(LoadCount, ProbeCount);

        public string AccessTooltip =>
            LoadCount == 0 && ProbeCount == 0
                ? "Classification unavailable for these events"
                : $"Loader-like opens: {LoadCount} · Metadata probes: {ProbeCount}\n" +
                  $"{Core.Models.AccessClassLabels.Load} = real loader image-map open. " +
                  $"{Core.Models.AccessClassLabels.Probe} = GetFileAttributes-class call " +
                  "(app enumerating PATH, planted DLL would not execute).";

        // Cross-surface ExploitabilityVerdict — same record AnalyzePage /
        // ScanPage / ProcmonPage feed into the VerdictBadge control. The
        // tier collapses Mode (derived from the DLL name via the standard
        // classifier) + Writability (single-dir tier in Runtime's case
        // because each row represents one (proc, dll, dir) tuple).
        public Core.Services.Exploitability.ExploitabilityVerdict Verdict { get; }
        public int VerdictSortKey => Verdict.Score;

        public TraceRow(string proc, string dll, string dir, int events, bool writable,
                        int loadCount = 0, int probeCount = 0)
        {
            ProcessName = Path.GetFileName(proc);
            DllName = dll;
            Directory = dir;
            EventCount = events;
            IsWritable = writable;
            LoadCount = loadCount;
            ProbeCount = probeCount;

            var mode = Core.Services.ProcmonRowClassifier.Classify(dll).Mode;
            var writTier = writable
                ? Core.Services.ProcmonDirWritability.AllLowPrivWritable
                : Core.Services.ProcmonDirWritability.AllLocked;
            Verdict = Core.Services.Exploitability.ExploitabilityVerdict.For.ProcmonRow(mode, writTier);
        }
    }

    public class ProcessTreeNode
    {
        public TracedProcess Process { get; }
        public List<ProcessTreeNode> Children { get; } = [];

        public ProcessTreeNode(TracedProcess proc) { Process = proc; }

        public string Icon => Process.IsRootTarget ? "▸" : "·";
        public string Label =>
            $"{Process.Name} [{Process.Pid}] {Process.LifetimeLabel}" +
            (Process.DllMissCount > 0 ? $" ({Process.DllMissCount} miss)" : "");
        public string Tooltip =>
            $"PID: {Process.Pid}\n" +
            $"Image: {Process.ImagePath ?? "?"}\n" +
            $"Parent: {Process.ParentPid}\n" +
            $"Lifetime: {Process.LifetimeLabel}\n" +
            $"DLL misses: {Process.DllMissCount}";
    }
}
