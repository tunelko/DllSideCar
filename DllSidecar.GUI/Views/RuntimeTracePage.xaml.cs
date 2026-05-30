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
    // Per-session memoized ACL probes for row writability tier.
    private readonly Core.Services.DirAclCache _dirAcl = new();
    private readonly List<TraceRow> _allRows = [];
    private readonly List<TraceRow> _rows = [];
    private readonly List<ProcessTreeNode> _treeNodes = [];
    // When non-null, only DLL events whose ProcessId is in this set are shown.
    private HashSet<int>? _processFilterPids;
    private DispatcherTimer? _elapsedTimer;
    // Populated by ProcessPickerDialog; drives Attach-mode Start.
    private int? _attachPid;
    private string? _attachProcName;
    // Guards against double-subscription on re-Loaded page.
    private bool _subscribedToLiveTrace;

    public RuntimeTracePage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        // Tracer lives on MainWindow; only handlers are wired per page lifecycle.
        Loaded   += (_, _) => AdoptLiveTraceIfRunning();
        Unloaded += (_, _) => ReleaseLiveTraceHandlers();

        // Surface init failures in the log instead of an empty page.
        _ = InitAsync().ContinueWith(t =>
        {
            if (t.IsFaulted && t.Exception != null)
                _main.Log($"RuntimeTrace init failed: {t.Exception.InnerException?.GetType().Name}: {t.Exception.InnerException?.Message}");
        }, TaskScheduler.FromCurrentSynchronizationContext());
    }

    /// <summary>If a live trace is running on MainWindow, restore the recording UI and resume consuming relay events.</summary>
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
        // Do not touch _main.ActiveTracer — trace continues until user clicks Stop.
    }

    private async Task InitAsync()
    {
        Overlay.Show("Loading", "Preparing trace page...");
        try
        {
            await Task.Delay(50);
            UpdateModeUi();

            // Session memory wins; fall back to persisted AppConfig path.
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

            // Wizard-mode controls only show if a wizard session is active.
            ResumeWizardBtn.Visibility = _main.CurrentWizardSession != null
                ? Visibility.Visible : Visibility.Collapsed;
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
            // Auto-fill watch panel; '&' chain runs start even if stop fails.
            WatchNameBox.Text = dlg.SelectedImageFile;
            WatchCmdBox.Text = $"net stop {dlg.SelectedServiceName} & net start {dlg.SelectedServiceName}";
            // Cmd-line filter is non-empty for svchost-style shared hosts.
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

    /// <summary>True when page/MainWindow holds residue of an earlier trace; drives the Start confirmation gate.</summary>
    private bool HasPreviousTraceData() =>
        _lastResult != null
        || _main.LastEtwResult != null
        || (_main.LastScanResults?.Phantoms.Count ?? 0) > 0
        || (_main.LastScanResults?.Existing.Count ?? 0) > 0;

    /// <summary>Atomic wipe of every trace-related residue. Does NOT touch wizard state.</summary>
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
        // Destructive-action gate: confirm before discarding previous trace data.
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

        // Hand tracer to MainWindow so it survives navigation.
        var mode = isLaunch ? "Launch" : isAttach ? "Attach" : "Watch";
        _main.StartActiveTrace(tracer, cts, mode);

        // Wire to MainWindow's relay events; guard against double-subscribe.
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

    /// <summary>Apply the recording-in-progress look: stop icon, REC pulse, inputs disabled, elapsed-timer ticking.</summary>
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
            // Unhooks tracer handlers, stops, disposes, and clears MainWindow state.
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
        // Stop the storyboard so it doesn't burn compositor CPU while hidden.
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

        // Run elevation transition detection to tag rows with PRIVESC.
        var probeEvents = events.Select(e => new ProcmonEvent
        {
            ProcessName = e.ProcessName,
            Operation = "CreateFile",
            Result = "NAME NOT FOUND",
            Path = e.FilePath,
            Pid = e.ProcessId,
            Timestamp = e.Timestamp,
            Access = e.Access,
        }).ToList();
        // IL map gates the detector so same-name launchers (Battle.net) don't get flagged.
        var pidIl = result.ProcessTree
            .GroupBy(p => p.Pid)
            .ToDictionary(g => g.Key, g => g.First().IntegrityLevel);
        var transitions = Core.Services.ElevationTransitionDetector.DetectAndTag(probeEvents, pidIl);

        // Direct IL signal: tags High/System IL PIDs even when UAC parent is missing from capture.
        var highIlPids = result.ProcessTree
            .Where(p => p.IntegrityLevel == IntegrityLevel.High || p.IntegrityLevel == IntegrityLevel.System)
            .Select(p => p.Pid)
            .ToHashSet();
        if (highIlPids.Count > 0)
        {
            foreach (var ev in probeEvents)
                if (ev.Pid.HasValue && highIlPids.Contains(ev.Pid.Value))
                    ev.Phase = IlPhase.HighIl;
        }
        var highIlProcesses = result.ProcessTree
            .Where(p => p.IntegrityLevel == IntegrityLevel.High || p.IntegrityLevel == IntegrityLevel.System)
            .ToList();
        var elevatedDllNames = probeEvents
            .Where(e => e.Phase == IlPhase.HighIl)
            .Select(e => e.DllName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        _allRows.Clear();
        var carrierInputs = new List<Core.Services.CarrierInput>();
        foreach (var s in summary)
        {
            // Real ACL probe (matches ProcmonPage); IsUserWritable includes live CurrentUserWrite probe.
            var aclPerms = _dirAcl.Get(s.Directory);
            bool writable = string.IsNullOrEmpty(aclPerms.Error) && aclPerms.IsUserWritable;

            bool highIl = elevatedDllNames.Contains(s.DllName);

            // Canonical privesc-carrier identifier (same gates as ProcmonPage banner).
            var input = new Core.Services.CarrierInput(
                DllName: s.DllName,
                IsHighIlSearch: highIl,
                SearchedDirs: new[] { s.Directory },
                LoaderLikeCount: s.LoadCount,
                MetadataProbeCount: s.ProbeCount,
                EventCount: s.EventCount);
            carrierInputs.Add(input);

            bool isCarrier = Core.Services.PrivescCarrierIdentifier.Qualifies(input, _dirAcl, out _);
            _allRows.Add(new TraceRow(s.ProcessImage, s.DllName, s.Directory,
                s.EventCount, writable, s.LoadCount, s.ProbeCount, isCarrier));
        }

        UpdateElevationBanner(transitions, highIlProcesses, carrierInputs);
        _carriersForBanner = Core.Services.PrivescCarrierIdentifier.Identify(carrierInputs, _dirAcl);
        _transitionSummaryForBanner = BuildTransitionSummary(transitions, highIlProcesses);
    }

    private static string BuildTransitionSummary(
        IReadOnlyList<Core.Models.ElevationTransition> transitions,
        IReadOnlyList<Core.Models.TracedProcess> highIlProcesses)
    {
        if (transitions != null && transitions.Count > 0)
        {
            return transitions.Count == 1
                ? $"{transitions[0].ProcessName} PID {transitions[0].ParentPid} -> {transitions[0].ChildPid}"
                : string.Join(" · ", transitions.Select(t => $"{t.ProcessName} {t.ParentPid}->{t.ChildPid}"));
        }
        if (highIlProcesses != null && highIlProcesses.Count > 0)
            return string.Join(" · ", highIlProcesses.Take(3).Select(p => $"{p.Name} PID {p.Pid} (IL={p.IntegrityLevel})"));
        return "";
    }

    private List<Core.Services.PrivescCarrier> _carriersForBanner = [];

    private string _transitionSummaryForBanner = "";

    private void PromotePrivesc_Click(object sender, RoutedEventArgs e)
    {
        if (_carriersForBanner.Count == 0)
        {
            SetStatus("No carriers ranked — run the trace first", StatusKind.Warn);
            return;
        }
        _main.PendingPrivescHandoff = new MainWindow.PrivescCarrierHandoff(
            SourceLabel: "Runtime ETW trace",
            Carriers: _carriersForBanner,
            TransitionSummary: _transitionSummaryForBanner);
        _main.NavigateTo(new PrivescPage(_main));
    }

    /// <summary>Shows the UAC elevation banner when a transition or High-IL process is detected, listing privesc carrier DLLs.</summary>
    private void UpdateElevationBanner(
        IReadOnlyList<Core.Models.ElevationTransition> transitions,
        IReadOnlyList<Core.Models.TracedProcess> highIlProcesses,
        IReadOnlyList<Core.Services.CarrierInput> carrierInputs)
    {
        bool hasTransition  = transitions != null && transitions.Count > 0;
        bool hasHighIlProc  = highIlProcesses != null && highIlProcesses.Count > 0;
        if (!hasTransition && !hasHighIlProc)
        {
            ElevationBanner.Visibility = Visibility.Collapsed;
            return;
        }

        string header;
        if (hasTransition && transitions!.Count == 1)
        {
            var t = transitions[0];
            var gap = t.Gap?.TotalMilliseconds switch
            {
                null => "gap: n/a",
                < 1000 => $"gap: {t.Gap!.Value.TotalMilliseconds:F0} ms",
                _ => $"gap: {t.Gap!.Value.TotalSeconds:F2} s",
            };
            header = $"{t.ProcessName}  PID {t.ParentPid} -> {t.ChildPid}  ({gap})";
        }
        else if (hasTransition)
        {
            header = $"{transitions!.Count} transitions: " +
                string.Join("  ·  ",
                    transitions.Select(t => $"{t.ProcessName} PID {t.ParentPid}->{t.ChildPid}"));
        }
        else
        {
            // Direct IL signal: surface elevated processes without needing both UAC sides.
            var procs = highIlProcesses!
                .Take(3)
                .Select(p => $"{p.Name} (PID {p.Pid}, IL={p.IntegrityLevel})");
            var moreProcs = highIlProcesses!.Count > 3 ? $" +{highIlProcesses.Count - 3} more" : "";
            header = $"Elevated process observed (direct ETW IL signal): {string.Join(" · ", procs)}{moreProcs}";
        }

        var carriers = Core.Services.PrivescCarrierIdentifier.Identify(carrierInputs, _dirAcl);

        if (carriers.Count == 0)
        {
            ElevationBannerText.Text =
                header + "\nNo privesc carrier DLL identified — elevated child loaded only from KnownDLLs, locked dirs, or probe-only paths.";
            ElevationBanner.Visibility = Visibility.Visible;
            return;
        }

        const int show = 5;
        var top = carriers.Take(show).Select(c => c.DllName);
        var moreCount = carriers.Count - show;
        var carriersText = string.Join(", ", top);
        if (moreCount > 0)
            carriersText += $" (+{moreCount} more)";

        ElevationBannerText.Text =
            header +
            $"\n{carriers.Count} privesc carrier DLL{(carriers.Count == 1 ? "" : "s")}: {carriersText}";

        ElevationBanner.Visibility = Visibility.Visible;
        PromotePrivescBtn.IsEnabled = true;
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
        // Per-event work happens via MainWindow's counter; elapsed-timer reads it.
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

        // Update AttackPathPage focus with scan candidate match if available.
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

        // Destination: Wizard if a session is alive, otherwise Scan.
        var resumingWizard = _main.CurrentWizardSession != null;
        if (resumingWizard)
        {
            // Tag session as Runtime-originated so WizardPage lands on Survey.
            var s = _main.CurrentWizardSession!;
            s.EntryPoint = Core.Models.Wizard.WizardEntryPoint.RuntimeTrace;
            if (s.ScanResults == null)
            {
                s.ScanResults = _main.LastScanResults;
                s.SurveyRootDir = _main.LastScanDir;
            }
        }
        // Probe-only phantoms have weak runtime evidence; surface the count.
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
        // WizardPage ctor adopts _main.CurrentWizardSession and resumes appropriately.
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

    /// <summary>Begins the RecPulse storyboard from RecBadge.Resources; fails soft if missing.</summary>
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

    /// <summary>Parses a command line into (exePath, arguments).</summary>
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

        // Compact LOAD/PROBE/MIXED label; empty for Unknown-only events.
        public string AccessLabel => Core.Models.AccessClassLabels.FromCounts(LoadCount, ProbeCount);

        public string AccessTooltip =>
            LoadCount == 0 && ProbeCount == 0
                ? "Classification unavailable for these events"
                : $"Loader-like opens: {LoadCount} · Metadata probes: {ProbeCount}\n" +
                  $"{Core.Models.AccessClassLabels.Load} = real loader image-map open. " +
                  $"{Core.Models.AccessClassLabels.Probe} = GetFileAttributes-class call " +
                  "(app enumerating PATH, planted DLL would not execute).";

        // Cross-surface verdict feeding into VerdictBadge.
        public Core.Services.Exploitability.ExploitabilityVerdict Verdict { get; }
        public int VerdictSortKey => Verdict.Score;

        public TraceRow(string proc, string dll, string dir, int events, bool writable,
                        int loadCount = 0, int probeCount = 0, bool privescCandidate = false)
        {
            ProcessName = Path.GetFileName(proc);
            DllName = dll;
            Directory = dir;
            EventCount = events;
            IsWritable = writable;
            LoadCount = loadCount;
            ProbeCount = probeCount;
            IsPrivescCandidate = privescCandidate;

            var mode = Core.Services.ProcmonRowClassifier.Classify(dll).Mode;
            var writTier = writable
                ? Core.Services.ProcmonDirWritability.AllLowPrivWritable
                : Core.Services.ProcmonDirWritability.AllLocked;
            Verdict = Core.Services.Exploitability.ExploitabilityVerdict.For.ProcmonRow(mode, writTier, privescCandidate);
        }

        /// <summary>True when the elevated child searched this row's DLL; drives the PRIVESC chip and verdict.</summary>
        public bool IsPrivescCandidate { get; }
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
