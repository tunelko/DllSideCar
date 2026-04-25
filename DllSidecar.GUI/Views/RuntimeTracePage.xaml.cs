using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

public partial class RuntimeTracePage : Page
{
    private readonly MainWindow _main;
    private EtwDllTracer? _tracer;
    private CancellationTokenSource? _cts;
    private EtwTraceResult? _lastResult;
    private readonly List<TraceRow> _allRows = [];
    private readonly List<TraceRow> _rows = [];
    private readonly List<ProcessTreeNode> _treeNodes = [];
    // When non-null, only DLL events whose ProcessId is in this set are shown.
    // Set by ProcessTree_Selected; cleared by the × chip.
    private HashSet<int>? _processFilterPids;
    private DispatcherTimer? _elapsedTimer;
    private Stopwatch? _sw;
    private int _liveEventCount;
    // Populated by ProcessPickerDialog; drives Attach-mode Start.
    private int? _attachPid;
    private string? _attachProcName;

    public RuntimeTracePage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        _ = InitAsync();
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
            }
        }
        finally { Overlay.Hide(); }
    }

    private void Mode_Changed(object sender, RoutedEventArgs e) => UpdateModeUi();

    private void UpdateModeUi()
    {
        if (TargetBox == null) return; // called during InitializeComponent before controls exist
        var isLaunch = ModeLaunch.IsChecked == true;
        // Launch mode: show path TextBox + folder (📁) action. Attach mode: show PID chip + picker (⋮).
        TargetBox.Visibility = isLaunch ? Visibility.Visible : Visibility.Collapsed;
        AttachPicker.Visibility = isLaunch ? Visibility.Collapsed : Visibility.Visible;
        BrowseBtn.Visibility = isLaunch ? Visibility.Visible : Visibility.Collapsed;
        PickProcBtn.Visibility = isLaunch ? Visibility.Collapsed : Visibility.Visible;
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

    private void Trace_Click(object sender, RoutedEventArgs e)
    {
        if (_tracer != null) { Stop_Click(sender, e); return; }
        Start_Click(sender, e);
    }

    private void Start_Click(object sender, RoutedEventArgs e)
    {
        var filter = new EtwTraceFilter
        {
            IncludeChildren = ChkChildren.IsChecked == true,
            DllOnly = ChkDllOnly.IsChecked == true,
            NameNotFoundOnly = ChkNotFoundOnly.IsChecked == true,
        };

        _cts = new CancellationTokenSource();
        _tracer = new EtwDllTracer(filter);
        _tracer.EventCaptured += OnEventCaptured;
        _tracer.ProcessDetected += OnProcessDetected;
        _tracer.StatusChanged += OnStatusChanged;

        var isLaunch = ModeLaunch.IsChecked == true;
        Overlay.Show("Starting trace",
            isLaunch ? "Launching ETW session and target process..." : "Attaching to process...");

        try
        {
            if (isLaunch)
            {
                var (exePath, parsedArgs) = ParseCommandLine(TargetBox.Text);
                if (string.IsNullOrEmpty(exePath))
                {
                    SetStatus("Enter the path to an EXE", StatusKind.Err);
                    _tracer.Dispose();
                    _tracer = null;
                    return;
                }
                if (!File.Exists(exePath))
                {
                    SetStatus($"File not found: {exePath}", StatusKind.Err);
                    _tracer.Dispose();
                    _tracer = null;
                    return;
                }
                var args = ArgsBox.Text.Trim();
                if (string.IsNullOrEmpty(args) && !string.IsNullOrEmpty(parsedArgs))
                    args = parsedArgs;
                var launchMode = ParseLaunchMode();
                _tracer.StartWithExe(exePath, string.IsNullOrEmpty(args) ? null : args, launchMode, _cts.Token);
            }
            else
            {
                if (!_attachPid.HasValue)
                {
                    SetStatus("Pick a process first (click 'Pick process...')", StatusKind.Err);
                    _tracer.Dispose();
                    _tracer = null;
                    return;
                }
                try { Process.GetProcessById(_attachPid.Value); }
                catch
                {
                    SetStatus($"Process {_attachPid} no longer running — pick another", StatusKind.Err);
                    _tracer.Dispose();
                    _tracer = null;
                    return;
                }
                _tracer.AttachToPid(_attachPid.Value, _cts.Token);
            }
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, StatusKind.Err);
            _main.Log($"Trace start failed: {ex.Message}");
            _tracer?.Dispose();
            _tracer = null;
            return;
        }
        finally { Overlay.Hide(); }

        _liveEventCount = 0;
        _allRows.Clear();
        _rows.Clear();
        _treeNodes.Clear();
        DllGrid.ItemsSource = null;
        ProcessTree.ItemsSource = null;
        ResetStats();

        // Stop icon (■) in IconButton chrome; color cue via ToolTip since style stays neutral.
        TraceBtn.Content = "■";
        TraceBtn.ToolTip = "Stop trace";
        TargetBox.IsEnabled = false;
        ArgsBox.IsEnabled = false;
        IlAuto.IsEnabled = false;
        IlMedium.IsEnabled = false;
        IlSame.IsEnabled = false;
        BrowseBtn.IsEnabled = false;
        PickProcBtn.IsEnabled = false;
        ModeLaunch.IsEnabled = false;
        ModeAttach.IsEnabled = false;
        PromoteBtn.IsEnabled = false;
        CorrelateBtn.IsEnabled = false;

        _sw = Stopwatch.StartNew();
        _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _elapsedTimer.Tick += (_, _) =>
        {
            ElapsedText.Text = $"{_sw!.Elapsed:mm\\:ss}";
            StatEvents.Text = _liveEventCount.ToString();
        };
        _elapsedTimer.Start();

        var mode = ModeLaunch.IsChecked == true ? "Launch" : "Attach";
        SetStatus($"[{mode}] Tracing... interact with the target, then click STOP.", StatusKind.Info);
        _main.Log($"Runtime trace started ({mode})");

        if (isLaunch)
            Window.GetWindow(this)!.WindowState = WindowState.Minimized;
    }

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        if (_tracer == null) return;

        _elapsedTimer?.Stop();
        _sw?.Stop();

        Overlay.Show("Processing", "Aggregating trace results...");

        try
        {
            _lastResult = _tracer.Stop();
            _main.LastEtwResult = _lastResult;
        }
        finally
        {
            Overlay.Hide();
            _tracer.Dispose();
            _tracer = null;
            _cts?.Dispose();
            _cts = null;
        }

        TraceBtn.Content = "▶";
        TraceBtn.ToolTip = "Start trace";
        TargetBox.IsEnabled = true;
        ArgsBox.IsEnabled = true;
        IlAuto.IsEnabled = true;
        IlMedium.IsEnabled = true;
        IlSame.IsEnabled = true;
        BrowseBtn.IsEnabled = true;
        PickProcBtn.IsEnabled = true;
        ModeLaunch.IsEnabled = true;
        ModeAttach.IsEnabled = true;

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
            _allRows.Add(new TraceRow(s.ProcessImage, s.DllName, s.Directory, s.EventCount, s.DirWritable));
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
        Interlocked.Increment(ref _liveEventCount);
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

        _main.Log($"Promoted {added} runtime phantoms into scan results");
        SetStatus($"Promoted {added} phantoms — opening Scan page", StatusKind.Ok);
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

        public TraceRow(string proc, string dll, string dir, int events, bool writable)
        {
            ProcessName = Path.GetFileName(proc);
            DllName = dll;
            Directory = dir;
            EventCount = events;
            IsWritable = writable;
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
