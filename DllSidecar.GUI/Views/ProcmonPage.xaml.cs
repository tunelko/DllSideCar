using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

public partial class ProcmonPage : Page
{
    private readonly MainWindow _main;
    private ProcmonParser.ParseResult? _lastResult;
    // Master list — never mutated after parse. View grid binds to filtered projection.
    private readonly List<DllRow> _allRows = [];

    public ProcmonPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        UpdateLaunchBtn();
        RestorePersistedState();
        WirePersistence();
        // Re-hydrate from the MainWindow session state so a parse done earlier
        // in the same app session is still visible after navigating away and
        // back. UiState handles the CSV path + checkbox filters; the heavy
        // ParseResult itself lives on MainWindow because it's not config.
        if (_main.LastProcmonResult != null) RehydrateFromLastResult();
    }

    /// <summary>
    /// Reconstructs the grid, stats and status from a previously-parsed result
    /// held on MainWindow. Called from the ctor when navigating back to a page
    /// that had been parsed earlier in this app session.
    /// </summary>
    private void RehydrateFromLastResult()
    {
        _lastResult = _main.LastProcmonResult;
        if (_lastResult == null) return;
        if (!string.IsNullOrEmpty(_main.LastProcmonCsvPath))
            CsvPathBox.Text = _main.LastProcmonCsvPath;

        _allRows.Clear();
        foreach (var a in _lastResult.ByDll) _allRows.Add(new DllRow(a));

        StatTotal.Text  = _lastResult.TotalRows.ToString();
        StatEvents.Text = _lastResult.FilteredRows.ToString();
        StatDlls.Text   = _allRows.Count.ToString();
        StatHigh.Text   = _allRows.Count(r => r.Aggregation.AnyDirUserSpace).ToString();

        ApplyViewFilter();
        SetStatus(
            $"Restored parse — {_lastResult.FilteredRows} events, {_allRows.Count} unique DLLs",
            StatusKind.Info);
    }

    private void RestorePersistedState()
    {
        var s = ConfigManager.Current.UiState.ProcmonPage;
        if (!string.IsNullOrEmpty(s.LastCsvPath)) CsvPathBox.Text = s.LastCsvPath;
        ChkOnlyUserSpace.IsChecked = s.OnlyUserSpace;
        ChkOnlyHighRisk.IsChecked  = s.OnlyHighRisk;
        ChkHideKnownDlls.IsChecked = s.HideKnownDlls;
    }

    private void WirePersistence()
    {
        void Save(object? _, object __) => PersistState();
        CsvPathBox.TextChanged  += Save;
        ChkOnlyUserSpace.Checked += Save; ChkOnlyUserSpace.Unchecked += Save;
        ChkOnlyHighRisk.Checked  += Save; ChkOnlyHighRisk.Unchecked  += Save;
        ChkHideKnownDlls.Checked += Save; ChkHideKnownDlls.Unchecked += Save;
    }

    private void PersistState()
    {
        if (!IsLoaded) return;
        var s = ConfigManager.Current.UiState.ProcmonPage;
        s.LastCsvPath    = CsvPathBox.Text?.Trim();
        s.OnlyUserSpace  = ChkOnlyUserSpace.IsChecked == true;
        s.OnlyHighRisk   = ChkOnlyHighRisk.IsChecked == true;
        s.HideKnownDlls  = ChkHideKnownDlls.IsChecked == true;
        ConfigManager.Save();
    }

    private static readonly string[] ProcmonExportHeader =
    { "Risk", "DLL", "Procs", "Events", "Dirs", "Processes" };

    private List<string[]> BuildExportRows()
    {
        var view = DllGrid.ItemsSource as IEnumerable<DllRow> ?? _allRows;
        return view.Select(r => new[]
        {
            r.Risk, r.DllName, r.ProcessCount.ToString(),
            r.EventCount.ToString(), r.DirCount.ToString(), r.ProcessList,
        }).ToList();
    }

    private void CopyList_Click(object sender, RoutedEventArgs e)
    {
        var rows = BuildExportRows();
        if (rows.Count == 0) { SetStatus("Nothing to copy — parse a CSV first", StatusKind.Warn); return; }
        if (Services.ListExporter.CopyTsv(ProcmonExportHeader, rows, out var n))
            SetStatus($"Copied {n} rows to clipboard (TSV).", StatusKind.Ok);
        else
            SetStatus("Clipboard copy failed", StatusKind.Err);
    }

    private void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        var rows = BuildExportRows();
        if (rows.Count == 0) { SetStatus("Nothing to export — parse a CSV first", StatusKind.Warn); return; }
        var baseName = Path.GetFileNameWithoutExtension(CsvPathBox.Text ?? "procmon");
        var suggested = $"procmon-aggregated-{baseName}-{DateTime.Now:yyyyMMdd-HHmm}.csv";
        var path = Services.ListExporter.SaveCsv(ProcmonExportHeader, rows, suggested);
        if (path != null)
        {
            SetStatus($"Exported {rows.Count} rows → {Path.GetFileName(path)}", StatusKind.Ok);
            _main.Log($"Procmon export: {path}");
        }
    }

    private void UpdateLaunchBtn()
    {
        var procmon = ConfigManager.Current.Tools.ProcmonPath;
        var hasProcmon = !string.IsNullOrWhiteSpace(procmon) && File.Exists(procmon);
        LaunchProcmonBtn.IsEnabled = hasProcmon;
        LaunchProcmonBtn.ToolTip = hasProcmon
            ? $"Launch {procmon}"
            : "ProcMon path not configured — set in Configuration or Toolkit page";
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "ProcMon CSV|*.csv|All files|*.*",
            Title = "Select ProcMon CSV export",
        };
        if (dlg.ShowDialog() == true) CsvPathBox.Text = dlg.FileName;
    }

    private async void Parse_Click(object sender, RoutedEventArgs e)
    {
        var path = CsvPathBox.Text.Trim();
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            SetStatus("File does not exist", StatusKind.Err);
            return;
        }

        SetStatus($"Parsing {path}...", StatusKind.Info);
        Overlay.Show("Parsing CSV", $"Reading {Path.GetFileName(path)}...");
        try { _lastResult = await Task.Run(() => ProcmonParser.Parse(path)); }
        finally { Overlay.Hide(); }

        if (!string.IsNullOrEmpty(_lastResult.Error))
        {
            SetStatus(_lastResult.Error, StatusKind.Err);
            return;
        }

        _allRows.Clear();
        foreach (var a in _lastResult.ByDll) _allRows.Add(new DllRow(a));

        StatTotal.Text = _lastResult.TotalRows.ToString();
        StatEvents.Text = _lastResult.FilteredRows.ToString();
        StatDlls.Text = _allRows.Count.ToString();
        StatHigh.Text = _allRows.Count(r => r.Aggregation.AnyDirUserSpace).ToString();

        ApplyViewFilter();

        // Park the successful parse on MainWindow so the next ProcmonPage
        // instance (e.g. after navigating to Config and back) re-hydrates
        // automatically. Mirrors LastScanResults / LastEtwResult.
        _main.LastProcmonResult = _lastResult;
        _main.LastProcmonCsvPath = path;

        SetStatus($"Parsed — {_lastResult.FilteredRows} events, {_allRows.Count} unique DLLs",
            _allRows.Count > 0 ? StatusKind.Ok : StatusKind.Warn);
    }

    private void Filter_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyViewFilter();
    }

    private void Search_Changed(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyViewFilter();
    }

    private void ApplyViewFilter()
    {
        IEnumerable<DllRow> view = _allRows;

        if (ChkOnlyUserSpace.IsChecked == true)
            view = view.Where(r => r.Aggregation.AnyDirUserSpace);

        if (ChkOnlyHighRisk.IsChecked == true)
            view = view.Where(r => string.Equals(r.Risk, "HIGH", StringComparison.OrdinalIgnoreCase));

        // KnownDLLs (kernel32, ntdll, user32…) are surfaced by ProcMon because
        // every process searches for them in its own dir first, but Windows
        // ignores that and loads them from System32 regardless. Hiding them
        // by default keeps the grid focused on actually-exploitable rows.
        if (ChkHideKnownDlls.IsChecked == true)
            view = view.Where(r => r.Mode != ProcmonRowMode.KnownDll);

        var q = DllSearchBox?.Text?.Trim();
        if (!string.IsNullOrEmpty(q))
        {
            view = view.Where(r =>
                r.DllName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.ProcessList.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.Aggregation.SearchedDirs.Any(d => d.Contains(q, StringComparison.OrdinalIgnoreCase)));
        }

        DllGrid.ItemsSource = view.ToList();
    }

    private void DllGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (DllGrid.SelectedItem is not DllRow row || _lastResult == null)
        {
            DetailsEmpty.Visibility = Visibility.Visible;
            DetailsContent.Visibility = Visibility.Collapsed;
            PromoteBtn.IsEnabled = false;
            return;
        }

        DetailsEmpty.Visibility = Visibility.Collapsed;
        DetailsContent.Visibility = Visibility.Visible;
        // Promotion is meaningful for everything EXCEPT KnownDLLs (Windows
        // always loads those from System32, classic sideload cannot intercept).
        // Resolvable AND Phantom rows both promote — Resolvable gets Proxy mode
        // with real exports, Phantom gets Sideload mode with a synthetic
        // PeAnalysis. The Promote handler decides the actual mode at click time.
        PromoteBtn.IsEnabled = row.Mode != ProcmonRowMode.KnownDll;

        DetailTitle.Text = $"{row.DllName}  —  {row.Aggregation.EventCount} events  —  risk: {row.Risk}";
        DetailProcesses.Text = string.Join("\n", row.Aggregation.Processes.OrderBy(p => p));

        var events = _lastResult.Events
            .Where(ev => string.Equals(ev.DllName, row.DllName, StringComparison.OrdinalIgnoreCase))
            .ToList();

        DetailPaths.ItemsSource = events.Select(ev => new
        {
            Path = ev.Path,
            Meta = $"{ev.ProcessName}" +
                   (ev.Pid.HasValue ? $"  (pid {ev.Pid})" : "") +
                   (ev.Timestamp.HasValue ? $"  @ {ev.Timestamp:HH:mm:ss.fff}" : "") +
                   (IsLikelyUserSpace(ev.SearchDir) ? "  [USER-SPACE DIR]" : ""),
        }).ToList();
    }

    private static bool IsLikelyUserSpace(string dir)
    {
        if (string.IsNullOrEmpty(dir)) return false;
        var lower = dir.ToLowerInvariant();
        return !lower.StartsWith(@"c:\windows") && !lower.StartsWith(@"c:\program files");
    }

    /// <summary>
    /// Hand the selected ProcMon row off to DLL Techniques. Mirrors the
    /// phantom-from-Scan flow (<c>ScanPage.GenerateSideloadForPhantom</c>):
    /// pick an arch, look up the canonical system DLL via
    /// <see cref="SystemDllResolver"/>, synthesize a <see cref="PeAnalysis"/>
    /// so GeneratePage has the export table it needs for Proxy generation,
    /// fill <c>PendingDeployContext</c> with the searched-dir as the deploy
    /// slot, then navigate. The auto-mode is Proxy when exports exist on the
    /// canonical (forward-chain works), Sideload otherwise.
    /// </summary>
    private void Promote_Click(object sender, RoutedEventArgs e)
    {
        if (DllGrid.SelectedItem is not DllRow row || _lastResult == null)
        {
            SetStatus("Select a row to promote.", StatusKind.Warn);
            return;
        }
        if (row.Mode == ProcmonRowMode.KnownDll)
        {
            SetStatus("KnownDLLs always load from System32 — cannot be sideloaded.", StatusKind.Warn);
            return;
        }

        // ProcMon CSV records process names but not full executable paths, so we
        // can't probe each importer's PE header for arch the way ScanPage does.
        // Default to x64 — the dominant target on modern Windows; the user can
        // override the arch radio buttons in GeneratePage if a 32-bit host is
        // intended. SystemDllResolver will fall through to null when no x64
        // canonical exists, dropping us into Sideload mode automatically.
        const string arch = "x64";
        var resolved = Core.Services.SystemDllResolver.Resolve(row.DllName, arch);
        var exports = resolved?.Analysis.Exports ?? new List<ExportEntry>();
        var autoMode = exports.Count > 0
            ? Core.Models.GenerationMode.Proxy
            : Core.Models.GenerationMode.Sideload;

        // Pick the first user-writable searched dir as the deploy slot. ProcMon
        // emitted these because the loader looked there and couldn't find the
        // DLL — they're literally the slots where dropping a sideloaded copy
        // would intercept. Fall back to the first dir if every entry is in a
        // locked location (the user can still inspect / override in GeneratePage).
        var deployDir = row.Aggregation.SearchedDirs
            .FirstOrDefault(d => IsLikelyUserSpace(d))
            ?? row.Aggregation.SearchedDirs.FirstOrDefault()
            ?? "";

        var synth = new PeAnalysis
        {
            Path = string.IsNullOrEmpty(deployDir)
                ? row.DllName
                : Path.Combine(deployDir, row.DllName),
            Filename = row.DllName,
            Arch = arch,
            IsDll = true,
            FileSize = 0,
            ProductName = "",
            FileVersion = "",
            OriginalFilename = row.DllName,
            Exports = exports,
            NamedExports = resolved?.Analysis.NamedExports ?? 0,
            OrdinalOnlyExports = resolved?.Analysis.OrdinalOnlyExports ?? 0,
        };

        _main.CurrentAnalysis = synth;
        _main.CurrentDllPath = synth.Path;

        // HostExePath is left empty: ProcMon gives us process NAMES but not the
        // launcher path, and by the time the user opens DllSidecar the original
        // process may be long gone. GeneratePage shows the field blank with a
        // hint so the researcher fills it themselves (or accepts Compile-only).
        _main.PendingDeployContext = new MainWindow.DeployContext(
            TargetDir: deployDir,
            TargetName: row.DllName,
            HostExePath: "",
            SystemOrigPath: resolved?.Path,
            AutoMode: autoMode,
            AutoExportCount: exports.Count);

        var modeLabel = autoMode == Core.Models.GenerationMode.Proxy ? "Proxy" : "Sideload";
        var sysTag = resolved != null ? $"sys={resolved.Path}" : "no system match";
        _main.Log($"Promote ProcMon row '{row.DllName}' → DLL Techniques in {modeLabel} mode (arch={arch}, exports={exports.Count}, {sysTag}, deploy={deployDir})");
        _main.NavigateTo(new GeneratePage(_main, autoMode));
    }

    private void LaunchProcmon_Click(object sender, RoutedEventArgs e)
    {
        var procmon = ConfigManager.Current.Tools.ProcmonPath;
        if (string.IsNullOrWhiteSpace(procmon) || !File.Exists(procmon))
        {
            SetStatus("ProcMon path not set — configure it first", StatusKind.Err);
            return;
        }

        var psi = new ProcessStartInfo
        {
            FileName = procmon,
            UseShellExecute = false,
            CreateNoWindow = false,
        };
        // Suggest useful defaults. User can tweak filter manually once launched.
        psi.ArgumentList.Add("/AcceptEula");
        psi.ArgumentList.Add("/Quiet");

        try
        {
            Process.Start(psi);
            SetStatus($"Launched {Path.GetFileName(procmon)}", StatusKind.Ok);
            _main.Log($"Launched ProcMon: {procmon}");
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            SetStatus($"Launch failed: {ex.Message}", StatusKind.Err);
            _main.Log($"Launch ProcMon failed: {ex.Message}");
        }
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

    private class DllRow
    {
        public ProcmonAggregation Aggregation { get; }
        // Computed once at row construction from ProcmonRowClassifier — gating
        // signal for the Mode column, the Hide KnownDLLs filter, and (in the
        // upcoming Promote action) the choice between Proxy and Sideload
        // generation modes.
        public ProcmonRowMode Mode { get; }
        public string? CanonicalPath { get; }

        public DllRow(ProcmonAggregation a)
        {
            Aggregation = a;
            var classification = ProcmonRowClassifier.Classify(a.DllName);
            Mode = classification.Mode;
            CanonicalPath = classification.CanonicalPath;
        }

        public string Risk => Aggregation.RiskHeuristic;
        public string DllName => Aggregation.DllName;
        public int ProcessCount => Aggregation.Processes.Count;
        public int EventCount => Aggregation.EventCount;
        public int DirCount => Aggregation.SearchedDirs.Count;
        public string ProcessList => string.Join(", ", Aggregation.Processes.OrderBy(p => p));

        public string ModeLabel => Mode switch
        {
            ProcmonRowMode.KnownDll   => "KNOWN-DLL",
            ProcmonRowMode.Resolvable => "RESOLVABLE",
            ProcmonRowMode.Phantom    => "PHANTOM",
            _ => "?",
        };
    }
}
