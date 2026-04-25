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
    }

    private void RestorePersistedState()
    {
        var s = ConfigManager.Current.UiState.ProcmonPage;
        if (!string.IsNullOrEmpty(s.LastCsvPath)) CsvPathBox.Text = s.LastCsvPath;
        ChkOnlyUserSpace.IsChecked = s.OnlyUserSpace;
        ChkOnlyHighRisk.IsChecked  = s.OnlyHighRisk;
    }

    private void WirePersistence()
    {
        void Save(object? _, object __) => PersistState();
        CsvPathBox.TextChanged  += Save;
        ChkOnlyUserSpace.Checked += Save; ChkOnlyUserSpace.Unchecked += Save;
        ChkOnlyHighRisk.Checked  += Save; ChkOnlyHighRisk.Unchecked  += Save;
    }

    private void PersistState()
    {
        if (!IsLoaded) return;
        var s = ConfigManager.Current.UiState.ProcmonPage;
        s.LastCsvPath   = CsvPathBox.Text?.Trim();
        s.OnlyUserSpace = ChkOnlyUserSpace.IsChecked == true;
        s.OnlyHighRisk  = ChkOnlyHighRisk.IsChecked == true;
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
            return;
        }

        DetailsEmpty.Visibility = Visibility.Collapsed;
        DetailsContent.Visibility = Visibility.Visible;

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
        public DllRow(ProcmonAggregation a) { Aggregation = a; }

        public string Risk => Aggregation.RiskHeuristic;
        public string DllName => Aggregation.DllName;
        public int ProcessCount => Aggregation.Processes.Count;
        public int EventCount => Aggregation.EventCount;
        public int DirCount => Aggregation.SearchedDirs.Count;
        public string ProcessList => string.Join(", ", Aggregation.Processes.OrderBy(p => p));
    }
}
