using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Forms;
using System.Windows.Media;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;
using DllSidecar.Core.Services;
using DllSidecar.Core.Services.Privesc;

namespace DllSidecar.GUI.Views;

/// <summary>
/// Standalone privesc analysis module. Runs PrivescAnalyzer against all PE files under a
/// target directory and surfaces EVERY finding — not just those attached to sideload
/// candidates. Used to survey the privesc surface of an install tree before looking at
/// specific sideload targets.
/// </summary>
public partial class PrivescPage : Page
{
    private readonly MainWindow _main;
    private readonly List<FindingRow> _rows = [];
    private CancellationTokenSource? _cts;

    public PrivescPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        DirPathBox.Text = ConfigManager.Current.UiState.LastPrivescDir
            ?? ConfigManager.Current.Paths.LastScanPath
            ?? @"C:\Program Files";
        DirPathBox.TextChanged += (_, _) =>
        {
            if (!IsLoaded) return;
            ConfigManager.Current.UiState.LastPrivescDir = DirPathBox.Text?.Trim();
            ConfigManager.Save();
        };
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new FolderBrowserDialog { Description = "Select directory to analyze for privesc vectors" };
        if (!string.IsNullOrWhiteSpace(DirPathBox.Text) && Directory.Exists(DirPathBox.Text))
            dlg.SelectedPath = DirPathBox.Text;
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            DirPathBox.Text = dlg.SelectedPath;
    }

    private async void Analyze_Click(object sender, RoutedEventArgs e)
    {
        var dir = DirPathBox.Text.Trim();
        if (!Directory.Exists(dir))
        {
            SetStatus("Directory does not exist", StatusKind.Err);
            return;
        }

        _rows.Clear();
        FindingsGrid.ItemsSource = null;
        ResetStats();
        SetScanning(true);
        SetStatus("Analyzing...", StatusKind.Info);
        Overlay.Show("Analyzing privesc surface",
            "Enumerating services registry, scheduled tasks, and PE manifests...");

        _cts = new CancellationTokenSource();
        var ct = _cts.Token;

        try
        {
            var result = await Task.Run(() => RunAnalysis(dir, ct), ct);

            StatPEs.Text = result.PesAnalyzed.ToString();
            StatSystem.Text = result.SystemCount.ToString();
            StatTasks.Text = result.TaskCount.ToString();
            StatAuto.Text = result.AutoElevateCount.ToString();
            StatJackpot.Text = result.JackpotCount.ToString();

            _rows.AddRange(result.Rows);
            FindingsGrid.ItemsSource = _rows;

            SetStatus(
                $"Done — {_rows.Count} finding(s) across {result.PesAnalyzed} PE(s). " +
                $"{result.JackpotCount} jackpot · {result.SystemCount} SYSTEM · {result.TaskCount} task · {result.AutoElevateCount} auto-elevate",
                _rows.Count > 0 ? StatusKind.Ok : StatusKind.Warn);
            _main.Log($"Privesc surface: {dir} → {_rows.Count} findings ({result.JackpotCount} jackpot)");
        }
        catch (OperationCanceledException)
        {
            SetStatus("Cancelled", StatusKind.Warn);
        }
        catch (Exception ex)
        {
            SetStatus($"Failed: {ex.Message}", StatusKind.Err);
            Log.Error("privesc.page", "Analysis failed", ex);
        }
        finally
        {
            Overlay.Hide();
            SetScanning(false);
        }
    }

    private class AnalysisResult
    {
        public int PesAnalyzed { get; set; }
        public int SystemCount { get; set; }
        public int TaskCount { get; set; }
        public int AutoElevateCount { get; set; }
        public int JackpotCount { get; set; }
        public List<FindingRow> Rows { get; } = [];
    }

    private AnalysisResult RunAnalysis(string dir, CancellationToken ct)
    {
        var result = new AnalysisResult();

        // Enumerate PE files in the target directory
        var peFiles = new List<string>();
        try
        {
            foreach (var f in Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (ext is ".exe" or ".dll" or ".sys" or ".ocx")
                    peFiles.Add(f);
            }
        }
        catch (UnauthorizedAccessException) { /* partial results */ }

        // Analyze each PE (needed for PeAnalysis objects; use a lightweight parse)
        var analyses = new List<PeAnalysis>();
        foreach (var f in peFiles)
        {
            ct.ThrowIfCancellationRequested();
            try { analyses.Add(PeAnalyzer.Analyze(f)); }
            catch (Exception ex) { Log.Debug("privesc.page", $"Skipped {f}", ex); }
        }
        result.PesAnalyzed = analyses.Count;

        // Build the detector pipeline — honor filter checkboxes
        var detectors = new List<IPrivescDetector>();
        bool useServices = false, useTasks = false, useAuto = false, useUpdater = false;
        Dispatcher.Invoke(() =>
        {
            useServices = ChkServices.IsChecked == true;
            useTasks = ChkTasks.IsChecked == true;
            useAuto = ChkAutoElevate.IsChecked == true;
            useUpdater = ChkUpdater.IsChecked == true;
        });
        if (useServices) detectors.Add(new ServicesDetector());
        if (useTasks) detectors.Add(new ScheduledTaskDetector());
        if (useAuto) detectors.Add(new AutoElevateDetector());
        if (useUpdater) detectors.Add(new UpdaterHeuristicDetector());

        var analyzer = new PrivescAnalyzer(detectors);
        analyzer.Prepare(dir, analyses, ct);

        foreach (var pe in analyses)
        {
            ct.ThrowIfCancellationRequested();
            var ctx = analyzer.Analyze(pe, ct);
            foreach (var f in ctx.Findings)
            {
                var row = new FindingRow(f, pe);
                result.Rows.Add(row);
                switch (f.Vector)
                {
                    case PrivescVector.ServiceSystem when f.Severity >= PrivescSeverity.High:
                        result.SystemCount++; break;
                    case PrivescVector.ScheduledTask when f.Severity >= PrivescSeverity.Medium:
                        result.TaskCount++; break;
                    case PrivescVector.AutoElevate:
                    case PrivescVector.HighIntegrity:
                        result.AutoElevateCount++; break;
                }
                if (f.Severity == PrivescSeverity.Critical) result.JackpotCount++;
            }
        }

        // Sort: Critical → High → Medium → Low → Info
        result.Rows.Sort((a, b) => b.SeverityOrder.CompareTo(a.SeverityOrder));
        return result;
    }

    private void FindingsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FindingsGrid.SelectedItem is not FindingRow row)
        {
            DetailEmpty.Visibility = Visibility.Visible;
            DetailContent.Visibility = Visibility.Collapsed;
            OpenAnalyzeBtn.Visibility = Visibility.Collapsed;
            return;
        }
        DetailEmpty.Visibility = Visibility.Collapsed;
        DetailContent.Visibility = Visibility.Visible;
        OpenAnalyzeBtn.Visibility = Visibility.Visible;

        DetailTitle.Text = row.Finding.Title;
        DetailPe.Text = row.Pe.Path;
        DetailEvidence.Text = row.Finding.Evidence;

        var ctx = new List<string>();
        if (!string.IsNullOrEmpty(row.Finding.PrivilegedAccount))
            ctx.Add($"Account:  {row.Finding.PrivilegedAccount}");
        if (!string.IsNullOrEmpty(row.Finding.PrivilegedProcessPath))
            ctx.Add($"Runner:   {row.Finding.PrivilegedProcessPath}");
        ctx.Add($"Severity: {row.Finding.Severity}");
        ctx.Add($"Vector:   {row.Finding.Vector}");
        ctx.Add($"Detector: {row.Finding.DetectorName}");
        DetailContext.Text = string.Join("\n", ctx);

        DetailExtras.ItemsSource = row.Finding.Extras;
    }

    private void OpenInAnalyze_Click(object sender, RoutedEventArgs e)
    {
        if (FindingsGrid.SelectedItem is not FindingRow row) return;
        _main.CurrentDllPath = row.Pe.Path;
        _main.NavigateTo(new AnalyzePage(_main));
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        CancelBtn.IsEnabled = false;
    }

    private void SetScanning(bool scanning)
    {
        AnalyzeBtn.IsEnabled = !scanning;
        AnalyzeBtn.Visibility = scanning ? Visibility.Collapsed : Visibility.Visible;
        CancelBtn.IsEnabled = scanning;
        CancelBtn.Visibility = scanning ? Visibility.Visible : Visibility.Collapsed;
        BrowseBtn.IsEnabled = !scanning;
        DirPathBox.IsEnabled = !scanning;
    }

    private void ResetStats()
    {
        StatPEs.Text = "0";
        StatSystem.Text = "0";
        StatTasks.Text = "0";
        StatAuto.Text = "0";
        StatJackpot.Text = "0";
    }

    private enum StatusKind { Info, Ok, Warn, Err }

    private void SetStatus(string text, StatusKind k)
    {
        Status.Text = text;
        Status.Foreground = new SolidColorBrush(k switch
        {
            StatusKind.Ok   => Color.FromRgb(0x00, 0xCA, 0x4E),
            StatusKind.Warn => Color.FromRgb(0xF5, 0xA5, 0x24),
            StatusKind.Err  => Color.FromRgb(0xFF, 0x5B, 0x4F),
            _               => Color.FromRgb(0x73, 0x73, 0x73),
        });
    }

    private class FindingRow
    {
        public PrivescFinding Finding { get; }
        public PeAnalysis Pe { get; }

        public FindingRow(PrivescFinding f, PeAnalysis pe)
        {
            Finding = f;
            Pe = pe;
        }

        public string SeverityLabel => Finding.Severity.ToString().ToUpper();
        public int SeverityOrder => (int)Finding.Severity;
        public string VectorLabel => Finding.Vector.ToString();
        public string PeFilename => Pe.Filename;
        public string Title => Finding.Title;
        public string Account => Finding.PrivilegedAccount ?? "—";

        public SolidColorBrush SeverityBg => Freeze(new SolidColorBrush(Finding.Severity switch
        {
            PrivescSeverity.Critical => Color.FromArgb(0x38, 0xFF, 0x5B, 0x4F),
            PrivescSeverity.High     => Color.FromArgb(0x38, 0xF5, 0xA5, 0x24),
            PrivescSeverity.Medium   => Color.FromArgb(0x38, 0x0A, 0x72, 0xEF),
            PrivescSeverity.Low      => Color.FromArgb(0x26, 0x73, 0x73, 0x73),
            _                        => Color.FromArgb(0x1F, 0x73, 0x73, 0x73),
        }));

        public SolidColorBrush SeverityFg => Freeze(new SolidColorBrush(Finding.Severity switch
        {
            PrivescSeverity.Critical => Color.FromRgb(0xFF, 0x90, 0x85),
            PrivescSeverity.High     => Color.FromRgb(0xFF, 0xC6, 0x6E),
            PrivescSeverity.Medium   => Color.FromRgb(0x6A, 0xB0, 0xFF),
            PrivescSeverity.Low      => Color.FromRgb(0xA1, 0xA1, 0xA1),
            _                        => Color.FromRgb(0x73, 0x73, 0x73),
        }));

        private static SolidColorBrush Freeze(SolidColorBrush b) { b.Freeze(); return b; }
    }
}
