using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
// See BuildPage for rationale: WinForms is referenced fully-qualified to keep
// the global `MessageBox` alias pointing at AppDialog.
using WinForms = System.Windows.Forms;
using System.Windows.Media;
using Microsoft.Win32;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

public partial class ScanPage : Page
{
    private readonly MainWindow _main;
    // _allRows: everything that survived the scan (structural filters only).
    // _rows:    the view subset after applying MinConfidence (a view-side filter because
    //           Confidence can change after ProcMon correlation — filtering at scan time
    //           would drop candidates before evidence exists).
    private readonly List<CandidateRow> _allRows = [];
    private readonly List<CandidateRow> _rows = [];
    private CancellationTokenSource? _cts;
    private ScanResults? _lastScan;

    public ScanPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        DirPathBox.Text = _main.LastScanDir ?? ConfigManager.Current.Paths.LastScanPath ?? "";
        ChkAutoCve.IsChecked = ConfigManager.Current.AutoCveLookup;
        RestoreFilters();
        WireFilterPersistence();

        // Restore previous scan results if still in session — prevents forcing a re-scan
        // when the user navigates away and back
        if (_main.LastScanResults != null)
        {
            _lastScan = _main.LastScanResults;
            foreach (var c in _lastScan.Existing) _allRows.Add(new CandidateRow(c));
            foreach (var p in _lastScan.Phantoms) _allRows.Add(new CandidateRow(p));
            _allRows.Sort((a, b) => b.ScoreValue.CompareTo(a.ScoreValue));
            _ = StampReportedBadgesAsync(); // fire-and-forget on restore; tree rebinds via ApplyViewFilter below
            ApplyViewFilter();

            StatCandidates.Text = _lastScan.ExistingCount.ToString();
            StatPhantoms.Text = _lastScan.PhantomCount.ToString();
            StatTopScore.Text = _rows.Count > 0 ? $"{_rows[0].ScoreValue}/10" : "–";
            CorrelateBtn.IsEnabled = _rows.Count > 0;
            CorrelateEtwBtn.IsEnabled = _rows.Count > 0 && _main.LastEtwResult != null;
            CheckCvesBtn.IsEnabled = _lastScan.Existing.Count > 0;
            PromoteToWizardBtn.IsEnabled = _rows.Count > 0;

            SetStatus($"Restored: {_rows.Count} candidates from previous scan · click SCAN to refresh",
                StatusKind.Info);
        }
    }

    /// <summary>
    /// Filters _allRows → _rows by the view-side MinConfidence combo and rebinds the grid.
    /// Called after scan, after correlate, and when the MinConfidence combo changes.
    /// </summary>
    private void ApplyViewFilter()
    {
        var minConf = ParseCombo(MinConfCombo);
        var q = DllSearchBox?.Text?.Trim() ?? "";
        _rows.Clear();
        foreach (var r in _allRows)
        {
            if (r.ConfidenceValue < minConf) continue;
            if (q.Length > 0
                && !r.Filename.Contains(q, StringComparison.OrdinalIgnoreCase)
                && !r.ShortPath.Contains(q, StringComparison.OrdinalIgnoreCase)
                && !r.KindLabel.Contains(q, StringComparison.OrdinalIgnoreCase)
                && !r.ImportersText.Contains(q, StringComparison.OrdinalIgnoreCase))
                continue;
            _rows.Add(r);
        }
        CandidatesGrid.ItemsSource = null;
        CandidatesGrid.ItemsSource = _rows;
    }

    private void DllSearch_Changed(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyViewFilter();
    }

    private void MinConfCombo_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyViewFilter();
    }

    private void RestoreFilters()
    {
        var s = ConfigManager.Current.UiState.ScanPage;
        ChkRequireImporter.IsChecked = s.RequireImporter;
        ChkOnlyWritable.IsChecked = s.OnlyWritable;
        ChkOnlySignedExe.IsChecked = s.OnlySignedExe;
        ChkIncludePhantoms.IsChecked = s.IncludePhantoms;
        SelectComboByContent(MinExploitCombo, s.MinExploit);
        SelectComboByContent(MinImpactCombo,  s.MinImpact);
        SelectComboByContent(MinConfCombo,    s.MinConf);
    }

    private static void SelectComboByContent(System.Windows.Controls.ComboBox combo, int target)
    {
        for (int i = 0; i < combo.Items.Count; i++)
        {
            if (combo.Items[i] is System.Windows.Controls.ComboBoxItem ci
                && ci.Content is string str
                && int.TryParse(str, out var n) && n == target)
            {
                combo.SelectedIndex = i;
                return;
            }
        }
    }

    private void WireFilterPersistence()
    {
        void Save(object? _, object __) => PersistFilters();
        ChkRequireImporter.Checked  += Save; ChkRequireImporter.Unchecked  += Save;
        ChkOnlyWritable.Checked     += Save; ChkOnlyWritable.Unchecked     += Save;
        ChkOnlySignedExe.Checked    += Save; ChkOnlySignedExe.Unchecked    += Save;
        ChkIncludePhantoms.Checked  += Save; ChkIncludePhantoms.Unchecked  += Save;
        MinExploitCombo.SelectionChanged += Save;
        MinImpactCombo.SelectionChanged  += Save;
        MinConfCombo.SelectionChanged    += Save;
    }

    private void PersistFilters()
    {
        if (!IsLoaded) return;
        var s = ConfigManager.Current.UiState.ScanPage;
        s.RequireImporter = ChkRequireImporter.IsChecked == true;
        s.OnlyWritable    = ChkOnlyWritable.IsChecked == true;
        s.OnlySignedExe   = ChkOnlySignedExe.IsChecked == true;
        s.IncludePhantoms = ChkIncludePhantoms.IsChecked == true;
        s.MinExploit = ParseCombo(MinExploitCombo);
        s.MinImpact  = ParseCombo(MinImpactCombo);
        s.MinConf    = ParseCombo(MinConfCombo);
        ConfigManager.Save();
    }

    public void PrefillAndScan(string directory)
    {
        DirPathBox.Text = directory;
        Dispatcher.BeginInvoke(() => Scan_Click(this, new RoutedEventArgs()));
    }

    private void BrowseDir_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new WinForms.FolderBrowserDialog { Description = "Select install directory to scan" };
        if (!string.IsNullOrWhiteSpace(DirPathBox.Text) && Directory.Exists(DirPathBox.Text))
            dlg.SelectedPath = DirPathBox.Text;
        if (dlg.ShowDialog() == WinForms.DialogResult.OK)
            DirPathBox.Text = dlg.SelectedPath;
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        var dir = DirPathBox.Text.Trim();
        if (!Directory.Exists(dir))
        {
            SetStatus("Directory does not exist", StatusKind.Err);
            return;
        }

        ConfigManager.Current.Paths.LastScanPath = dir;
        ConfigManager.Save();

        _allRows.Clear();
        _rows.Clear();
        CandidatesGrid.ItemsSource = null;
        ScanProgressBar.Value = 0;
        ProgressPct.Text = "0%";
        StatScanned.Text = "0";
        StatTotal.Text = "0";
        StatCandidates.Text = "0";
        StatPhantoms.Text = "0";
        StatTopScore.Text = "–";
        StatElapsed.Text = "0.0s";
        CurrentFile.Text = "";
        PhaseLabel.Text = "starting";
        SetStatus($"Scanning: {dir}", StatusKind.Info);
        SetScanning(true);
        _main.Log($"Scan start: {dir}");
        ClearDetails();

        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        var sw = Stopwatch.StartNew();

        var options = new ScanOptions
        {
            MinExploitability = ParseCombo(MinExploitCombo),
            MinImpact         = ParseCombo(MinImpactCombo),
            // MinConfidence intentionally 0 at scan time — applied as a view-side filter
            // (see ApplyViewFilter) so ProcMon correlation can raise Confidence after scan.
            MinConfidence     = 0,
            RequireImporter = ChkRequireImporter.IsChecked == true,
            OnlyUserWritable = ChkOnlyWritable.IsChecked == true,
            OnlySignedExe = ChkOnlySignedExe.IsChecked == true,
            IncludePhantoms = ChkIncludePhantoms.IsChecked == true,
        };

        var progress = new Progress<ScanProgressInfo>(p =>
        {
            PhaseLabel.Text = p.Phase;
            StatScanned.Text = p.Scanned.ToString();
            if (p.Total > 0) StatTotal.Text = p.Total.ToString();
            if (p.Candidates > 0) StatCandidates.Text = p.Candidates.ToString();
            StatElapsed.Text = $"{sw.Elapsed.TotalSeconds:0.0}s";
            if (!string.IsNullOrEmpty(p.CurrentFile)) CurrentFile.Text = p.CurrentFile;
            if (p.Total > 0)
            {
                var pct = (double)p.Scanned / p.Total * 100.0;
                ScanProgressBar.Value = pct;
                ProgressPct.Text = $"{pct:0}%";
            }
        });

        ScanResults results = new();
        try
        {
            results = await Task.Run(() => new SideloadScanner().Scan(dir, options, progress, ct), ct);
        }
        catch (OperationCanceledException) { /* user clicked Cancel — expected flow */ }
        catch (Exception ex) { _main.Log($"Scan error: {ex.Message}"); }

        sw.Stop();
        _lastScan = results;
        // Persist in MainWindow so it survives navigation
        _main.LastScanResults = results;
        _main.LastScanDir = dir;
        var hasCandidates = (results.Existing.Count + results.Phantoms.Count) > 0;
        CorrelateBtn.IsEnabled = hasCandidates;
        CorrelateEtwBtn.IsEnabled = hasCandidates && _main.LastEtwResult != null;
        CheckCvesBtn.IsEnabled = results.Existing.Count > 0;
        PromoteToWizardBtn.IsEnabled = hasCandidates;
        _allRows.Clear();
        foreach (var c in results.Existing) _allRows.Add(new CandidateRow(c));
        foreach (var p in results.Phantoms) _allRows.Add(new CandidateRow(p));
        _allRows.Sort((a, b) => b.ScoreValue.CompareTo(a.ScoreValue));
        // Cross-reference with the Library so rows already reported get a REPORTED badge.
        await StampReportedBadgesAsync();
        ApplyViewFilter();

        StatCandidates.Text = results.ExistingCount.ToString();
        StatPhantoms.Text = results.PhantomCount.ToString();
        StatTopScore.Text = _rows.Count > 0 ? $"{_rows[0].ScoreValue}/10" : "–";
        StatElapsed.Text = $"{sw.Elapsed.TotalSeconds:0.0}s";
        CurrentFile.Text = "";
        SetScanning(false);

        var cancelled = ct.IsCancellationRequested;
        var highCount = _rows.Count(r => r.ScoreValue >= 7);
        var msg = cancelled
            ? $"Cancelled — {results.ExistingCount} existing + {results.PhantomCount} phantoms"
            : $"Done — {results.ExistingCount} existing + {results.PhantomCount} phantoms ({highCount} high/critical) in {sw.Elapsed.TotalSeconds:0.0}s";
        SetStatus(msg, cancelled ? StatusKind.Warn : StatusKind.Ok);
        _main.Log(msg);

        // Auto CVE dedup (Fase 7b). Fires only on clean finish with at least one existing
        // candidate. CveDedupService caches 24h so rerunning the same scan is cheap. Goes
        // through RunBulkCveDedupAsync directly — CheckCves_Click is the per-DLL window.
        if (!cancelled && ChkAutoCve.IsChecked == true && results.Existing.Count > 0)
        {
            await RunBulkCveDedupAsync();
        }
    }

    private void AutoCve_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        ConfigManager.Current.AutoCveLookup = ChkAutoCve.IsChecked == true;
        ConfigManager.Save();
    }

    /// <summary>
    /// Query the Advisory Library for records that already have a SourceCandidateKey
    /// matching any of the rows we just loaded, and stamp a REPORTED reference on those
    /// rows so the grid can render a badge + status tooltip. Silent on failure (library
    /// might not exist yet on a fresh install).
    /// </summary>
    private async Task StampReportedBadgesAsync()
    {
        try
        {
            var repo = new Core.Services.AdvisoryLibrary.AdvisoryRepository();
            await repo.InitializeAsync();
            var reported = await repo.GetReportedBySourceKeyAsync();
            foreach (var r in _allRows)
            {
                var key = r.BuildSourceKey();
                if (key != null && reported.TryGetValue(key, out var refv))
                    r.Reported = refv;
            }
        }
        catch (Exception ex) { _main.Log($"REPORTED lookup skipped: {ex.Message}"); }
    }

    // Columns mirror the grid so TSV paste / CSV loads give the same triage view the
    // researcher sees in the app. ScoreValue is included as a numeric column too so
    // downstream filtering/sorting (Excel, pandas) doesn't have to parse "7/10".
    private static readonly string[] ExportHeader =
    {
        "Total", "ScoreValue", "Exploit", "Impact", "Conf",
        "Severity", "Privesc", "Kind", "CVE", "Dyn",
        "DLL", "Arch", "DllSig", "Importers", "Writable", "Path",
    };

    private List<string[]> BuildExportRows() => _rows.Select(r => new[]
    {
        r.ScoreText, r.ScoreValue.ToString(), r.ExploitText, r.ImpactText, r.ConfidenceText,
        r.Severity, r.PrivescLabel, r.KindLabel, r.CveLabel, r.DynLabel,
        r.Filename, r.Arch, r.DllSig, r.ImportersText, r.WritableText, r.ShortPath ?? "",
    }).ToList();

    private void CopyList_Click(object sender, RoutedEventArgs e)
    {
        if (_rows.Count == 0) { SetStatus("Nothing to copy — run a scan first", StatusKind.Warn); return; }
        if (Services.ListExporter.CopyTsv(ExportHeader, BuildExportRows(), out var n))
            SetStatus($"Copied {n} candidates to clipboard (TSV).", StatusKind.Ok);
        else
            SetStatus("Clipboard copy failed", StatusKind.Err);
    }

    private void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        if (_rows.Count == 0) { SetStatus("Nothing to export — run a scan first", StatusKind.Warn); return; }
        var dirName = Path.GetFileName(_main.LastScanDir?.TrimEnd('\\') ?? "scan");
        var suggested = $"sideload-candidates-{dirName}-{DateTime.Now:yyyyMMdd-HHmm}.csv";
        var path = Services.ListExporter.SaveCsv(ExportHeader, BuildExportRows(), suggested);
        if (path != null)
        {
            SetStatus($"Exported {_rows.Count} candidates → {Path.GetFileName(path)}", StatusKind.Ok);
            _main.Log($"Scan export: {path}");
        }
    }

    // Physical reparent: take the inline details DockPanel out of its Border, host it in
    // the modal window at 80% of MainWindow size, and push it back on close. Keeps all
    // bindings / selection state / current row live (no data duplication).
    private void ExpandDetails_Click(object sender, RoutedEventArgs e)
    {
        var host = CandidateDetailsHost;
        if (host == null || host.Parent is not Border originalBorder) return;
        originalBorder.Child = null;
        ExpandDetailsBtn.Visibility = Visibility.Collapsed; // hide the icon inside the modal

        var modal = new DetailModalWindow("CANDIDATE DETAILS", host, Window.GetWindow(this));
        modal.Closed += (_, _) =>
        {
            var content = modal.DetachContent();
            if (content is DockPanel back && originalBorder.Child == null)
                originalBorder.Child = back;
            ExpandDetailsBtn.Visibility = Visibility.Visible;
        };
        modal.ShowDialog();
    }

    private static int ParseCombo(System.Windows.Controls.ComboBox combo)
    {
        if (combo.SelectedItem is ComboBoxItem item && item.Content is string s
            && int.TryParse(s, out var v)) return v;
        return 0;
    }

    private void SetScanning(bool scanning)
    {
        ScanBtn.IsEnabled = !scanning;
        ScanBtn.Visibility = scanning ? Visibility.Collapsed : Visibility.Visible;
        CancelBtn.IsEnabled = scanning;
        CancelBtn.Visibility = scanning ? Visibility.Visible : Visibility.Collapsed;
        BrowseBtn.IsEnabled = !scanning;
        DirPathBox.IsEnabled = !scanning;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        CancelBtn.IsEnabled = false;
        SetStatus("Cancelling...", StatusKind.Warn);
    }

    /// <summary>
    /// Per-DLL CVE check: opens a results window for the currently selected candidate so the
    /// researcher can inspect matches in detail (this used to disappear when the bulk-dedup
    /// path took over). Bulk dedup over every candidate is the responsibility of Auto CVE
    /// (the checkbox + RunBulkCveDedupAsync).
    /// </summary>
    private void CheckCves_Click(object sender, RoutedEventArgs e)
    {
        if (CandidatesGrid.SelectedItem is not CandidateRow row)
        {
            MessageBox.Show(
                "Select a candidate first to run a per-DLL CVE check.\n\n" +
                "For a sweep over the whole scan, enable 'Auto CVE lookup' instead.",
                "No selection", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (row.Existing == null)
        {
            // Phantom slots have no PE on disk — vendor/product/filename can't be extracted
            // reliably enough to query NVD. Tell the user instead of silently doing nothing.
            MessageBox.Show(
                "This is a phantom slot — no PE on disk to derive vendor/product from.\n\n" +
                "Pick an existing candidate (one with a real DLL) to run a CVE check.",
                "Phantom selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dlg = new CveResultsWindow(row.Existing.Dll) { Owner = Window.GetWindow(this) };
        dlg.ShowDialog();

        // Reload the candidate's cached CVE result (CveResultsWindow may have cached fresh
        // data) so the table badge in this page reflects what the dialog just showed.
        try
        {
            var fresh = Core.Services.Cve.CveCache.TryGet(
                $"{row.Existing.Dll.CompanyName} {row.Existing.Dll.ProductName} dll hijacking");
            if (fresh != null) row.Existing.Cve = fresh;
            CandidatesGrid.Items.Refresh();
        }
        catch { /* badge refresh is best-effort */ }
    }

    /// <summary>
    /// Bulk dedup across every existing candidate. Triggered ONLY by the Auto CVE flow at the
    /// end of a scan (line ~269) — the per-DLL Check CVEs button no longer routes here.
    /// </summary>
    private async Task RunBulkCveDedupAsync()
    {
        if (_lastScan == null || _lastScan.Existing.Count == 0) return;

        // Only query existing candidates — phantoms don't have a PeAnalysis on disk
        // to extract vendor/product from (synthesized slots with no version info).
        var targets = _lastScan.Existing
            .Where(c => c.Cve == null)
            .ToList();

        if (targets.Count == 0)
        {
            SetStatus("All candidates already have CVE results (cached 24h)", StatusKind.Info);
            CandidatesGrid.Items.Refresh();
            return;
        }

        CheckCvesBtn.IsEnabled = false;
        _main.Log($"CVE dedup starting for {targets.Count} candidates...");
        SetStatus($"Querying NVD for {targets.Count} candidates...", StatusKind.Info);

        // Concurrency 3 — NVD rate limit is 5 req/30s without API key. Keeping
        // below that with some headroom for cache misses. CveCache absorbs reruns.
        using var sem = new System.Threading.SemaphoreSlim(3);
        int done = 0, errors = 0, exact = 0;

        var tasks = targets.Select(async cand =>
        {
            await sem.WaitAsync();
            try
            {
                var r = await Core.Services.Cve.CveDedupService.QueryAsync(cand.Dll);
                cand.Cve = r;
                Interlocked.Increment(ref done);
                if (!string.IsNullOrEmpty(r.Error)) Interlocked.Increment(ref errors);
                if (r.HasExactMatch) Interlocked.Increment(ref exact);
                Dispatcher.Invoke(() =>
                {
                    SetStatus($"CVE dedup: {done}/{targets.Count} queried · {exact} exact · {errors} errors", StatusKind.Info);
                    CandidatesGrid.Items.Refresh();
                });
            }
            finally { sem.Release(); }
        });

        try { await Task.WhenAll(tasks); }
        catch (Exception ex)
        {
            _main.Log($"CVE dedup failed: {ex.Message}");
            SetStatus($"CVE dedup error: {ex.Message}", StatusKind.Err);
            CheckCvesBtn.IsEnabled = true;
            return;
        }

        CheckCvesBtn.IsEnabled = true;
        var kind = exact > 0 ? StatusKind.Warn : StatusKind.Ok;
        var finalMsg = exact > 0
            ? $"CVE dedup done — {exact} EXACT match(es) found · review before reporting. {errors} errors."
            : $"CVE dedup done — {done}/{targets.Count} queried · 0 exact matches. {errors} errors.";
        SetStatus(finalMsg, kind);
        _main.Log(finalMsg);
        CandidatesGrid.Items.Refresh();
    }

    private void Correlate_Click(object sender, RoutedEventArgs e)
    {
        if (_lastScan == null)
        {
            SetStatus("Run a scan first", StatusKind.Err);
            return;
        }

        var dlg = new OpenFileDialog
        {
            Filter = "ProcMon CSV|*.csv|All files|*.*",
            Title = "Select ProcMon CSV export",
        };
        if (dlg.ShowDialog() != true) return;

        SetStatus($"Parsing {Path.GetFileName(dlg.FileName)}...", StatusKind.Info);
        var parsed = ProcmonParser.Parse(dlg.FileName);
        if (!string.IsNullOrEmpty(parsed.Error))
        {
            SetStatus($"CSV parse failed: {parsed.Error}", StatusKind.Err);
            return;
        }

        var report = ProcmonCorrelator.Correlate(_lastScan, parsed);

        // Re-sort on updated Totals; re-apply view filter so MinConfidence actually bites
        // now that evidence exists. This closes the Sprint-1 gap where MinConfidence=9
        // couldn't select "only runtime-confirmed" candidates.
        _allRows.Sort((a, b) => b.ScoreValue.CompareTo(a.ScoreValue));
        ApplyViewFilter();

        var total = report.ExistingMatched + report.PhantomMatched;
        var msg = total > 0
            ? $"Correlation: {report.ExistingMatched} existing + {report.PhantomMatched} phantom candidates verified ({parsed.FilteredRows} events in CSV)"
            : $"Correlation: no match ({parsed.FilteredRows} events in CSV)";
        SetStatus(msg, total > 0 ? StatusKind.Ok : StatusKind.Warn);
        _main.Log(msg);
    }

    /// <summary>
    /// Hand the current scan results to the Research Wizard. The wizard ctor
    /// detects the populated <see cref="WizardSession.ScanResults"/> and resumes
    /// at the Survey stage, skipping Input.
    /// </summary>
    private void PromoteToWizard_Click(object sender, RoutedEventArgs e)
    {
        if (_lastScan == null || _allRows.Count == 0)
        {
            SetStatus("No scan results to promote", StatusKind.Warn);
            return;
        }

        var session = _main.CurrentWizardSession ?? new Core.Models.Wizard.WizardSession();
        session.EntryPoint = Core.Models.Wizard.WizardEntryPoint.ScanFolder;
        session.ScanResults = _lastScan;
        if (!string.IsNullOrEmpty(_main.LastScanDir))
            session.SurveyRootDir = _main.LastScanDir;
        _main.CurrentWizardSession = session;

        _main.Log($"Promoted scan ({_lastScan.ExistingCount} existing + {_lastScan.PhantomCount} phantom) to wizard");
        _main.NavigateTo(new Wizard.WizardPage(_main));
    }

    private void CorrelateEtw_Click(object sender, RoutedEventArgs e)
    {
        if (_lastScan == null || _main.LastEtwResult == null)
        {
            SetStatus("Run a scan and a Runtime Trace first", StatusKind.Err);
            return;
        }

        var procmonResult = EtwResultConverter.ToProcmonResult(_main.LastEtwResult);
        var report = ProcmonCorrelator.Correlate(_lastScan, procmonResult);

        _allRows.Sort((a, b) => b.ScoreValue.CompareTo(a.ScoreValue));
        ApplyViewFilter();

        var total = report.ExistingMatched + report.PhantomMatched;
        var msg = total > 0
            ? $"ETW Correlation: {report.ExistingMatched} existing + {report.PhantomMatched} phantom verified ({_main.LastEtwResult.FilteredEvents} events)"
            : $"ETW Correlation: no match ({_main.LastEtwResult.FilteredEvents} events)";
        SetStatus(msg, total > 0 ? StatusKind.Ok : StatusKind.Warn);
        _main.Log(msg);
    }

    private void CandidatesGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CandidatesGrid.SelectedItem is not CandidateRow row) { ClearDetails(); _main.CurrentAttackFocus = null; return; }
        if (row.Existing != null) PopulateExistingDetails(row.Existing);
        else if (row.Phantom != null) PopulatePhantomDetails(row.Phantom);
        // Make this candidate the focus for AttackPathPage. Phantom path is synthesized
        // (DirectoryPath + DllName) since phantom slots have no file on disk.
        var dllPath = row.Existing?.Dll.Path
            ?? (row.Phantom != null ? Path.Combine(row.Phantom.DirectoryPath, row.Phantom.DllName) : null);
        _main.CurrentAttackFocus = new MainWindow.AttackPathFocus(
            MainWindow.AttackFocusSource.Scan,
            DllName: row.Filename,
            DllPath: dllPath,
            Candidate: row.Existing,
            Phantom: row.Phantom);
    }

    private void CandidatesGrid_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (CandidatesGrid.SelectedItem is not CandidateRow row) return;

        if (row.Existing != null)
        {
            // EXISTING: double-click opens in Analyze — unambiguous flow.
            OpenExistingInAnalyze(row.Existing);
        }
        else if (row.Phantom != null)
        {
            // PHANTOM: three distinct research moves. YesNoCancel with clear mapping.
            // Yes   = Generate Sideload at this slot — the primary research action for phantoms
            // No    = Analyze the importer (see who loads it)
            // Cancel = Stay on scan (details visible in side panel)
            var importer = row.Phantom.Importers.FirstOrDefault()?.ExeFilename ?? "?";
            var res = MessageBox.Show(
                $"Phantom slot '{row.Phantom.DllName}' is a MISSING DLL that an existing PE tries to load. " +
                $"It has no file on disk — that's the attack surface.\n\n" +
                $"What do you want to do?\n\n" +
                $"  Yes    →  Generate a Sideload DLL at this slot (create the replacement)\n" +
                $"  No     →  Analyze the IMPORTER ({importer}) first\n" +
                $"  Cancel →  Stay on scan (see side panel)",
                "Phantom — choose next step",
                MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (res == MessageBoxResult.Yes)
                GenerateSideloadForPhantom(row.Phantom);
            else if (res == MessageBoxResult.No)
                OpenPhantomImporter(row.Phantom);
        }
    }

    private void OpenInAnalyze_Click(object sender, RoutedEventArgs e)
    {
        if (CandidatesGrid.SelectedItem is not CandidateRow row) return;
        if (row.Existing != null) OpenExistingInAnalyze(row.Existing);
        else if (row.Phantom != null) OpenPhantomImporter(row.Phantom);
    }

    private void GenerateSideload_Click(object sender, RoutedEventArgs e)
    {
        if (CandidatesGrid.SelectedItem is not CandidateRow row) return;
        if (row.Phantom != null)
        {
            GenerateSideloadForPhantom(row.Phantom);
        }
        else if (row.Existing != null)
        {
            // For existing DLLs: regular flow — set the existing DLL as target and jump to Sideload generation
            _main.CurrentAnalysis = row.Existing.Dll;
            _main.CurrentDllPath = row.Existing.Dll.Path;
            _main.NavigateTo(new GeneratePage(_main, GenerationMode.Sideload));
        }
    }

    private void OpenExistingInAnalyze(SideloadCandidate c)
    {
        _main.CurrentAnalysis = c.Dll;
        _main.CurrentDllPath = c.Dll.Path;
        _main.NavigateTo(new AnalyzePage(_main));
    }

    private void OpenPhantomImporter(PhantomCandidate p)
    {
        var imp = p.Importers.FirstOrDefault();
        if (imp == null) return;
        _main.CurrentAnalysis = null;
        _main.CurrentDllPath = imp.ExePath;
        _main.Log($"Opening importer '{imp.ExeFilename}' of phantom '{p.DllName}' in Analyze");
        _main.NavigateTo(new AnalyzePage(_main));
    }

    /// <summary>
    /// Synthesize a PeAnalysis representing the phantom DLL slot (no file on disk,
    /// but well-defined name + target dir + expected arch inherited from the importer)
    /// and navigate to GeneratePage in Sideload mode. The user gets a ready-to-build
    /// project that produces the DLL replacement — the research move for phantoms.
    /// </summary>
    private void GenerateSideloadForPhantom(PhantomCandidate p)
    {
        // Pick arch by MAJORITY VOTE across all importers, not FirstOrDefault — a
        // single stray importer of a different arch in the same dir (MobaXterm's
        // mx86_64b\bin\ has a mix) would otherwise leak x64 when the dominant
        // loader is x86, breaking the sideload. Tie → x86 (many targets have
        // an x86 renderer/helper subprocess that is the real sideload entry
        // even when the main EXE is x64 — Acrobat AcroCEF.exe, Electron, etc).
        int x86Votes = 0, x64Votes = 0;
        foreach (var importer in p.Importers)
        {
            var impArch = ResolveImporterArch(importer.ExePath);
            if (impArch == "x86") x86Votes++;
            else if (impArch == "x64") x64Votes++;
        }
        string arch = (x86Votes == 0 && x64Votes == 0) ? "x64"           // nothing to vote on → legacy default
                    : (x86Votes >= x64Votes)            ? "x86" : "x64"; // tie favours x86

        _main.Log($"Arch vote for phantom '{p.DllName}': x86={x86Votes}, x64={x64Votes} → picked {arch}");

        // Primary importer used for the HostExePath default in the deploy banner.
        // Prefer one whose arch matches the winner, so the suggested host actually
        // loads the DLL we're about to build.
        var imp = p.Importers.FirstOrDefault(i => ResolveImporterArch(i.ExePath) == arch)
               ?? p.Importers.FirstOrDefault();

        // Try to locate the canonical system copy of this DLL (System32 for x64 /
        // SysWOW64 for x86). When found, we borrow its export table so the generated
        // DLL exposes the same surface the host will try to bind against — otherwise
        // the loader rejects the import table and payload never fires.
        var resolved = SystemDllResolver.Resolve(p.DllName, arch);
        var exports = resolved?.Analysis.Exports ?? new List<ExportEntry>();
        var autoMode = exports.Count > 0 ? GenerationMode.Proxy : GenerationMode.Sideload;

        var synth = new PeAnalysis
        {
            Path = Path.Combine(p.DirectoryPath, p.DllName),
            Filename = p.DllName,
            Arch = arch,
            IsDll = true,
            FileSize = 0,
            ProductName = "",
            FileVersion = "",
            OriginalFilename = p.DllName,
            Exports = exports,
            // Mirror the counters PeAnalyzer maintains so downstream validations
            // (GeneratePage checks NamedExports, not Exports.Count) work correctly.
            NamedExports = resolved?.Analysis.NamedExports ?? 0,
            OrdinalOnlyExports = resolved?.Analysis.OrdinalOnlyExports ?? 0,
        };

        _main.CurrentAnalysis = synth;
        _main.CurrentDllPath = synth.Path;

        // Hand off the deploy/run context to GeneratePage so the build .bat will
        // copy the compiled DLL into p.DirectoryPath and launch the importer EXE.
        // GeneratePage consumes (and clears) this on Generate.
        if (imp != null)
        {
            _main.PendingDeployContext = new MainWindow.DeployContext(
                TargetDir: p.DirectoryPath,
                TargetName: p.DllName,
                HostExePath: imp.ExePath,
                SystemOrigPath: resolved?.Path,
                AutoMode: autoMode,
                AutoExportCount: exports.Count);
            var modeLabel = autoMode == GenerationMode.Proxy ? "Proxy" : "Sideload";
            var sysTag = resolved != null ? $"sys={resolved.Path}" : "no system match";
            _main.Log($"Generate {modeLabel} for phantom '{p.DllName}' at {p.DirectoryPath} (arch={arch}, exports={exports.Count}, {sysTag}, host={imp.ExeFilename})");
        }
        else
        {
            _main.PendingDeployContext = null;
            _main.Log($"Generate {autoMode} for phantom '{p.DllName}' at {p.DirectoryPath} (arch={arch}, exports={exports.Count}, no importer — bat will compile only)");
        }

        _main.NavigateTo(new GeneratePage(_main, autoMode));
    }

    /// <summary>
    /// Resolve a PE file's arch ("x86" / "x64") using the scan graph first (cheap
    /// lookup) and falling back to a live PeAnalyzer pass if the PE is referenced
    /// by a phantom but wasn't classified as "existing" (e.g. filtered out).
    /// Returns null when the file can't be parsed or doesn't exist.
    /// </summary>
    private string? ResolveImporterArch(string exePath)
    {
        if (string.IsNullOrEmpty(exePath)) return null;
        if (_lastScan != null)
        {
            var impPe = _lastScan.Existing
                .Select(c => c.Dll)
                .FirstOrDefault(dll => string.Equals(dll.Path, exePath, StringComparison.OrdinalIgnoreCase));
            if (impPe != null) return impPe.Arch;
        }
        try { return PeAnalyzer.Analyze(exePath).Arch; }
        catch { return null; }
    }

    private void CopyPath_Click(object sender, RoutedEventArgs e)
    {
        if (CandidatesGrid.SelectedItem is not CandidateRow row) return;
        var path = row.Existing?.Dll.Path ??
            Path.Combine(row.Phantom?.DirectoryPath ?? "", row.Phantom?.DllName ?? "");
        try
        {
            System.Windows.Clipboard.SetText(path);
            _main.Log($"Copied: {path}");
        }
        catch (System.Runtime.InteropServices.COMException ex)
        {
            // Clipboard can be locked by another process — transient, inform user
            _main.Log($"Clipboard unavailable (another process holds it): {ex.Message}");
        }
    }


    private void ClearDetails()
    {
        DetailsEmpty.Visibility = Visibility.Visible;
        DetailsContent.Visibility = Visibility.Collapsed;
        ActionBar.Visibility = Visibility.Collapsed;
    }

    private void PopulateExistingDetails(SideloadCandidate c)
    {
        DetailsEmpty.Visibility = Visibility.Collapsed;
        DetailsContent.Visibility = Visibility.Visible;
        ActionBar.Visibility = Visibility.Visible;

        var dynTag = c.IsDynamicallyVerified ? "  [VERIFIED DYN]" : "";
        var privTag = c.HasPrivescPath ? $"  [{c.Privesc!.ShortLabel}]" : "";
        DetailTitle.Text = $"[EXISTING]  {c.Dll.Filename}{dynTag}{privTag}  —  {c.Score.Total}/10 ({c.Score.Severity})";
        DetailPath.Text = c.Dll.Path;
        PopulateScoreAxes(c.Score);
        PopulateChain(c.Privesc, c, null);
        DetailAcl.Text = FormatAcl(c.Dir);
        DetailDllSig.Text = FormatSigning(c.DllSigning);
        DetailEvidence.Text = FormatEvidence(c.Evidence);
        PopulatePrivesc(c.Privesc);
        DetailImporters.ItemsSource = FormatImporters(c.Importers);
        DetailFactors.ItemsSource = FormatFactors(c.Score.Factors);
    }

    private void PopulatePhantomDetails(PhantomCandidate p)
    {
        DetailsEmpty.Visibility = Visibility.Collapsed;
        DetailsContent.Visibility = Visibility.Visible;
        ActionBar.Visibility = Visibility.Visible;

        var dynTag = p.IsDynamicallyVerified ? "  [VERIFIED DYN]" : "";
        var privTag = p.HasPrivescPath ? $"  [{p.Privesc!.ShortLabel}]" : "";
        DetailTitle.Text = $"[PHANTOM]  {p.DllName}{dynTag}{privTag}  —  {p.Score.Total}/10 ({p.Score.Severity})";
        DetailPath.Text = $"Drop target: {Path.Combine(p.DirectoryPath, p.DllName)}\n" +
                          $"Searched (not found) in:\n  " + string.Join("\n  ", p.SearchedLocations);
        PopulateScoreAxes(p.Score);
        PopulateChain(p.Privesc, null, p);
        DetailAcl.Text = FormatAcl(p.Dir);
        DetailDllSig.Text = "N/A — phantom slot (DLL does not exist; drop yours here)";
        DetailEvidence.Text = FormatEvidence(p.Evidence);
        PopulatePrivesc(p.Privesc);
        DetailImporters.ItemsSource = FormatImporters(p.Importers);
        DetailFactors.ItemsSource = FormatFactors(p.Score.Factors);
    }

    private void PopulateScoreAxes(ScoreBreakdown s)
    {
        DetailExploitBadge.Text = $"EXPLOIT {s.Exploitability}/10";
        DetailImpactBadge.Text  = $"IMPACT {s.Impact}/10";
        DetailConfBadge.Text    = $"CONF {s.Confidence}/10 · {s.ConfidenceLevel}";
    }

    private void PopulateChain(PrivescContext? priv, SideloadCandidate? existing, PhantomCandidate? phantom)
    {
        // Per-step list (Sprint 3 Attack Path)
        if (priv == null || priv.ChainSteps.Count == 0)
        {
            DetailChainSummary.Text = "(no chain available — privesc context empty)";
            DetailChainSteps.ItemsSource = null;
        }
        else
        {
            DetailChainSummary.Text = priv.ChainSummary;
            DetailChainSteps.ItemsSource = FormatChainSteps(priv.ChainSteps);
        }

        // DiscoveredVia trace (only for Sprint-3 targeted re-scan candidates — phantoms
        // are never discovered indirectly because they have no file on disk to resolve to)
        if (existing?.Discovery == DiscoveryOrigin.PrivescResolvedTarget &&
            !string.IsNullOrEmpty(existing.DiscoveredViaLabel))
        {
            DetailDiscoveredVia.Text = existing.DiscoveredViaLabel;
            DetailDiscoveredViaBlock.Visibility = Visibility.Visible;
        }
        else
        {
            DetailDiscoveredViaBlock.Visibility = Visibility.Collapsed;
        }
    }

    private static IEnumerable<object> FormatChainSteps(IReadOnlyList<ChainStep> steps) =>
        steps.Select(s => new
        {
            KindLabel = s.Kind switch
            {
                ChainStepKind.WritePrimitive  => "WRITE",
                ChainStepKind.LoadVector      => "LOAD",
                ChainStepKind.Trigger         => "TRIGGER",
                ChainStepKind.Privilege       => "PRIV",
                ChainStepKind.RuntimeEvidence => "EVIDENCE",
                _ => "?",
            },
            KindBg = MakeBrush(s.Kind, bg: true),
            KindFg = MakeBrush(s.Kind, bg: false),
            Label = s.Label,
            Detail = s.Detail ?? "",
            DetailVisibility = string.IsNullOrEmpty(s.Detail) ? Visibility.Collapsed : Visibility.Visible,
        });

    private static SolidColorBrush MakeBrush(ChainStepKind kind, bool bg)
    {
        // Per-kind colour: write=yellow, load=blue, trigger=mauve, priv=red, evidence=phosphor
        var (r, g, b) = kind switch
        {
            ChainStepKind.WritePrimitive  => ((byte)0xF9, (byte)0xE2, (byte)0xAF),
            ChainStepKind.LoadVector      => ((byte)0x0A, (byte)0x72, (byte)0xEF),
            ChainStepKind.Trigger         => ((byte)0xCB, (byte)0xA6, (byte)0xF7),
            ChainStepKind.Privilege       => ((byte)0xFF, (byte)0x5B, (byte)0x4F),
            ChainStepKind.RuntimeEvidence => ((byte)0x00, (byte)0xF0, (byte)0xA3),
            _                             => ((byte)0x73, (byte)0x73, (byte)0x73),
        };
        var brush = new SolidColorBrush(bg ? Color.FromArgb(0x33, r, g, b) : Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

    private void PopulatePrivesc(PrivescContext? priv)
    {
        if (priv == null || priv.Findings.Count == 0)
        {
            DetailPrivescSummary.Text = "(no privesc path detected)";
            DetailPrivescFindings.ItemsSource = null;
            return;
        }

        DetailPrivescSummary.Text =
            $"Highest: {priv.HighestSeverity}  |  Vector: {priv.PrimaryVector}  |  Findings: {priv.Findings.Count}";

        DetailPrivescFindings.ItemsSource = priv.Findings
            .OrderByDescending(f => f.Severity)
            .Select(f => new
            {
                Vector = f.Vector.ToString(),
                SeverityLabel = f.Severity.ToString().ToUpper(),
                SeverityBg = SeverityBrush(f.Severity, bg: true),
                SeverityFg = SeverityBrush(f.Severity, bg: false),
                Title = f.Title,
                Evidence = BuildEvidenceLine(f),
            })
            .ToList();
    }

    private static string BuildEvidenceLine(PrivescFinding f)
    {
        var parts = new List<string> { f.Evidence };
        if (!string.IsNullOrEmpty(f.PrivilegedProcessPath))
            parts.Add($"runner: {f.PrivilegedProcessPath}");
        if (!string.IsNullOrEmpty(f.PrivilegedAccount))
            parts.Add($"as: {f.PrivilegedAccount}");
        if (f.Extras.TryGetValue("SourcePE", out var src))
            parts.Add($"via: {src}");
        return string.Join("  ·  ", parts);
    }

    private static SolidColorBrush SeverityBrush(PrivescSeverity sev, bool bg) => sev switch
    {
        PrivescSeverity.Critical      => bg ? RgbBrush(0xFF, 0x5B, 0x4F, 0.18) : RgbBrush(0xFF, 0x90, 0x85),
        PrivescSeverity.High          => bg ? RgbBrush(0xF5, 0xA5, 0x24, 0.18) : RgbBrush(0xFF, 0xC6, 0x6E),
        PrivescSeverity.Medium        => bg ? RgbBrush(0x0A, 0x72, 0xEF, 0.18) : RgbBrush(0x6A, 0xB0, 0xFF),
        PrivescSeverity.Low           => bg ? RgbBrush(0x73, 0x73, 0x73, 0.18) : RgbBrush(0xA1, 0xA1, 0xA1),
        PrivescSeverity.Informational => bg ? RgbBrush(0x73, 0x73, 0x73, 0.12) : RgbBrush(0x73, 0x73, 0x73),
        _                             => bg ? RgbBrush(0x26, 0x26, 0x26, 1.0)  : RgbBrush(0x52, 0x52, 0x52),
    };

    private static SolidColorBrush RgbBrush(byte r, byte g, byte b, double opacity = 1.0)
    {
        var br = new SolidColorBrush(Color.FromRgb(r, g, b)) { Opacity = opacity };
        br.Freeze();
        return br;
    }

    private static string FormatEvidence(DynamicEvidence? ev)
    {
        if (ev == null) return "(no ProcMon CSV loaded — static-only result)";
        var lines = new List<string>
        {
            $"Events:     {ev.EventCount}",
            $"Match:      {(ev.MatchedByDirectory ? "NAME+DIR (high confidence)" : "NAME only (DLL matches; dir differs)")}",
            $"Processes:  {string.Join(", ", ev.Processes)}",
        };
        if (ev.SearchedDirs.Count > 0)
            lines.Add("Dirs:\n  " + string.Join("\n  ", ev.SearchedDirs));
        return string.Join("\n", lines);
    }

    private static string FormatAcl(DirectoryPermissions d)
    {
        var lines = new List<string>
        {
            $"Path:               {d.Path}",
            $"BUILTIN\\Users:      {YesNo(d.UsersWrite)}",
            $"Everyone:           {YesNo(d.EveryoneWrite)}",
            $"AuthenticatedUsers: {YesNo(d.AuthenticatedUsersWrite)}",
            $"Current user (effective): {YesNo(d.CurrentUserWrite)}",
        };
        if (d.WritableBy.Count > 0) lines.Add($"Other principals:   {string.Join(", ", d.WritableBy)}");
        if (!string.IsNullOrEmpty(d.Error)) lines.Add($"Error: {d.Error}");
        return string.Join("\n", lines);
    }

    private static IEnumerable<object> FormatImporters(List<ImporterRef> imps) =>
        imps.Select(i => new
        {
            Filename = i.ExeFilename,
            Meta = $"{(i.Signing.IsTrusted ? "SIGNED" : i.Signing.Status.ToString().ToUpper())}" +
                   $"  |  {SubsystemName(i.Subsystem)}" +
                   $"{(i.IsDelayLoad ? "  |  DELAY-LOAD" : "")}" +
                   $"{(i.ForcesSystem32Only ? "  |  SYS32-ONLY" : "")}" +
                   $"\n{i.ExePath}",
        });

    private static IEnumerable<object> FormatFactors(List<ScoreFactor> factors) =>
        // Order by axis then by absolute-impact so each axis block reads top-down by weight
        factors
            .OrderBy(f => (int)f.Axis)
            .ThenByDescending(f => Math.Abs(f.Points))
            .Select(f => new
            {
                Axis = f.Axis switch
                {
                    ScoreAxis.Exploitability => "EXPLOIT",
                    ScoreAxis.Impact         => "IMPACT",
                    ScoreAxis.Confidence     => "CONF",
                    _                        => "?",
                },
                AxisBrush = (SolidColorBrush)(f.Axis switch
                {
                    ScoreAxis.Exploitability => new SolidColorBrush(Color.FromRgb(0x00, 0xF0, 0xA3)),
                    ScoreAxis.Impact         => new SolidColorBrush(Color.FromRgb(0xFF, 0x5B, 0x4F)),
                    ScoreAxis.Confidence     => new SolidColorBrush(Color.FromRgb(0x0A, 0x72, 0xEF)),
                    _                        => new SolidColorBrush(Color.FromRgb(0x6C, 0x70, 0x86)),
                }),
                Points = f.Points >= 0 ? $"+{f.Points}" : f.Points.ToString(),
                PointsBrush = (SolidColorBrush)(f.Points > 0
                    ? new SolidColorBrush(Color.FromRgb(0xA6, 0xE3, 0xA1))
                    : f.Points < 0
                        ? new SolidColorBrush(Color.FromRgb(0xF3, 0x8B, 0xA8))
                        : new SolidColorBrush(Color.FromRgb(0x6C, 0x70, 0x86))),
                Reason = f.Reason,
            });

    private static string FormatSigning(SigningInfo s)
    {
        var lines = new List<string>
        {
            $"Status:   {s.Status}",
        };
        if (!string.IsNullOrEmpty(s.Subject)) lines.Add($"Subject:  {s.Subject}");
        if (!string.IsNullOrEmpty(s.Issuer)) lines.Add($"Issuer:   {s.Issuer}");
        if (s.NotAfter.HasValue) lines.Add($"Expires:  {s.NotAfter:yyyy-MM-dd}");
        if (!string.IsNullOrEmpty(s.ThumbprintSha1)) lines.Add($"SHA1:     {s.ThumbprintSha1}");
        if (!string.IsNullOrEmpty(s.ErrorMessage) && s.Status != SigningStatus.Valid)
            lines.Add($"Error:    {s.ErrorMessage}");
        return string.Join("\n", lines);
    }

    private static string SubsystemName(ushort s) => s switch
    {
        1 => "native",
        2 => "GUI",
        3 => "console",
        9 => "WinCE",
        _ => $"subsys_{s}",
    };

    private static string YesNo(bool b) => b ? "YES" : "no";

    private enum StatusKind { Info, Ok, Warn, Err }

    private void SetStatus(string text, StatusKind k)
    {
        ScanStatus.Text = text;
        ScanStatus.Foreground = new SolidColorBrush(k switch
        {
            StatusKind.Ok   => Color.FromRgb(0xA6, 0xE3, 0xA1),
            StatusKind.Warn => Color.FromRgb(0xF9, 0xE2, 0xAF),
            StatusKind.Err  => Color.FromRgb(0xF3, 0x8B, 0xA8),
            _               => Color.FromRgb(0x6C, 0x70, 0x86),
        });
    }

    // Row view-model — wraps either an existing-DLL candidate or a phantom drop-point
    private class CandidateRow
    {
        public SideloadCandidate? Existing { get; }
        public PhantomCandidate? Phantom { get; }
        /// <summary>Populated by StampReportedBadgesAsync if a library record matches this candidate.</summary>
        public Core.Services.AdvisoryLibrary.AdvisoryRepository.ReportedRef? Reported { get; set; }

        public CandidateRow(SideloadCandidate c) { Existing = c; }
        public CandidateRow(PhantomCandidate p) { Phantom = p; }

        /// <summary>Build the canonical SourceCandidateKey for cross-ref with the library.</summary>
        public string? BuildSourceKey()
        {
            if (Existing != null && !string.IsNullOrWhiteSpace(Existing.Dll.Path))
                return $"existing|{Existing.Dll.Path.Trim().ToLowerInvariant()}";
            if (Phantom != null)
                return $"phantom|{Phantom.DirectoryPath.Trim().ToLowerInvariant()}|{Phantom.DllName.Trim().ToLowerInvariant()}";
            return null;
        }

        public string ReportedLabel => Reported == null ? "" : "REPORTED";
        public string ReportedTooltip => Reported == null
            ? ""
            : $"Already in library: {Reported.Title}  ·  status: {Reported.Status}  ·  updated {Reported.UpdatedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm}";
        public System.Windows.Media.Brush ReportedBg => Reported == null
            ? Freeze(new SolidColorBrush(Colors.Transparent))
            : Freeze(new SolidColorBrush(Color.FromArgb(0x33, 0x00, 0xF0, 0xA3)));
        public System.Windows.Media.Brush ReportedFg => Reported == null
            ? Freeze(new SolidColorBrush(Colors.Transparent))
            : Freeze(new SolidColorBrush(Color.FromRgb(0x00, 0xF0, 0xA3)));

        public string KindLabel
        {
            get
            {
                if (Phantom != null)
                    return Phantom.Evidence?.Source == EvidenceSource.RuntimeTrace ? "RUNTIME" : "IAT";
                return Existing?.Discovery switch
                {
                    DiscoveryOrigin.PrivescResolvedTarget => "RESOLVED",
                    DiscoveryOrigin.DynamicRuntime => "RUNTIME",
                    _ => "EXISTING",
                };
            }
        }
        public SolidColorBrush KindBg => Freeze(new SolidColorBrush(KindLabel switch
        {
            "RUNTIME"  => Color.FromArgb(0x30, 0x00, 0xF0, 0xA3),
            "IAT"      => Color.FromArgb(0x30, 0x0A, 0x72, 0xEF),
            "RESOLVED" => Color.FromArgb(0x30, 0xF5, 0xA5, 0x24),
            _          => Color.FromArgb(0x22, 0x73, 0x73, 0x73),
        }));
        public SolidColorBrush KindFg => Freeze(new SolidColorBrush(KindLabel switch
        {
            "RUNTIME"  => Color.FromRgb(0x00, 0xF0, 0xA3),
            "IAT"      => Color.FromRgb(0x6A, 0xB0, 0xFF),
            "RESOLVED" => Color.FromRgb(0xFF, 0xC6, 0x6E),
            _          => Color.FromRgb(0xA1, 0xA1, 0xA1),
        }));

        public string DynLabel
        {
            get
            {
                var ev = Existing?.Evidence ?? Phantom?.Evidence;
                if (ev == null) return "—";
                return ev.MatchedByDirectory ? "VERIF" : "name";
            }
        }

        private DllSidecar.Core.Models.Cve.CveQueryResult? Cve => Existing?.Cve ?? Phantom?.Cve;
        public string CveLabel
        {
            get
            {
                var c = Cve;
                if (c == null) return "?";
                if (!string.IsNullOrEmpty(c.Error)) return "ERR";
                if (c.HasExactMatch) return "EXACT!";
                if (c.Matches.Count == 0) return "0";
                return c.Matches.Count.ToString();
            }
        }
        public int CveSortKey
        {
            get
            {
                var c = Cve;
                if (c == null) return -1;                       // not queried last
                if (c.HasExactMatch) return 1_000_000;          // exact first
                if (!string.IsNullOrEmpty(c.Error)) return -2;  // errors dead last
                return c.Matches.Count;
            }
        }
        public SolidColorBrush CveBg => Freeze(new SolidColorBrush(CveLabel switch
        {
            "EXACT!" => Color.FromArgb(0x40, 0xFF, 0x5B, 0x4F),
            "ERR"    => Color.FromArgb(0x30, 0xF5, 0xA5, 0x24),
            "?"      => Color.FromArgb(0x22, 0x73, 0x73, 0x73),
            "0"      => Color.FromArgb(0x30, 0x00, 0xCA, 0x4E),
            _        => Color.FromArgb(0x30, 0xF5, 0xA5, 0x24),
        }));
        public SolidColorBrush CveFg => Freeze(new SolidColorBrush(CveLabel switch
        {
            "EXACT!" => Color.FromRgb(0xFF, 0x90, 0x85),
            "ERR"    => Color.FromRgb(0xFF, 0xC6, 0x6E),
            "?"      => Color.FromRgb(0xA1, 0xA1, 0xA1),
            "0"      => Color.FromRgb(0x5F, 0xE5, 0x8A),
            _        => Color.FromRgb(0xFF, 0xC6, 0x6E),
        }));
        public string CveTooltip
        {
            get
            {
                var c = Cve;
                if (c == null) return "Not queried — click 'Check CVEs' to run NVD dedup";
                if (!string.IsNullOrEmpty(c.Error)) return $"Query failed: {c.Error}";
                if (c.HasExactMatch) return $"{c.ExactCount} EXACT match(es) — likely dup, check before reporting. Total NVD hits: {c.Matches.Count}";
                if (c.Matches.Count == 0) return "No CVEs found for this vendor/product + DLL hijacking keywords";
                return $"{c.Matches.Count} related CVE(s) found · {c.LikelyCount} likely · {c.ExactCount} exact";
            }
        }
        private ScoreBreakdown? Score => Existing?.Score ?? Phantom?.Score;
        public int ScoreValue => Score?.Total ?? 0;
        public int ExploitValue => Score?.Exploitability ?? 0;
        public int ImpactValue => Score?.Impact ?? 0;
        public int ConfidenceValue => Score?.Confidence ?? 0;
        public string ScoreText => $"{ScoreValue}/10";
        public string ExploitText => ExploitValue.ToString();
        public string ImpactText => ImpactValue.ToString();
        public string ConfidenceText => ConfidenceValue.ToString();
        public string Severity => Score?.Severity ?? "?";

        // Cross-surface ExploitabilityVerdict (Phase 4) — same record the
        // VerdictBadge control consumes on AnalyzePage / ProcmonPage / Runtime.
        // Computed lazily so we don't re-evaluate on every binding refresh.
        private Core.Services.Exploitability.ExploitabilityVerdict? _verdict;
        private bool _verdictComputed;
        public Core.Services.Exploitability.ExploitabilityVerdict? Verdict
        {
            get
            {
                if (_verdictComputed) return _verdict;
                _verdictComputed = true;
                if (Existing != null) _verdict = Core.Services.Exploitability.ExploitabilityVerdict.For.Candidate(Existing);
                else if (Phantom != null) _verdict = Core.Services.Exploitability.ExploitabilityVerdict.For.Phantom(Phantom);
                return _verdict;
            }
        }
        public int VerdictSortKey => Verdict?.Score ?? 0;
        public string Filename => Existing?.Dll.Filename ?? Phantom?.DllName ?? "?";
        public string Arch => Existing?.Dll.Arch ?? "—";

        public string DllSig => Existing != null
            ? Existing.DllSigning.Status switch
              {
                  SigningStatus.Valid     => "signed",
                  SigningStatus.NotSigned => "unsigned",
                  SigningStatus.Invalid   => "invalid",
                  SigningStatus.Untrusted => "untrusted",
                  _ => "?",
              }
            : "—";

        public string ImportersText
        {
            get
            {
                var imps = Existing?.Importers ?? Phantom?.Importers ?? new List<ImporterRef>();
                var n = imps.Count;
                var signed = imps.Count(i => i.Signing.IsTrusted);
                return signed > 0 ? $"{n} ({signed} signed)" : n.ToString();
            }
        }

        public string WritableText
        {
            get
            {
                var dir = Existing?.Dir ?? Phantom?.Dir;
                if (dir == null) return "?";
                return dir.IsLowPrivWritable ? "LOW-PRIV" : dir.CurrentUserWrite ? "user" : "admin";
            }
        }

        public string PrivescLabel
        {
            get
            {
                var priv = Existing?.Privesc ?? Phantom?.Privesc;
                return priv?.ShortLabel ?? "—";
            }
        }

        public SolidColorBrush PrivescBg
        {
            get
            {
                var priv = Existing?.Privesc ?? Phantom?.Privesc;
                if (priv == null || priv.Findings.Count == 0)
                    return Freeze(new SolidColorBrush(Color.FromArgb(0x22, 0x73, 0x73, 0x73)));
                return priv.HighestSeverity switch
                {
                    PrivescSeverity.Critical => Freeze(new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0x5B, 0x4F))),
                    PrivescSeverity.High     => Freeze(new SolidColorBrush(Color.FromArgb(0x33, 0xF5, 0xA5, 0x24))),
                    PrivescSeverity.Medium   => Freeze(new SolidColorBrush(Color.FromArgb(0x33, 0x0A, 0x72, 0xEF))),
                    _                        => Freeze(new SolidColorBrush(Color.FromArgb(0x22, 0x73, 0x73, 0x73))),
                };
            }
        }

        public SolidColorBrush PrivescFg
        {
            get
            {
                var priv = Existing?.Privesc ?? Phantom?.Privesc;
                if (priv == null || priv.Findings.Count == 0)
                    return Freeze(new SolidColorBrush(Color.FromRgb(0x73, 0x73, 0x73)));
                return priv.HighestSeverity switch
                {
                    PrivescSeverity.Critical => Freeze(new SolidColorBrush(Color.FromRgb(0xFF, 0x90, 0x85))),
                    PrivescSeverity.High     => Freeze(new SolidColorBrush(Color.FromRgb(0xFF, 0xC6, 0x6E))),
                    PrivescSeverity.Medium   => Freeze(new SolidColorBrush(Color.FromRgb(0x6A, 0xB0, 0xFF))),
                    _                        => Freeze(new SolidColorBrush(Color.FromRgb(0xA1, 0xA1, 0xA1))),
                };
            }
        }

        private static SolidColorBrush Freeze(SolidColorBrush b) { b.Freeze(); return b; }

        public string ShortPath
        {
            get
            {
                var p = Existing?.Dll.Path ?? Path.Combine(Phantom?.DirectoryPath ?? "", Phantom?.DllName ?? "");
                return p.Length <= 60 ? p : "..." + p[^57..];
            }
        }
    }
}
