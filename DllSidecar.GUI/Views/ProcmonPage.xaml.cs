using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;
using DllSidecar.Core.Services.Exploitability;

namespace DllSidecar.GUI.Views;

public partial class ProcmonPage : Page
{
    private readonly MainWindow _main;
    private ProcmonParser.ParseResult? _lastResult;
    // Master list — never mutated after parse. View grid binds to filtered projection.
    private readonly List<DllRow> _allRows = [];
    // Per-page ACL cache so the writability gate doesn't re-probe the same
    // directories thousands of times when a CSV references the same paths
    // from many rows. Lives with the page — cleared if the user reparses.
    private readonly DirAclCache _dirAcl = new();

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
        foreach (var a in _lastResult.ByDll) _allRows.Add(new DllRow(a, _dirAcl));

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
        ChkHideLockedDirs.IsChecked = s.HideLockedDirs;
    }

    private void WirePersistence()
    {
        void Save(object? _, object __) => PersistState();
        CsvPathBox.TextChanged  += Save;
        ChkOnlyUserSpace.Checked += Save; ChkOnlyUserSpace.Unchecked += Save;
        ChkOnlyHighRisk.Checked  += Save; ChkOnlyHighRisk.Unchecked  += Save;
        ChkHideKnownDlls.Checked += Save; ChkHideKnownDlls.Unchecked += Save;
        ChkHideLockedDirs.Checked += Save; ChkHideLockedDirs.Unchecked += Save;
    }

    private void PersistState()
    {
        if (!IsLoaded) return;
        var s = ConfigManager.Current.UiState.ProcmonPage;
        s.LastCsvPath    = CsvPathBox.Text?.Trim();
        s.OnlyUserSpace  = ChkOnlyUserSpace.IsChecked == true;
        s.OnlyHighRisk   = ChkOnlyHighRisk.IsChecked == true;
        s.HideKnownDlls  = ChkHideKnownDlls.IsChecked == true;
        s.HideLockedDirs = ChkHideLockedDirs.IsChecked == true;
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
        _dirAcl.Clear();   // fresh ACL view per parse (target install may have changed between runs)
        List<DllRow> built;
        try
        {
            _lastResult = await Task.Run(() => ProcmonParser.Parse(path));
            if (!string.IsNullOrEmpty(_lastResult.Error))
            {
                Overlay.Hide();
                SetStatus(_lastResult.Error, StatusKind.Err);
                return;
            }
            // Row construction triggers ACL probes (one File.WriteAllText per
            // unique dir on first hit). Off the UI thread so 5000-row CSVs
            // don't freeze the window for the 1-2s the probes can take.
            Overlay.UpdateSubtitle($"Checking ACLs on {_lastResult.ByDll.SelectMany(a => a.SearchedDirs).Distinct(StringComparer.OrdinalIgnoreCase).Count()} unique dirs...");
            built = await Task.Run(() =>
                _lastResult.ByDll.Select(a => new DllRow(a, _dirAcl)).ToList());
        }
        finally { Overlay.Hide(); }

        _allRows.Clear();
        _allRows.AddRange(built);

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

        // Writability gate — when every searched directory requires admin to
        // write, planting a sideloaded DLL already needs elevation, which
        // collapses the threat model. Hide them by default; rows with at
        // least one user-writable slot (or Unknown verdict) stay visible.
        if (ChkHideLockedDirs.IsChecked == true)
            view = view.Where(r => r.Writability != ProcmonDirWritability.AllLocked);

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

        // Writability gate — warn (don't block) when every searched dir
        // requires admin to write. The PoC will still compile fine, but
        // dropping it into one of those slots would already need elevation,
        // which collapses the classic CWE-427 threat model. Researcher
        // confirms before we hand off, so the limitation is visible.
        if (row.Writability == ProcmonDirWritability.AllLocked)
        {
            var dirsBlock = string.Join("\n  ", row.Aggregation.SearchedDirs.OrderBy(d => d, StringComparer.OrdinalIgnoreCase));
            var r = AppDialog.Show(
                Window.GetWindow(this),
                $"None of the NAME-NOT-FOUND directories for '{row.DllName}' are writable by low-privilege users:\n\n  {dirsBlock}\n\n" +
                $"Dropping a sideloaded copy into any of these slots already requires admin rights. The classic CWE-427 threat model collapses without low-priv write access — the resulting PoC would only fire from an already-elevated context.\n\n" +
                $"Promote anyway?",
                "Locked search paths",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);
            if (r != MessageBoxResult.Yes)
            {
                SetStatus("Promote cancelled — every searched dir is locked.", StatusKind.Warn);
                return;
            }
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

        // Writability tier across this row's SearchedDirs. Computed at row
        // construction by probing each dir through DirAclCache (cache keeps
        // bulk parses fast). Drives the Dir column color, the Hide locked
        // filter, and the warning shown by Promote when no writable slot
        // exists.
        public ProcmonDirWritability Writability { get; }

        public DllRow(ProcmonAggregation a, DirAclCache dirAcl)
        {
            Aggregation = a;
            var classification = ProcmonRowClassifier.Classify(a.DllName);
            Mode = classification.Mode;
            CanonicalPath = classification.CanonicalPath;
            Writability = ProcmonRowWritabilityClassifier.Classify(a.SearchedDirs, dirAcl);
            Verdict = ExploitabilityVerdict.For.ProcmonRow(Mode, Writability);
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

        public string WritabilityLabel => Writability switch
        {
            ProcmonDirWritability.AllLowPrivWritable => "WRITABLE",
            ProcmonDirWritability.Mixed              => "MIXED",
            ProcmonDirWritability.AllLocked          => "LOCKED",
            _ => "—",
        };

        // Unified ExploitabilityVerdict (Phase 4) — same record the VerdictBadge
        // control consumes on AnalyzePage and ScanPage. Combines Mode + Writability
        // into a single tier + score so the row reads at-a-glance without forcing
        // the researcher to mentally cross both columns.
        public ExploitabilityVerdict Verdict { get; }
        public int VerdictSortKey => Verdict.Score;
    }
}
