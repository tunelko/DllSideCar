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
    // Per-page ACL cache; cleared on reparse.
    private readonly DirAclCache _dirAcl = new();

    public ProcmonPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        UpdateLaunchBtn();
        RestorePersistedState();
        WirePersistence();
        // Re-hydrate from MainWindow session state if a parse exists.
        if (_main.LastProcmonResult != null)
        {
            RehydrateFromLastResult();
        }
        // Session-restore path: only the CSV path survives restart, so re-parse.
        else if (!string.IsNullOrEmpty(_main.LastProcmonCsvPath) && File.Exists(_main.LastProcmonCsvPath))
        {
            Loaded += AutoParseOnce;
        }
    }

    private void AutoParseOnce(object sender, RoutedEventArgs e)
    {
        Loaded -= AutoParseOnce;
        CsvPathBox.Text = _main.LastProcmonCsvPath ?? "";
        Parse_Click(this, new RoutedEventArgs());
    }

    /// <summary>Reconstructs grid, stats and status from a previously-parsed result on MainWindow.</summary>
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

        UpdateElevationBanner();

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
    { "Risk", "DLL", "Access", "Loads", "Probes", "Procs", "Events", "Dirs", "Processes" };

    private List<string[]> BuildExportRows()
    {
        var view = DllGrid.ItemsSource as IEnumerable<DllRow> ?? _allRows;
        return view.Select(r => new[]
        {
            r.Risk, r.DllName, r.AccessLabel, r.LoadCount.ToString(), r.ProbeCount.ToString(),
            r.ProcessCount.ToString(), r.EventCount.ToString(), r.DirCount.ToString(), r.ProcessList,
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
            // ACL probes run off the UI thread to avoid freezing on large CSVs.
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

        UpdateElevationBanner();

        ApplyViewFilter();

        // Park parse on MainWindow for re-hydration after navigation.
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

    /// <summary>Shows the UAC elevation banner naming the top privesc carrier DLLs.</summary>
    private void UpdateElevationBanner()
    {
        if (_lastResult == null || _lastResult.Transitions.Count == 0)
        {
            ElevationBanner.Visibility = Visibility.Collapsed;
            return;
        }

        var ts = _lastResult.Transitions;
        string header;
        if (ts.Count == 1)
        {
            var t = ts[0];
            var gap = t.Gap?.TotalMilliseconds switch
            {
                null => "gap: n/a",
                < 1000 => $"gap: {t.Gap!.Value.TotalMilliseconds:F0} ms",
                _ => $"gap: {t.Gap!.Value.TotalSeconds:F2} s",
            };
            header = $"{t.ProcessName}  PID {t.ParentPid} -> {t.ChildPid}  ({gap})";
        }
        else
        {
            header = $"{ts.Count} transitions: " +
                string.Join("  ·  ",
                    ts.Select(t => $"{t.ProcessName} PID {t.ParentPid}->{t.ChildPid}"));
        }

        // Strict carrier identification shared with RuntimeTracePage.
        var carriers = PrivescCarrierIdentifier.FromAggregations(_lastResult.ByDll, _dirAcl);

        if (carriers.Count == 0)
        {
            ElevationBannerText.Text =
                header + "\nNo privesc carrier DLL identified — the elevated child loaded only from KnownDLLs, locked dirs, or probe-only paths.";
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
        PromotePrivescBtn.Tag = carriers; // top carrier picked up by the handler
    }

    /// <summary>Hand the carrier list to PrivescPage and navigate; chain explanation renders there.</summary>
    private void PromotePrivesc_Click(object sender, RoutedEventArgs e)
    {
        if (PromotePrivescBtn.Tag is not List<PrivescCarrier> carriers || carriers.Count == 0)
        {
            SetStatus("No carriers ranked — re-parse the CSV", StatusKind.Warn);
            return;
        }

        var summary = BuildTransitionSummary();
        _main.PendingPrivescHandoff = new MainWindow.PrivescCarrierHandoff(
            SourceLabel: "ProcMon CSV",
            Carriers: carriers,
            TransitionSummary: summary);
        _main.NavigateTo(new PrivescPage(_main));
    }

    private string BuildTransitionSummary()
    {
        if (_lastResult == null || _lastResult.Transitions.Count == 0) return "";
        var ts = _lastResult.Transitions;
        if (ts.Count == 1)
        {
            var t = ts[0];
            return $"{t.ProcessName} PID {t.ParentPid} -> {t.ChildPid}";
        }
        return string.Join(" · ", ts.Select(t => $"{t.ProcessName} {t.ParentPid}->{t.ChildPid}"));
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

        // KnownDLLs always load from System32 — filter them out.
        if (ChkHideKnownDlls.IsChecked == true)
            view = view.Where(r => r.Mode != ProcmonRowMode.KnownDll);

        // Hide rows where every searched directory is admin-only.
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
        // Promotion blocked only for KnownDLLs; Promote handler picks Proxy/Sideload mode.
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

    /// <summary>Hand selected row to DLL Techniques: synthesize PeAnalysis, fill PendingDeployContext, navigate. Mode: Proxy when canonical has exports, Sideload otherwise.</summary>
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

        // Access-class gate: warn when all events are probe-only (planted DLL would not execute).
        if (row.LoadCount == 0 && row.ProbeCount > 0)
        {
            var r = AppDialog.Show(
                Window.GetWindow(this),
                $"All {row.ProbeCount} event(s) for '{row.DllName}' are metadata-only probes " +
                $"(GetFileAttributes-class — {Core.Models.AccessClassLabels.Probe} in Detail).\n\n" +
                $"The loader never attempted a real image-map open. A planted DLL at any of " +
                $"the searched paths would NOT be loaded — the app is enumerating PATH on its " +
                $"own (e.g. which(), version-detect, or conflict scan).\n\n" +
                $"Promote anyway?",
                "Probe-only evidence",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);
            if (r != MessageBoxResult.Yes)
            {
                SetStatus("Promote cancelled — probe-only evidence (no loader open observed).", StatusKind.Warn);
                return;
            }
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

        // Default to x64; user can override in GeneratePage if 32-bit host intended.
        const string arch = "x64";
        var resolved = Core.Services.SystemDllResolver.Resolve(row.DllName, arch);
        var exports = resolved?.Analysis.Exports ?? new List<ExportEntry>();
        var autoMode = exports.Count > 0
            ? Core.Models.GenerationMode.Proxy
            : Core.Models.GenerationMode.Sideload;

        // Pick the first user-writable searched dir as deploy slot.
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

        // HostExePath left empty: ProcMon CSV has process names only.
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
        // Gating signal for Mode column, Hide KnownDLLs filter, Promote mode.
        public ProcmonRowMode Mode { get; }
        public string? CanonicalPath { get; }

        // Writability tier across SearchedDirs; drives Dir column color and Promote warning.
        public ProcmonDirWritability Writability { get; }

        public DllRow(ProcmonAggregation a, DirAclCache dirAcl)
        {
            Aggregation = a;
            var classification = ProcmonRowClassifier.Classify(a.DllName);
            Mode = classification.Mode;
            CanonicalPath = classification.CanonicalPath;
            Writability = ProcmonRowWritabilityClassifier.Classify(a.SearchedDirs, dirAcl);
            // Route through PrivescCarrierIdentifier so badge and banner agree row-by-row.
            var carrierInput = new CarrierInput(
                DllName: a.DllName,
                IsHighIlSearch: a.HighIlSearch,
                SearchedDirs: a.SearchedDirs.ToList(),
                LoaderLikeCount: a.LoaderLikeCount,
                MetadataProbeCount: a.MetadataProbeCount,
                EventCount: a.EventCount);
            bool isCarrier = PrivescCarrierIdentifier.Qualifies(carrierInput, dirAcl, out _);
            Verdict = ExploitabilityVerdict.For.ProcmonRow(Mode, Writability, isCarrier);
        }

        public string Risk => Aggregation.RiskHeuristic;
        public string DllName => Aggregation.DllName;
        public int ProcessCount => Aggregation.Processes.Count;
        public int EventCount => Aggregation.EventCount;
        public int DirCount => Aggregation.SearchedDirs.Count;
        public string ProcessList => string.Join(", ", Aggregation.Processes.OrderBy(p => p));

        // Loader-vs-probe split from AccessClassifier; powers Access column.
        public int LoadCount  => Aggregation.LoaderLikeCount;
        public int ProbeCount => Aggregation.MetadataProbeCount;
        public string AccessLabel => Core.Models.AccessClassLabels.FromCounts(LoadCount, ProbeCount);
        public string AccessTooltip =>
            LoadCount == 0 && ProbeCount == 0
                ? "Classification unavailable — CSV missing Detail or events were Unknown"
                : $"Loader-like opens: {LoadCount} · Metadata probes: {ProbeCount}\n" +
                  $"{Core.Models.AccessClassLabels.Load} = real loader image-map open. " +
                  $"{Core.Models.AccessClassLabels.Probe} = GetFileAttributes-class call " +
                  "(app enumerating PATH, planted DLL would not execute).";

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

        // Unified verdict consumed by VerdictBadge across all surfaces.
        public ExploitabilityVerdict Verdict { get; }
        public int VerdictSortKey => Verdict.Score;
    }
}
