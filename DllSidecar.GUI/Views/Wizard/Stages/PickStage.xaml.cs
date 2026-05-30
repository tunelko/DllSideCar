using System.IO;
using System.Windows;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Wizard;

namespace DllSidecar.GUI.Views.Wizard.Stages;

public partial class PickStage : System.Windows.Controls.UserControl, IWizardStage
{
    private readonly WizardSession _session;
    private readonly WizardPage _shell;
    private readonly List<Row> _rows = [];
    private readonly List<Row> _filtered = [];

    public PickStage(WizardSession session, WizardPage shell)
    {
        _session = session;
        _shell = shell;
        InitializeComponent();
        LoadRows();
    }

    public bool CanSkip => false;

    public Task<bool> ValidateAndCommit()
    {
        // Single-PE case: skip and synthesize target from input
        if (_session.InputKind == WizardInputKind.SinglePe &&
            !string.IsNullOrEmpty(_session.InputPath) &&
            File.Exists(_session.InputPath))
        {
            try
            {
                var pe = Core.Services.PeAnalyzer.Analyze(_session.InputPath);
                _session.ChosenExisting = new SideloadCandidate { Dll = pe };
                _session.ChosenPhantom = null;
                return Task.FromResult(true);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to analyze PE: {ex.Message}",
                    "Wizard", MessageBoxButton.OK, MessageBoxImage.Warning);
                return Task.FromResult(false);
            }
        }

        if (Grid.SelectedItem is not Row row)
        {
            MessageBox.Show("Pick a row from the list before continuing.",
                "No target", MessageBoxButton.OK, MessageBoxImage.Warning);
            return Task.FromResult(false);
        }
        _session.ChosenExisting = row.Existing;
        _session.ChosenPhantom = row.Phantom;
        return Task.FromResult(true);
    }

    public Task OnSkip() => Task.CompletedTask;

    private void LoadRows()
    {
        if (_session.ScanResults == null) return;
        foreach (var c in _session.ScanResults.Existing) _rows.Add(new Row(c));
        foreach (var p in _session.ScanResults.Phantoms) _rows.Add(new Row(p));
        // Default sort: derived Total. Column headers allow per-axis re-sorting.
        _rows.Sort((a, b) => b.ScoreValue.CompareTo(a.ScoreValue));
        ApplyFilter();
        if (_filtered.Count > 0)
        {
            // Auto-select current session choice or top row
            var current = _filtered.FirstOrDefault(r =>
                (_session.ChosenExisting != null && r.Existing == _session.ChosenExisting) ||
                (_session.ChosenPhantom != null && r.Phantom == _session.ChosenPhantom));
            Grid.SelectedItem = current ?? _filtered[0];
        }
    }

    private void SearchBox_Changed(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyFilter();
    }

    /// <summary>Rebuilds <see cref="_filtered"/> from <see cref="_rows"/> using SearchBox query, preserving selection.</summary>
    private void ApplyFilter()
    {
        var q = SearchBox?.Text?.Trim() ?? "";
        _filtered.Clear();
        foreach (var r in _rows)
        {
            if (q.Length > 0
                && !r.Filename.Contains(q, StringComparison.OrdinalIgnoreCase)
                && !r.ShortPath.Contains(q, StringComparison.OrdinalIgnoreCase)
                && !r.Kind.Contains(q, StringComparison.OrdinalIgnoreCase)
                && !r.Privesc.Contains(q, StringComparison.OrdinalIgnoreCase))
                continue;
            _filtered.Add(r);
        }

        var previouslySelected = Grid.SelectedItem as Row;
        Grid.ItemsSource = null;
        Grid.ItemsSource = _filtered;
        if (previouslySelected != null && _filtered.Contains(previouslySelected))
            Grid.SelectedItem = previouslySelected;
    }

    // ---- Copy / Export (uniform placement with RuntimeTrace / Scan / Procmon) ----

    private static readonly string[] ExportHeader =
    {
        "Total", "Exploit", "Impact", "Conf", "Kind", "DLL", "Access", "Privesc", "Dir", "Path",
    };

    private List<string[]> BuildExportRows() => _filtered.Select(r => new[]
    {
        r.ScoreText, r.ExploitText, r.ImpactText, r.ConfidenceText,
        r.Kind, r.Filename, r.AccessLabel, r.Privesc, r.DirBadge, r.ShortPath,
    }).ToList();

    private void CopyList_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        if (_filtered.Count == 0) return;
        Services.ListExporter.CopyTsv(ExportHeader, BuildExportRows(), out _);
    }

    private void ExportCsv_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        if (_filtered.Count == 0) return;
        var suggested = $"wizard-pick-{DateTime.Now:yyyyMMdd-HHmm}.csv";
        Services.ListExporter.SaveCsv(ExportHeader, BuildExportRows(), suggested);
    }

    private class Row
    {
        public SideloadCandidate? Existing { get; }
        public PhantomCandidate? Phantom { get; }
        public Row(SideloadCandidate c) { Existing = c; }
        public Row(PhantomCandidate p) { Phantom = p; }

        private ScoreBreakdown? Score => Existing?.Score ?? Phantom?.Score;
        public int ScoreValue => Score?.Total ?? 0;
        public int ExploitValue => Score?.Exploitability ?? 0;
        public int ImpactValue => Score?.Impact ?? 0;
        public int ConfidenceValue => Score?.Confidence ?? 0;
        public string ScoreText => $"{ScoreValue}/10";
        public string ExploitText => ExploitValue.ToString();
        public string ImpactText => ImpactValue.ToString();
        public string ConfidenceText => ConfidenceValue.ToString();
        public string Kind => Existing != null ? "EXISTING"
            : Phantom?.Evidence?.Source == EvidenceSource.RuntimeTrace ? "RUNTIME" : "IAT";
        public string Filename => Existing?.Dll.Filename ?? Phantom?.DllName ?? "";
        public string Privesc => (Existing?.Privesc ?? Phantom?.Privesc)?.ShortLabel ?? "—";

        // Access label mirrors ProcMon's Options: field; empty when no runtime evidence.
        public string AccessLabel
        {
            get
            {
                var ev = Existing?.Evidence ?? Phantom?.Evidence;
                return ev?.AccessLabel ?? "";
            }
        }
        public string AccessTooltip
        {
            get
            {
                var ev = Existing?.Evidence ?? Phantom?.Evidence;
                if (ev == null) return "No runtime evidence yet";
                return $"Loader-like opens: {ev.LoaderLikeEventCount} · Metadata probes: {ev.MetadataProbeEventCount}\n" +
                       $"{Core.Models.AccessClassLabels.Load} = real loader image-map open. " +
                       $"{Core.Models.AccessClassLabels.Probe} = GetFileAttributes-class call " +
                       "(app enumerating PATH, planted DLL would not execute).";
            }
        }
        // OPEN = low-priv writable · USER = current user only · LOCKED = admin · ? = ACL check failed.
        public string DirBadge
        {
            get
            {
                var d = Existing?.Dir ?? Phantom?.Dir;
                if (d == null || !string.IsNullOrEmpty(d.Error)) return "?";
                if (d.IsLowPrivWritable) return "OPEN";
                if (d.CurrentUserWrite)  return "USER";
                return "LOCKED";
            }
        }
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
