using System.IO;
using System.Windows;
using System.Windows.Controls;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Wizard;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views.Wizard.Stages;

public partial class SurveyStage : System.Windows.Controls.UserControl, IWizardStage
{
    private readonly WizardSession _session;
    private readonly WizardPage _shell;
    private bool _running;

    public SurveyStage(WizardSession session, WizardPage shell)
    {
        _session = session;
        _shell = shell;
        InitializeComponent();
        Loaded += async (_, _) => await RunIfNeeded();
    }

    public bool CanSkip => false;

    public Task<bool> ValidateAndCommit()
    {
        if (_session.ScanResults == null)
        {
            MessageBox.Show("Survey has not completed yet.",
                "Wizard", MessageBoxButton.OK, MessageBoxImage.Warning);
            return Task.FromResult(false);
        }
        var total = _session.ScanResults.ExistingCount + _session.ScanResults.PhantomCount;
        if (total == 0)
        {
            var r = MessageBox.Show(
                "Scan found zero candidates. Continue anyway (you'll have nothing to pick) or pick a different input?",
                "No candidates", MessageBoxButton.YesNo, MessageBoxImage.Question);
            return Task.FromResult(r == MessageBoxResult.Yes);
        }
        return Task.FromResult(true);
    }

    public Task OnSkip() => Task.CompletedTask;

    private async Task RunIfNeeded()
    {
        if (_running) return;
        if (_session.ScanResults != null) { RenderResults(); return; }
        if (string.IsNullOrEmpty(_session.InputPath)) return;
        _running = true;

        try
        {
            // Stage: Input is Directory / SinglePe (Installer was removed).
            string? rootDir = _session.InputPath;

            if (_session.InputKind == WizardInputKind.SinglePe)
            {
                // Single PE — no scan needed; skip to Pick with a synthetic candidate
                _session.ScanResults = new ScanResults();
                _session.SurveyRootDir = Path.GetDirectoryName(_session.InputPath);
                RenderResults();
                StatusLine.Text = "Single PE — skipped scan. The target is preselected for you in the next stage.";
                return;
            }

            _session.SurveyRootDir = rootDir;

            _shell.ShowOverlay("Scanning", $"Analyzing PEs in {rootDir}...");
            var options = new ScanOptions
            {
                RequireImporter = true,
                IncludePhantoms = true,
                AnalyzePrivesc = true,
            };
            _session.ScanResults = await Task.Run(() =>
                new SideloadScanner().Scan(rootDir!, options, null, CancellationToken.None));
            _shell.HideOverlay();

            RenderResults();
        }
        catch (Exception ex)
        {
            Log.Error("wizard.survey", "Survey failed", ex);
            _shell.HideOverlay();
            StatusLine.Text = $"Survey error: {ex.Message}";
        }
        finally
        {
            _running = false;
            _shell.RefreshChrome();
        }
    }

    private void RenderResults()
    {
        var r = _session.ScanResults;
        if (r == null) return;

        StExisting.Text = r.ExistingCount.ToString();
        StPhantoms.Text = r.PhantomCount.ToString();

        int privescCount = r.Existing.Count(c => c.HasPrivescPath) + r.Phantoms.Count(p => p.HasPrivescPath);
        StPrivesc.Text = privescCount.ToString();

        // Default ranking by Total; user can re-sort via column headers.
        var rows = new List<CandidateRow>();
        foreach (var c in r.Existing) rows.Add(new CandidateRow(c));
        foreach (var p in r.Phantoms) rows.Add(new CandidateRow(p));
        rows.Sort((a, b) => b.ScoreValue.CompareTo(a.ScoreValue));

        StTop.Text = rows.Count > 0 ? $"{rows[0].ScoreValue}/10" : "—";

        // Mark top 3 (or all matching highest score) as visually highlighted
        int topScore = rows.Count > 0 ? rows[0].ScoreValue : 0;
        int markedTop = 0;
        for (int i = 0; i < rows.Count && i < 3; i++)
        {
            if (rows[i].ScoreValue > 0 && rows[i].ScoreValue >= topScore - 1)
            {
                rows[i].IsTop = true;
                markedTop++;
            }
        }

        // Show all candidates; grid sizes to fill available height.
        CandidatesGrid.ItemsSource = rows;

        StatusLine.Text = $"Surveyed {_session.SurveyRootDir}" +
            $" · {rows.Count} candidate(s)" +
            (markedTop > 0 ? $" · {markedTop} top highlighted." : "");
        _shell.RefreshChrome();
    }

    public class CandidateRow
    {
        public Core.Models.SideloadCandidate? Existing { get; }
        public Core.Models.PhantomCandidate? Phantom { get; }
        public bool IsTop { get; set; }

        public CandidateRow(Core.Models.SideloadCandidate c) { Existing = c; }
        public CandidateRow(Core.Models.PhantomCandidate p) { Phantom = p; }

        private Core.Models.ScoreBreakdown? Score => Existing?.Score ?? Phantom?.Score;
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
        // OPEN = any standard user · OWNER = only the dir's owner · LOCKED = admin required.
        // Decoupled from the DllSidecar process: same answer whether elevated or not.
        public string DirBadge
        {
            get
            {
                var d = Existing?.Dir ?? Phantom?.Dir;
                if (d == null || !string.IsNullOrEmpty(d.Error)) return "?";
                return d.Tier switch
                {
                    WriteTier.Open      => "OPEN",
                    WriteTier.OwnerOnly => "OWNER",
                    _                   => "LOCKED",
                };
            }
        }
        public string ShortPath
        {
            get
            {
                var p = Existing?.Dll.Path ?? System.IO.Path.Combine(Phantom?.DirectoryPath ?? "", Phantom?.DllName ?? "");
                return p.Length <= 60 ? p : "..." + p[^57..];
            }
        }
    }
}
