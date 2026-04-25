using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Cve;
using DllSidecar.Core.Services.Cve;
using DllSidecar.GUI.Helpers;

namespace DllSidecar.GUI.Views;

public partial class CveResultsWindow : Window
{
    private readonly PeAnalysis _pe;

    public CveResultsWindow(PeAnalysis pe)
    {
        _pe = pe;
        InitializeComponent();
        Services.WindowChromeHelper.Apply(this, $"CVE dedup — {pe.Filename}");
        HeaderTitle.Text = $"CVE dedup — {pe.Filename}";
        HeaderSubtitle.Text = $"Querying NVD for '{pe.ProductName}' · {pe.Filename} · Checking for existing CVE-427 / DLL hijacking reports.";
        Loaded += async (_, _) => await RunQuery();
    }

    private async Task RunQuery()
    {
        Overlay.Show("Querying NVD", "Checking existing CVEs for this PE...");
        CveQueryResult result;
        try
        {
            result = await Task.Run(() => CveDedupService.QueryAsync(_pe));
        }
        catch (Exception ex)
        {
            Log.Error("cve.ui", "Query failed", ex);
            result = new CveQueryResult { Error = ex.Message };
        }
        finally { Overlay.Hide(); }

        ApplyResult(result);
    }

    private void ApplyResult(CveQueryResult r)
    {
        if (!string.IsNullOrEmpty(r.Error))
        {
            FooterStatus.Text = $"Error: {r.Error}";
            FooterStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x5B, 0x4F));
            MatchesList.ItemsSource = Array.Empty<object>();
            return;
        }

        StatExact.Text = r.ExactCount.ToString();
        StatLikely.Text = r.LikelyCount.ToString();
        StatRelated.Text = r.Matches.Count(m => m.Confidence == MatchConfidence.Related).ToString();
        StatTotal.Text = r.TotalFromApi.ToString();

        if (r.HasExactMatch)
        {
            WarningBanner.Visibility = Visibility.Visible;
            WarningTitle.Text = "⚠  LIKELY DUPLICATE — Exact match found in NVD";
            WarningDetail.Text = "The target DLL name is mentioned explicitly in one or more CVE descriptions " +
                                 "for this vendor/product. Do NOT report without verifying that your finding is a " +
                                 "different vulnerability (different version, different code path, different file).";
        }

        MatchesList.ItemsSource = r.Matches.Select(m => new MatchRow(m)).ToList();

        var cacheFlag = r.FromCache ? " (cached)" : "";
        FooterStatus.Text = $"Query: '{r.Query}' · {r.Matches.Count} unique matches from {r.TotalFromApi} NVD hits{cacheFlag}";
        FooterStatus.Foreground = new SolidColorBrush(Color.FromRgb(0x73, 0x73, 0x73));
    }

    private void OpenUrl_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button b && b.Tag is string url) SafeUrl.Open(url);
    }

    private void CopyCve_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button b && b.Tag is string cveId)
        {
            try { System.Windows.Clipboard.SetText(cveId); }
            catch (Exception ex) { Log.Warn("cve.ui", "Clipboard failed", ex); }
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private class MatchRow
    {
        public CveMatch M { get; }
        public MatchRow(CveMatch m) { M = m; }

        public string CveId => M.CveId;
        public string Description => M.Description;
        public string ConfidenceLabel => M.Confidence switch
        {
            MatchConfidence.Exact => "EXACT",
            MatchConfidence.Likely => "LIKELY",
            MatchConfidence.Related => "RELATED",
            _ => "UNRELATED",
        };
        public string NvdUrl => M.NvdUrl;

        public SolidColorBrush ConfidenceBg => Freeze(new SolidColorBrush(M.Confidence switch
        {
            MatchConfidence.Exact    => Color.FromArgb(0x38, 0xFF, 0x5B, 0x4F),
            MatchConfidence.Likely   => Color.FromArgb(0x38, 0xF5, 0xA5, 0x24),
            MatchConfidence.Related  => Color.FromArgb(0x38, 0x0A, 0x72, 0xEF),
            _                        => Color.FromArgb(0x22, 0x73, 0x73, 0x73),
        }));

        public SolidColorBrush ConfidenceFg => Freeze(new SolidColorBrush(M.Confidence switch
        {
            MatchConfidence.Exact    => Color.FromRgb(0xFF, 0x90, 0x85),
            MatchConfidence.Likely   => Color.FromRgb(0xFF, 0xC6, 0x6E),
            MatchConfidence.Related  => Color.FromRgb(0x6A, 0xB0, 0xFF),
            _                        => Color.FromRgb(0x73, 0x73, 0x73),
        }));

        public string CvssText => M.CvssScore.HasValue
            ? $"CVSS {M.CvssScore:0.0} {M.CvssSeverity}"
            : "CVSS —";

        public string MetaLine
        {
            get
            {
                var parts = new List<string>();
                if (!string.IsNullOrEmpty(M.Vendor) || !string.IsNullOrEmpty(M.Product))
                    parts.Add($"{M.Vendor ?? "?"}/{M.Product ?? "?"}");
                if (M.PublishedDate.HasValue)
                    parts.Add($"published {M.PublishedDate:yyyy-MM-dd}");
                if (M.Cwes.Count > 0)
                    parts.Add(string.Join(" ", M.Cwes));
                return string.Join("  ·  ", parts);
            }
        }

        public string ReasonsLine => M.MatchReasons.Count > 0
            ? "Match: " + string.Join(" · ", M.MatchReasons)
            : "";

        public Visibility ReasonsVisibility => M.MatchReasons.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        private static SolidColorBrush Freeze(SolidColorBrush b) { b.Freeze(); return b; }
    }
}
