using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Services;
using DllSidecar.GUI.Helpers;

namespace DllSidecar.GUI.Views;

public partial class ToolkitPage : Page
{
    private readonly MainWindow _main;

    public ToolkitPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        _ = RefreshAsync();
    }

    public class ToolVm
    {
        public required string Name { get; set; }
        public required string Purpose { get; set; }
        public required string StatusLine { get; set; }
        public required System.Windows.Media.Brush StatusBrush { get; set; }
        public string? DownloadUrl { get; set; }
        public string? Notes { get; set; }
        public string? InstallDefId { get; set; }        // if set, tool has auto-install support
        public bool IsAvailable { get; set; }            // tool is resolved AND working

        public Visibility HasNotes => string.IsNullOrEmpty(Notes) ? Visibility.Collapsed : Visibility.Visible;

        // Install button (accent): shown when tool is MISSING + has auto-install support
        public Visibility ShowInstallButton =>
            (!IsAvailable && !string.IsNullOrEmpty(InstallDefId)) ? Visibility.Visible : Visibility.Collapsed;

        // Re-install button (secondary): shown when tool is ALREADY OK + has auto-install support
        public Visibility ShowReinstallButton =>
            (IsAvailable && !string.IsNullOrEmpty(InstallDefId)) ? Visibility.Visible : Visibility.Collapsed;

        // Open-page button: only when tool is missing AND no auto-install offered (manual link)
        public Visibility ShowDownloadButton =>
            (!IsAvailable && string.IsNullOrEmpty(InstallDefId)) ? Visibility.Visible : Visibility.Collapsed;
    }

    // Map tool Name → catalog Id for auto-install
    private static readonly Dictionary<string, string> AutoInstallable = new()
    {
        ["Process Monitor"] = "procmon",
        ["sigcheck"]        = "sigcheck",
    };

    private async Task RefreshAsync()
    {
        Overlay.Show("Probing toolkit",
            "Running version checks on gcc, windres, Procmon, sigcheck, Python, 7-Zip...");
        ToolkitReport report;
        try { report = await ToolkitChecker.CheckAllAsync(); }
        finally { Overlay.Hide(); }
        ApplyReport(report);
    }

    private void Refresh()
    {
        var report = ToolkitChecker.CheckAll();
        ApplyReport(report);
    }

    private void ApplyReport(ToolkitReport report)
    {

        StatAvailable.Text = $"{report.AvailableCount}/{report.TotalCount}";
        StatRequired.Text = report.RequiredMissing.ToString();
        StatReadiness.Text = report.AllRequiredPresent ? "READY" : "PARTIAL";
        StatReadiness.Foreground = report.AllRequiredPresent
            ? new SolidColorBrush(Color.FromRgb(0xA6, 0xE3, 0xA1))
            : new SolidColorBrush(Color.FromRgb(0xF9, 0xE2, 0xAF));

        // Match by base name — the stored Name may have " *" suffix for required tools
        var vms = report.Tools.Select(t =>
        {
            var baseName = t.Name;
            AutoInstallable.TryGetValue(baseName, out var installId);
            return new ToolVm
            {
                Name = t.Required ? $"{baseName}  *" : baseName,
                Purpose = t.Purpose,
                StatusLine = t.IsAvailable
                    ? $"[OK] {t.ResolvedPath}" + (string.IsNullOrEmpty(t.Version) ? "" : $"  |  {t.Version}")
                    : "[MISSING] not found — configure path or install",
                StatusBrush = new SolidColorBrush(t.IsAvailable
                    ? Color.FromRgb(0xA6, 0xE3, 0xA1)
                    : (t.Required ? Color.FromRgb(0xF3, 0x8B, 0xA8) : Color.FromRgb(0x6C, 0x70, 0x86))),
                DownloadUrl = t.DownloadUrl,
                Notes = t.Notes,
                InstallDefId = installId,
                IsAvailable = t.IsAvailable,
            };
        }).ToList();

        ToolsList.ItemsSource = vms;
        FooterStatus.Text = report.AllRequiredPresent
            ? $"All required tools present ({report.AvailableCount}/{report.TotalCount} total)."
            : $"{report.RequiredMissing} required tool(s) missing — fix before running the pipeline.";
        FooterStatus.Foreground = report.AllRequiredPresent
            ? new SolidColorBrush(Color.FromRgb(0xA6, 0xE3, 0xA1))
            : new SolidColorBrush(Color.FromRgb(0xF3, 0x8B, 0xA8));

        // Footer Sysinternals button: primary "Install" if missing, secondary "Re-install" if present
        var sysDir = ConfigManager.Current.Tools.SysinternalsDir;
        var sysInstalled = !string.IsNullOrWhiteSpace(sysDir) && Directory.Exists(sysDir);
        SysInstallBtn.Visibility = sysInstalled ? Visibility.Collapsed : Visibility.Visible;
        SysReinstallBtn.Visibility = sysInstalled ? Visibility.Visible : Visibility.Collapsed;

        _main.Log($"Toolkit: {report.AvailableCount}/{report.TotalCount} tools available, {report.RequiredMissing} required missing");
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private void Configure_Click(object sender, RoutedEventArgs e)
    {
        _main.NavigateTo(new ConfigPage(_main));
    }

    private void Download_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn && btn.Tag is string url && !string.IsNullOrEmpty(url))
        {
            if (!SafeUrl.Open(url))
                _main.Log($"Could not open {url} — check logs");
        }
    }

    private void OpenSysinternals_Click(object sender, RoutedEventArgs e)
    {
        if (!SafeUrl.Open(ConfigManager.Current.Tools.SysinternalsDownloadUrl))
            _main.Log("Could not open Sysinternals download URL");
    }

    private void Install_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button btn || btn.Tag is not string id) return;
        var def = ToolDownloader.GetById(id);
        if (def == null) { _main.Log($"Unknown tool id: {id}"); return; }

        var dlg = new DownloadDialog(def) { Owner = Window.GetWindow(this) };
        dlg.ShowDialog();

        // Refresh the list — if install succeeded, tool should now show OK
        _ = RefreshAsync();
    }

    private async void InstallSysinternalsSuite_Click(object sender, RoutedEventArgs e)
    {
        var def = ToolDownloader.GetById("sysinternals-suite");
        if (def == null) return;
        var dlg = new DownloadDialog(def) { Owner = Window.GetWindow(this) };
        dlg.ShowDialog();
        await RefreshAsync();
    }
}
