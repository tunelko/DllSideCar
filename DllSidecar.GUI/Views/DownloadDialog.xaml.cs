using System.Windows;
using System.Windows.Media;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

public partial class DownloadDialog : Window
{
    private readonly ToolDownloadDef _def;
    private CancellationTokenSource? _cts;
    public bool InstalledSuccessfully { get; private set; }

    public DownloadDialog(ToolDownloadDef def)
    {
        _def = def;
        InitializeComponent();
        Services.WindowChromeHelper.Apply(this, $"Install — {_def.DisplayName}");
        ToolTitle.Text = _def.DisplayName;
        ToolSubtitle.Text = $"{_def.Url}\nInstall → %LOCALAPPDATA%\\DllSidecar\\tools\\{_def.InstallSubdir}\\";
        AppendLog($"Target: {_def.DisplayName}");
        AppendLog($"URL:    {_def.Url}");
        AppendLog($"Size cap: {_def.MaxSizeBytes / (1024 * 1024)} MB");
        AppendLog($"Will verify: {string.Join(", ", _def.BinariesToVerify)}");
        AppendLog("");
        AppendLog("Click Install to begin. Cancel to abort.");
    }

    private async void Install_Click(object sender, RoutedEventArgs e)
    {
        InstallBtn.IsEnabled = false;
        CancelBtn.Content = "Abort";
        _cts = new CancellationTokenSource();

        var progress = new Progress<DownloadProgress>(p =>
        {
            PhaseLabel.Text = p.Phase.ToString().ToUpper();
            if (p.TotalBytes.HasValue)
            {
                ProgressBar.Value = p.Percent;
                PercentLabel.Text = $"{p.Percent:0}%  ({p.BytesReceived:N0} / {p.TotalBytes:N0} B)";
            }
            else
            {
                PercentLabel.Text = p.BytesReceived > 0 ? $"{p.BytesReceived:N0} B" : "";
            }
            if (!string.IsNullOrEmpty(p.Message)) AppendLog($"[{PhaseLabel.Text}] {p.Message}");
            PhaseLabel.Foreground = p.Phase switch
            {
                DownloadPhase.Done   => new SolidColorBrush(Color.FromRgb(0xA6, 0xE3, 0xA1)),
                DownloadPhase.Failed => new SolidColorBrush(Color.FromRgb(0xF3, 0x8B, 0xA8)),
                _                    => new SolidColorBrush(Color.FromRgb(0x89, 0xB4, 0xFA)),
            };
        });

        DownloadResult result;
        try
        {
            result = await Task.Run(() => ToolDownloader.InstallAsync(_def, progress, _cts.Token), _cts.Token);
        }
        catch (Exception ex)
        {
            AppendLog($"FATAL: {ex.GetType().Name}: {ex.Message}");
            result = new DownloadResult { Success = false, ErrorMessage = ex.Message };
        }

        AppendLog("");
        if (result.Success)
        {
            AppendLog($"[+] Installed to: {result.InstallPath}");
            foreach (var vs in result.VerifiedSigned) AppendLog($"    verified: {vs}");
            foreach (var (k, v) in result.ResolvedBinaries) AppendLog($"    config.{k} = {v}");
            InstalledSuccessfully = true;
        }
        else
        {
            AppendLog($"[!] Failed: {result.ErrorMessage}");
            foreach (var vf in result.VerificationFailures) AppendLog($"    {vf}");
        }

        InstallBtn.Visibility = Visibility.Collapsed;
        CancelBtn.Visibility = Visibility.Collapsed;
        CloseBtn.Visibility = Visibility.Visible;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if (_cts != null && !_cts.IsCancellationRequested)
        {
            AppendLog("[!] Cancelling...");
            _cts.Cancel();
        }
        else
        {
            DialogResult = false;
            Close();
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = InstalledSuccessfully;
        Close();
    }

    private void AppendLog(string line)
    {
        LogBox.AppendText(line + "\n");
        LogScroller.ScrollToEnd();
    }
}
