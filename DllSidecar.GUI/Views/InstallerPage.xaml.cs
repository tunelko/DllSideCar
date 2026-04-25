using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

public partial class InstallerPage : Page
{
    private readonly MainWindow _main;
    private CancellationTokenSource? _cts;
    private InstallerExtractionResult? _lastResult;

    public InstallerPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "Installers|*.msi;*.exe|MSI|*.msi|EXE|*.exe|All files|*.*",
            Title = "Select installer to extract (NOT execute)",
        };
        if (dlg.ShowDialog() == true) InstallerPathBox.Text = dlg.FileName;
    }

    private async void Extract_Click(object sender, RoutedEventArgs e)
    {
        var path = InstallerPathBox.Text.Trim();
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            SetStatus("File does not exist", StatusKind.Err);
            return;
        }

        SummaryCard.Visibility = Visibility.Collapsed;
        ScanBtn.IsEnabled = false;
        OpenFolderBtn.IsEnabled = false;
        LogBox.Clear();
        AppendLog($"Starting extraction of {Path.GetFileName(path)}");
        SetScanning(true);
        SetStatus("Extracting...", StatusKind.Info);
        Overlay.Show("Extracting installer", $"Processing {Path.GetFileName(path)}");

        _cts = new CancellationTokenSource();
        var progress = new Progress<string>(m => AppendLog(m));
        InstallerExtractionResult result;
        try
        {
            result = await InstallerExtractor.ExtractAsync(path, null, progress, _cts.Token);
        }
        catch (Exception ex)
        {
            AppendLog($"FATAL: {ex.GetType().Name}: {ex.Message}");
            result = new InstallerExtractionResult { Success = false, ErrorMessage = ex.Message };
        }
        finally
        {
            Overlay.Hide();
            SetScanning(false);
        }

        _lastResult = result;
        foreach (var line in result.Logs) AppendLog(line);

        if (result.Success)
        {
            SummaryCard.Visibility = Visibility.Visible;
            SumMethod.Text = result.MethodUsed.ToString();
            SumOutput.Text = result.OutputDir ?? "";
            SumFiles.Text = result.FilesExtracted.ToString("N0");
            SumSize.Text = $"{result.TotalBytesExtracted:N0} bytes";
            ScanBtn.IsEnabled = true;
            OpenFolderBtn.IsEnabled = true;
            SetStatus($"Extracted with {result.MethodUsed} — {result.FilesExtracted} files, {result.TotalBytesExtracted / 1024:N0} KB",
                StatusKind.Ok);
            _main.Log($"Installer extracted: {path} → {result.OutputDir}");
        }
        else
        {
            SetStatus($"Extraction failed: {result.ErrorMessage}", StatusKind.Err);
            _main.Log($"Installer extraction FAILED: {result.ErrorMessage}");
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        CancelBtn.IsEnabled = false;
        SetStatus("Cancelling...", StatusKind.Warn);
    }

    private void Scan_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult?.OutputDir == null) return;
        var scan = new ScanPage(_main);
        _main.NavigateTo(scan);
        scan.PrefillAndScan(_lastResult.OutputDir);
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult?.OutputDir == null || !Directory.Exists(_lastResult.OutputDir)) return;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "explorer.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add(_lastResult.OutputDir);
            Process.Start(psi);
        }
        catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception)
        {
            _main.Log($"Failed to open folder: {ex.Message}");
        }
    }

    private void SetScanning(bool scanning)
    {
        ExtractBtn.IsEnabled = !scanning;
        ExtractBtn.Visibility = scanning ? Visibility.Collapsed : Visibility.Visible;
        CancelBtn.IsEnabled = scanning;
        CancelBtn.Visibility = scanning ? Visibility.Visible : Visibility.Collapsed;
        InstallerPathBox.IsEnabled = !scanning;
    }

    private void AppendLog(string line)
    {
        LogBox.AppendText(line + "\n");
        LogScroller.ScrollToEnd();
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
}
