using System.IO;
using System.Windows;
using System.Windows.Controls;
// Fully-qualified WinForms; global MessageBox alias points at AppDialog.
using WinForms = System.Windows.Forms;
using Microsoft.Win32;
using DllSidecar.Core.Models.Wizard;

namespace DllSidecar.GUI.Views.Wizard.Stages;

public partial class InputStage : System.Windows.Controls.UserControl, IWizardStage
{
    private readonly WizardSession _session;
    private readonly WizardPage _shell;

    public InputStage(WizardSession session, WizardPage shell)
    {
        _session = session;
        _shell = shell;
        InitializeComponent();

        PathBox.Text = _session.InputPath ?? "";

        // Seed entry point from session (preserves Back→Input choice).
        switch (_session.EntryPoint)
        {
            case WizardEntryPoint.AnalyzeBinary: EntryAnalyze.IsChecked = true; break;
            case WizardEntryPoint.RuntimeTrace:  EntryRuntime.IsChecked = true; break;
            default:                             EntryScan.IsChecked = true; break;
        }

        Drop += OnDrop;
        DragEnter += OnDragEnter;
        DragOver += OnDragEnter;
        UpdateEntryUi();
        Detect();
    }

    public bool CanSkip => false;

    public Task<bool> ValidateAndCommit()
    {
        // Runtime entry pivots out of the wizard.
        if (EntryRuntime.IsChecked == true)
        {
            _session.EntryPoint = WizardEntryPoint.RuntimeTrace;
            _shell.PivotToRuntimeTrace();
            return Task.FromResult(false); // false = don't advance — we left the wizard
        }

        var path = PathBox.Text.Trim();
        if (string.IsNullOrEmpty(path))
        {
            MessageBox.Show("Drop a file/folder or browse first.",
                "Input required", MessageBoxButton.OK, MessageBoxImage.Warning);
            return Task.FromResult(false);
        }

        if (EntryAnalyze.IsChecked == true)
        {
            if (!File.Exists(path))
            {
                MessageBox.Show($"File does not exist:\n{path}",
                    "Invalid path", MessageBoxButton.OK, MessageBoxImage.Warning);
                return Task.FromResult(false);
            }
            _session.EntryPoint = WizardEntryPoint.AnalyzeBinary;
            _session.InputKind = WizardInputKind.SinglePe;
        }
        else // EntryScan
        {
            // Scan-folder accepts directories only.
            if (!Directory.Exists(path))
            {
                MessageBox.Show(
                    File.Exists(path)
                        ? "Scan a folder requires a directory path. To analyze a single PE, switch to 'Analyze a binary' above."
                        : $"Path does not exist:\n{path}",
                    "Invalid path", MessageBoxButton.OK, MessageBoxImage.Warning);
                return Task.FromResult(false);
            }
            _session.EntryPoint = WizardEntryPoint.ScanFolder;
            _session.InputKind = WizardInputKind.InstallDirectory;
        }

        _session.InputPath = path;
        return Task.FromResult(true);
    }

    public Task OnSkip() => Task.CompletedTask;

    // ---------- Entry selector ----------

    private void Entry_Changed(object sender, RoutedEventArgs e) => UpdateEntryUi();

    private void UpdateEntryUi()
    {
        if (PathRow == null) return; // fires during InitializeComponent before controls exist
        var isRuntime = EntryRuntime.IsChecked == true;
        PathRow.Visibility = isRuntime ? Visibility.Collapsed : Visibility.Visible;
        DetectBox.Visibility = isRuntime ? Visibility.Collapsed : Visibility.Visible;
        RuntimeHint.Visibility = isRuntime ? Visibility.Visible : Visibility.Collapsed;

        var isAnalyze = EntryAnalyze.IsChecked == true;
        BrowseDirBtn.Visibility = isAnalyze ? Visibility.Collapsed : Visibility.Visible;
    }

    // ---------- Browse ----------

    private void BrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "PE|*.dll;*.exe|All files|*.*",
            Title = EntryAnalyze.IsChecked == true
                ? "Pick a DLL or EXE to analyze"
                : "Pick a PE file",
        };
        if (dlg.ShowDialog() == true) PathBox.Text = dlg.FileName;
    }

    private void BrowseDir_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new WinForms.FolderBrowserDialog { Description = "Pick an install directory" };
        if (!string.IsNullOrWhiteSpace(PathBox.Text) && Directory.Exists(PathBox.Text))
            dlg.SelectedPath = PathBox.Text;
        if (dlg.ShowDialog() == WinForms.DialogResult.OK)
            PathBox.Text = dlg.SelectedPath;
    }

    // ---------- Drag & drop ----------

    private void OnDragEnter(object sender, System.Windows.DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop)
            ? System.Windows.DragDropEffects.Copy : System.Windows.DragDropEffects.None;
        e.Handled = true;
    }

    private void OnDrop(object sender, System.Windows.DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop)) return;
        var paths = (string[])e.Data.GetData(System.Windows.DataFormats.FileDrop);
        if (paths.Length == 0) return;
        PathBox.Text = paths[0];
    }

    // ---------- Auto-detection ----------

    private void PathBox_Changed(object sender, TextChangedEventArgs e) => Detect();

    private void Detect()
    {
        if (DetectKind == null) return;
        var raw = PathBox.Text?.Trim() ?? "";
        if (string.IsNullOrEmpty(raw))
        {
            DetectIcon.Text = "\U0001F4C1";
            DetectKind.Text = "No input yet";
            DetectKind.Foreground = (System.Windows.Media.Brush)FindResource("Overlay");
            DetectHint.Text = EntryAnalyze.IsChecked == true
                ? "Pick a .dll or .exe — the wizard will analyze it and skip directly to Pick."
                : "Pick an install directory — the wizard will scan every PE under it.";
            return;
        }

        string icon, kindLabel, hint;

        if (Directory.Exists(raw))
        {
            icon = "\U0001F4C1";
            kindLabel = "INSTALL DIRECTORY";
            hint = "Will scan every PE under this directory.";
        }
        else if (File.Exists(raw))
        {
            if (EntryAnalyze.IsChecked == true)
            {
                icon = "\U0001F50D"; kindLabel = "SINGLE PE";
                hint = "Will analyze this PE and jump to Pick with it pre-selected.";
            }
            else
            {
                DetectIcon.Text = "⚠";
                DetectKind.Text = "FILE — UNSUPPORTED HERE";
                DetectKind.Foreground = (System.Windows.Media.Brush)FindResource("Red");
                DetectHint.Text = "'Scan a folder' requires a directory. To analyze a single PE, switch to 'Analyze a binary' above.";
                return;
            }
        }
        else
        {
            DetectIcon.Text = "⚠";
            DetectKind.Text = "NOT FOUND";
            DetectKind.Foreground = (System.Windows.Media.Brush)FindResource("Red");
            DetectHint.Text = "Path does not exist.";
            return;
        }

        DetectIcon.Text = icon;
        DetectKind.Text = kindLabel;
        DetectKind.Foreground = (System.Windows.Media.Brush)FindResource("Phosphor");
        DetectHint.Text = hint;
    }
}
