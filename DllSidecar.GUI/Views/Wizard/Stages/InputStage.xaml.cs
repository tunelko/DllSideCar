using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Forms;
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

        // Seed entry point + goal toggles from session state (so going Back to Input preserves choices)
        switch (_session.EntryPoint)
        {
            case WizardEntryPoint.AnalyzeBinary: EntryAnalyze.IsChecked = true; break;
            case WizardEntryPoint.RuntimeTrace:  EntryRuntime.IsChecked = true; break;
            default:                             EntryScan.IsChecked = true; break;
        }
        switch (_session.HuntingGoal)
        {
            case WizardHuntingGoal.LocalPrivesc: GoalPrivesc.IsChecked = true; break;
            case WizardHuntingGoal.Persistence:  GoalPersist.IsChecked = true; break;
            default:                             GoalCode.IsChecked = true; break;
        }
        GoalCode.Checked    += (_, _) => GoalHint.Text = "Code execution in the user's context — the common case. Survey ranks by exploitability + writable ACLs.";
        GoalPrivesc.Checked += (_, _) => GoalHint.Text = "Looking for user → SYSTEM. Survey ranks SYSTEM services, AutoElevate manifests, scheduled tasks higher.";
        GoalPersist.Checked += (_, _) => GoalHint.Text = "Reboot-surviving vectors. Survey favours COM hijacks, writable Program Files, startup folder drops.";

        Drop += OnDrop;
        DragEnter += OnDragEnter;
        DragOver += OnDragEnter;
        UpdateEntryUi();
        Detect();
    }

    public bool CanSkip => false;

    public Task<bool> ValidateAndCommit()
    {
        // Capture goal
        _session.HuntingGoal = GoalPrivesc.IsChecked == true ? WizardHuntingGoal.LocalPrivesc
                             : GoalPersist.IsChecked == true ? WizardHuntingGoal.Persistence
                             : WizardHuntingGoal.ArbitraryCode;

        // Runtime entry pivots out of the wizard — no path validation, just route.
        if (EntryRuntime.IsChecked == true)
        {
            _session.EntryPoint = WizardEntryPoint.RuntimeTrace;
            _shell.PivotToRuntimeTrace();
            return Task.FromResult(false); // false = don't advance — we left the wizard
        }

        var path = PathBox.Text.Trim();
        if (string.IsNullOrEmpty(path))
        {
            System.Windows.MessageBox.Show("Drop a file/folder or browse first.",
                "Input required", MessageBoxButton.OK, MessageBoxImage.Warning);
            return Task.FromResult(false);
        }

        if (EntryAnalyze.IsChecked == true)
        {
            if (!File.Exists(path))
            {
                System.Windows.MessageBox.Show($"File does not exist:\n{path}",
                    "Invalid path", MessageBoxButton.OK, MessageBoxImage.Warning);
                return Task.FromResult(false);
            }
            _session.EntryPoint = WizardEntryPoint.AnalyzeBinary;
            _session.InputKind = WizardInputKind.SinglePe;
        }
        else // EntryScan
        {
            // Scan accepts directories or installer-like files (fall through to InstallerExtractor).
            var isDir = Directory.Exists(path);
            var isFile = File.Exists(path);
            if (!isDir && !isFile)
            {
                System.Windows.MessageBox.Show($"Path does not exist:\n{path}",
                    "Invalid path", MessageBoxButton.OK, MessageBoxImage.Warning);
                return Task.FromResult(false);
            }
            _session.EntryPoint = WizardEntryPoint.ScanFolder;
            _session.InputKind = isDir ? WizardInputKind.InstallDirectory : WizardInputKind.Installer;
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
            Filter = EntryAnalyze.IsChecked == true
                ? "PE|*.dll;*.exe|All files|*.*"
                : "Any supported|*.msi;*.exe;*.zip;*.7z;*.dll|Installers|*.msi;*.exe|Archives|*.zip;*.7z|PE|*.dll;*.exe|All files|*.*",
            Title = EntryAnalyze.IsChecked == true
                ? "Pick a DLL or EXE to analyze"
                : "Pick a file — auto-detect installer vs archive",
        };
        if (dlg.ShowDialog() == true) PathBox.Text = dlg.FileName;
    }

    private void BrowseDir_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new FolderBrowserDialog { Description = "Pick an install directory" };
        if (!string.IsNullOrWhiteSpace(PathBox.Text) && Directory.Exists(PathBox.Text))
            dlg.SelectedPath = PathBox.Text;
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
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
                : "Pick a directory or a .msi / .exe / .zip — the wizard decides extract + scan.";
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
            var ext = Path.GetExtension(raw).ToLowerInvariant();
            if (EntryAnalyze.IsChecked == true)
            {
                icon = "\U0001F50D"; kindLabel = "SINGLE PE";
                hint = "Will analyze this PE and jump to Pick with it pre-selected.";
            }
            else if (ext is ".msi") { icon = "\U0001F4E6"; kindLabel = "MSI INSTALLER"; hint = "Will extract statically then scan."; }
            else if (ext is ".zip" or ".7z" or ".rar") { icon = "\U0001F5DC"; kindLabel = "ARCHIVE"; hint = "Will extract with 7-Zip then scan."; }
            else if (ext is ".exe") { icon = "\U0001F4E5"; kindLabel = "EXE (installer or PE)"; hint = "Will try installer extraction; if it's a plain PE, switch to Analyze a binary."; }
            else { icon = "❓"; kindLabel = "UNKNOWN FILE"; hint = "Unrecognised extension — attempt as installer."; }
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
