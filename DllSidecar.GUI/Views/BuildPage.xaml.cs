using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
// Intentional: do NOT import System.Windows.Forms at file scope — it would pull
// System.Windows.Forms.MessageBox into the unqualified-name space and shadow
// (or at least race against) the `global using MessageBox = AppDialog` alias.
// We need exactly one WinForms type here (FolderBrowserDialog); reference it
// fully-qualified so `MessageBox.Show(...)` always lands on the themed dialog.
using WinForms = System.Windows.Forms;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

public partial class BuildPage : Page
{
    private readonly MainWindow _main;

    public BuildPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();

        var last = ConfigManager.Current.UiState.LastBuildDir;
        if (!string.IsNullOrEmpty(last)) DirBox.Text = last;
        DirBox.TextChanged += (_, _) =>
        {
            if (!IsLoaded) return;
            ConfigManager.Current.UiState.LastBuildDir = DirBox.Text?.Trim();
            ConfigManager.Save();
        };
    }

    private void BrowseDir_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new WinForms.FolderBrowserDialog { Description = "Select generated project directory" };
        if (dlg.ShowDialog() == WinForms.DialogResult.OK)
            DirBox.Text = dlg.SelectedPath;
    }

    private async void Build_Click(object sender, RoutedEventArgs e)
    {
        var dir = DirBox.Text.Trim();
        if (!Directory.Exists(dir))
        {
            SetStatus("Directory does not exist", false);
            return;
        }

        var cFiles = Directory.GetFiles(dir, "*.c");
        var defFiles = Directory.GetFiles(dir, "*.def");
        if (cFiles.Length == 0 || defFiles.Length == 0)
        {
            SetStatus("No .c or .def files found in directory", false);
            return;
        }

        BuildBtn.IsEnabled = false;
        SetStatus("Compiling...", null);
        Overlay.Show("Compiling DLL", $"Running MinGW on {Path.GetFileName(cFiles[0])}");

        // Detect arch from source
        var content = await File.ReadAllTextAsync(cFiles[0]);
        var arch = content.Contains("x64") || content.Contains("x86_64") ? "x64" : "x86";

        var dllName = Path.GetFileNameWithoutExtension(defFiles[0])
            .Replace("tracer_", "").Replace("proxy_", "").Replace("sideload_", "") + ".dll";
        var outputFile = Path.Combine(dir, dllName);

        var progress = new Progress<string>(msg => _main.Log($"  {msg}"));

        // Compile resource if present
        var extraObjects = new List<string>();
        var rcFile = Path.Combine(dir, "version.rc");
        if (File.Exists(rcFile))
        {
            var resObj = Path.Combine(dir, "version.res.o");
            if (await BuildSystem.CompileResourceAsync(rcFile, resObj, arch, progress))
                extraObjects.Add(resObj);
        }

        // AppPaths handles dev (src/templates) vs installed ({app}\templates) layout.
        var templatesDir = AppPaths.TemplatesDir;

        // BuildPage doesn't know the payload type — link ws2_32 unconditionally
        // so reverse-shell sources compile here too. The extra import is a few
        // bytes in the PE and only loads if winsock symbols are actually referenced.
        var result = await BuildSystem.CompileDllAsync(
            cFiles[0], defFiles[0], outputFile, arch,
            includeDirs: [templatesDir, dir],
            extraObjects: extraObjects.Count > 0 ? extraObjects : null,
            extraLibs: new[] { "ws2_32" },
            progress: progress);

        if (result.Success)
        {
            ResultText.Text = $"[+] Success: {dllName}\n    Size: {result.OutputSize:N0} bytes\n    Exports: {result.ExportCount}\n    Arch: {arch}\n\n    Path: {outputFile}";
            SetStatus($"Built {dllName} ({result.OutputSize:N0} bytes)", true);
        }
        else
        {
            ResultText.Text = $"[!] Failed:\n{result.Errors}";
            SetStatus("Build failed — see output", false);
        }

        ResultPanel.Visibility = Visibility.Visible;
        BuildBtn.IsEnabled = true;
        Overlay.Hide();
    }

    private void SetStatus(string text, bool? ok)
    {
        BuildStatus.Text = text;
        BuildStatus.Foreground = new System.Windows.Media.SolidColorBrush(ok switch
        {
            true  => System.Windows.Media.Color.FromRgb(0xA6, 0xE3, 0xA1),
            false => System.Windows.Media.Color.FromRgb(0xF3, 0x8B, 0xA8),
            _     => System.Windows.Media.Color.FromRgb(0x6C, 0x70, 0x86),
        });
    }
}
