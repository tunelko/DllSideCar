using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using DllSidecar.Core.Helpers;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

public partial class AnalyzePage : Page
{
    private readonly MainWindow _main;

    public AnalyzePage(MainWindow main)
    {
        _main = main;
        InitializeComponent();

        if (_main.CurrentDllPath != null)
            FilePathBox.Text = _main.CurrentDllPath;

        SetActionsEnabled(false);
    }

    private void SetActionsEnabled(bool enabled)
    {
        ActProxy.IsEnabled = enabled;
        ActSideload.IsEnabled = enabled;
        ActScanParent.IsEnabled = enabled;
        ActCopyPath.IsEnabled = enabled;
        ActCheckCves.IsEnabled = enabled;
        ActCallsites.IsEnabled = enabled;
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "PE files|*.dll;*.exe|All files|*.*",
            Title = "Select DLL or EXE to analyze"
        };
        if (dlg.ShowDialog() == true)
            FilePathBox.Text = dlg.FileName;
    }

    private void Analyze_Click(object sender, RoutedEventArgs e)
    {
        var path = FilePathBox.Text.Trim();
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            MessageBox.Show("File not found", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            _main.Log($"Analyzing: {path}");
            var analysis = PeAnalyzer.Analyze(path);
            _main.CurrentAnalysis = analysis;
            _main.CurrentDllPath = path;

            InfoFilename.Text = $"Filename: {analysis.Filename}";
            InfoArch.Text     = $"Architecture: {analysis.Arch} (0x{analysis.Machine:X4})";
            InfoType.Text     = $"Type: {(analysis.IsDll ? "DLL" : "EXE")}";
            InfoSize.Text     = $"Size: {analysis.FileSize:N0} bytes";
            InfoProduct.Text  = $"Product: {(string.IsNullOrEmpty(analysis.ProductName) ? "—" : analysis.ProductName)}";
            InfoVersion.Text  = $"Version: {(string.IsNullOrEmpty(analysis.FileVersion) ? "—" : analysis.FileVersion)}";

            var isKnown = KnownDlls.IsKnown(analysis.Filename);
            InfoKnownDll.Text = isKnown
                ? "KnownDLL: YES — not a sideload target"
                : "KnownDLL: NO — potential sideload target";
            InfoKnownDll.Foreground = new SolidColorBrush(
                isKnown ? Color.FromRgb(0xFF, 0x5B, 0x4F) : Color.FromRgb(0x00, 0xCA, 0x4E));
            InfoKnownDllHint.Text = isKnown
                ? "Windows always resolves this from System32 via the KnownDLLs cache before consulting any search path."
                : "Not in the KnownDLLs cache — the loader follows the normal search order, so file-replacement in the install dir is a valid attack vector (subject to directory ACL and importer manifest).";

            var sec = analysis.Security;
            SetFlag(FlagAslr, "ASLR", sec.Aslr);
            SetFlag(FlagHighEntropy, "High Entropy ASLR", sec.HighEntropyAslr);
            SetFlag(FlagDep, "DEP/NX", sec.Dep);
            SetFlag(FlagCfg, "Control Flow Guard", sec.Cfg);
            SetFlag(FlagForceIntegrity, "Force Integrity", sec.ForceIntegrity);
            SetFlag(FlagAuthenticode, "Authenticode", sec.Authenticode);
            FlagDepLoad.Text = $"DependentLoadFlags: 0x{sec.DependentLoadFlags:X4}";
            FlagScore.Text = $"Security score: {sec.Score}/7";

            ExportTitle.Text = $"EXPORTS — {analysis.Exports.Count} total ({analysis.NamedExports} named, {analysis.OrdinalOnlyExports} ordinal-only)";
            ExportsGrid.ItemsSource = analysis.Exports;

            ResultsPanel.Visibility = Visibility.Visible;
            ExportsPanel.Visibility = Visibility.Visible;

            // Secondary actions: always available after analysis
            ActScanParent.IsEnabled = true;
            ActCopyPath.IsEnabled = true;
            ActCheckCves.IsEnabled = true;

            // Primary generation buttons: enable based on what's technically possible.
            // Disabled buttons show a tooltip explaining WHY they're disabled.
            ApplyGenerationAvailability(analysis, isKnown);

            _main.Log($"Analysis complete: {analysis.Filename} ({analysis.Arch}, {analysis.Exports.Count} exports, security {sec.Score}/7)");
        }
        catch (Exception ex)
        {
            _main.Log($"Error: {ex.Message}");
            MessageBox.Show(ex.Message, "Analysis Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static void SetFlag(TextBlock tb, string name, bool enabled)
    {
        tb.Text = $"{(enabled ? "[+]" : "[-]")} {name}";
        tb.Foreground = new SolidColorBrush(
            enabled ? Color.FromRgb(0x00, 0xCA, 0x4E) : Color.FromRgb(0xFF, 0x5B, 0x4F));
    }

    /// <summary>
    /// Decide which generation modes are technically viable for this PE and set each
    /// tile's IsEnabled + tooltip accordingly. A disabled tile ALWAYS carries a tooltip
    /// explaining why so the researcher understands their constraints.
    /// </summary>
    private void ApplyGenerationAvailability(PeAnalysis a, bool isKnown)
    {
        // KnownDLL veto — neither proxy nor sideload works, the loader never
        // consults the search path for these.
        if (isKnown)
        {
            DisableTile(ActProxy,    "KnownDLL — cannot be replaced in an install dir.");
            DisableTile(ActSideload, "KnownDLL — cannot be sideloaded.");
            return;
        }

        // Not a DLL → the generation modes assume a DLL target (we're crafting a DLL replacement).
        if (!a.IsDll)
        {
            DisableTile(ActProxy,    "Target is an EXE. Pick one of its imported DLLs instead.");
            DisableTile(ActSideload, "Target is an EXE. Pick one of its imported DLLs instead.");
            return;
        }

        // Proxy: requires NAMED exports (forwarding .def needs names)
        if (a.NamedExports == 0)
            DisableTile(ActProxy, $"Proxy requires named exports for forwarding (ordinals alone can't drive .def forwarders). This DLL has {a.Exports.Count} export(s), all ordinal-only.");
        else
            EnableTile(ActProxy, $"Forward {a.NamedExports} named export(s) to _orig.dll, fire payload on a chosen export. Host process stays functional.");

        // Sideload: works with anything (payload in DllMain). Note about host breakage.
        if (a.Exports.Count == 0)
            EnableTile(ActSideload, "Target has no exports — Sideload mode (DllMain only) is the natural fit. No host functionality preserved.");
        else
            EnableTile(ActSideload, $"Stub DLL, payload in DllMain. Host calling any of the {a.Exports.Count} export(s) will fail — use only if the host tolerates missing exports or you want minimum footprint.");
    }

    private static void EnableTile(System.Windows.Controls.Button b, string reason)
    {
        b.IsEnabled = true;
        b.ToolTip = reason;
    }

    private static void DisableTile(System.Windows.Controls.Button b, string reason)
    {
        b.IsEnabled = false;
        b.ToolTip = "Disabled: " + reason;
    }

    private void ActProxy_Click(object sender, RoutedEventArgs e) =>
        _main.NavigateTo(new GeneratePage(_main, GenerationMode.Proxy));

    private void ActSideload_Click(object sender, RoutedEventArgs e) =>
        _main.NavigateTo(new GeneratePage(_main, GenerationMode.Sideload));

    private void ActScanParent_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_main.CurrentDllPath)) return;
        var parent = Path.GetDirectoryName(_main.CurrentDllPath);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent)) return;
        var scan = new ScanPage(_main);
        _main.NavigateTo(scan);
        scan.PrefillAndScan(parent);
    }

    private void ActCopyPath_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_main.CurrentDllPath)) return;
        try
        {
            System.Windows.Clipboard.SetText(_main.CurrentDllPath);
            _main.Log("Path copied to clipboard");
        }
        catch (Exception ex) { _main.Log($"Copy failed: {ex.Message}"); }
    }

    private void ActCheckCves_Click(object sender, RoutedEventArgs e)
    {
        if (_main.CurrentAnalysis == null)
        {
            MessageBox.Show("Analyze a PE first.", "CVE check", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dlg = new CveResultsWindow(_main.CurrentAnalysis) { Owner = Window.GetWindow(this) };
        dlg.ShowDialog();
    }

    private void ActCallsites_Click(object sender, RoutedEventArgs e)
    {
        if (_main.CurrentAnalysis == null || string.IsNullOrEmpty(_main.CurrentDllPath))
        {
            MessageBox.Show("Analyze a PE first.", "Callsites", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        // arm64 binaries fail in the scanner (Iced is x86/x64 only). Surface
        // it up-front rather than opening an empty modal.
        if (_main.CurrentAnalysis.Arch is not ("x86" or "x64"))
        {
            MessageBox.Show($"Callsite disassembly currently supports x86 and x64 only ({_main.CurrentAnalysis.Arch} not supported).",
                "Callsites", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dlg = new CallsitesWindow(_main.CurrentDllPath, _main.CurrentAnalysis.Arch)
        {
            Owner = Window.GetWindow(this)
        };
        dlg.ShowDialog();
    }
}
