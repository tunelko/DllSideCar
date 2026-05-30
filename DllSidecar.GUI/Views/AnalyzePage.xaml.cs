using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using DllSidecar.Core.Helpers;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;
using DllSidecar.Core.Services.Exploitability;

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

        // Restore from MainWindow's cached analysis/verdict if available.
        if (_main.CurrentAnalysis != null && _main.CurrentDllPath != null)
        {
            RenderAnalysis(_main.CurrentAnalysis, _main.CurrentDllPath,
                _main.LastCallsiteResult, _main.LastExploitabilityVerdict);
        }
        // Session-restore path: re-run analysis if file still exists.
        else if (!string.IsNullOrEmpty(_main.CurrentDllPath) && File.Exists(_main.CurrentDllPath))
        {
            Loaded += AutoAnalyzeOnce;
        }
    }

    private void AutoAnalyzeOnce(object sender, RoutedEventArgs e)
    {
        Loaded -= AutoAnalyzeOnce;
        Analyze_Click(this, new RoutedEventArgs());
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

            // Callsite scan for verdict; Iced only supports x86/x64 (arm64 → null).
            CallsiteScanResult? callsites = null;
            if (analysis.Arch is "x86" or "x64")
            {
                try { callsites = CallsiteScanner.Scan(path); }
                catch (Exception scanEx) { _main.Log($"Callsite scan failed: {scanEx.Message}"); }
            }
            var verdict = ExploitabilityVerdict.For.Binary(analysis, callsites);

            // Cache verdict + callsite result for rehydration.
            _main.LastCallsiteResult = callsites;
            _main.LastExploitabilityVerdict = verdict;

            RenderAnalysis(analysis, path, callsites, verdict);

            _main.Log($"Analysis complete: {analysis.Filename} ({analysis.Arch}, {analysis.Exports.Count} exports, security {analysis.Security.Score}/7, verdict {verdict.TierLabel} {verdict.Score}/10)");
        }
        catch (Exception ex)
        {
            _main.Log($"Error: {ex.Message}");
            MessageBox.Show(ex.Message, "Analysis Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>Paint every analysis-derived widget. Called from Analyze_Click and the ctor restore path.</summary>
    private void RenderAnalysis(PeAnalysis analysis, string path,
        CallsiteScanResult? callsites, ExploitabilityVerdict? verdict)
    {
        // File path box mirrors the canonical path so the user sees what's loaded.
        FilePathBox.Text = path;

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
        ActCallsites.IsEnabled = true;

        // Primary generation buttons: enable based on what's technically possible.
        ApplyGenerationAvailability(analysis, isKnown);

        // Verdict card: recompute when not cached.
        verdict ??= ExploitabilityVerdict.For.Binary(analysis, callsites);
        RenderVerdict(verdict);
    }

    private static void SetFlag(TextBlock tb, string name, bool enabled)
    {
        tb.Text = $"{(enabled ? "[+]" : "[-]")} {name}";
        tb.Foreground = new SolidColorBrush(
            enabled ? Color.FromRgb(0x00, 0xCA, 0x4E) : Color.FromRgb(0xFF, 0x5B, 0x4F));
    }

    /// <summary>Set IsEnabled + tooltip on each generation tile based on what's viable for this PE.</summary>
    private void ApplyGenerationAvailability(PeAnalysis a, bool isKnown)
    {
        // KnownDLL veto: loader never consults the search path.
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
        // arm64 not supported by Iced — surface up-front.
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

    /// <summary>Paint the exploitability card via the shared VerdictBadge control.</summary>
    private void RenderVerdict(ExploitabilityVerdict verdict)
    {
        ExploitabilityPanel.Visibility = Visibility.Visible;
        VerdictBadgeControl.Verdict = verdict;
        VerdictProsList.ItemsSource = verdict.Pros.ToList();
        VerdictConsList.ItemsSource = verdict.Cons.ToList();

        if (!string.IsNullOrEmpty(verdict.BlockingFactor))
        {
            VerdictBlocker.Text = "Blocker: " + verdict.BlockingFactor;
            VerdictBlocker.Visibility = Visibility.Visible;
        }
        else
        {
            VerdictBlocker.Visibility = Visibility.Collapsed;
        }
    }
}
