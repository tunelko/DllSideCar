using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

public partial class ConfigPage : Page
{
    private readonly MainWindow _main;

    public ConfigPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        ConfigureToolRows();
        LoadFromConfig();
    }

    /// <summary>
    /// Static metadata for each tool row — candidate filenames (used by Detect), browse mode,
    /// required flag and download URL. Kept here so adding a new tool means: add a property to
    /// <see cref="ToolsConfig"/>, add a ToolPathRow in XAML, add an entry here. No other changes.
    /// </summary>
    private void ConfigureToolRows()
    {
        // MinGW dirs are folders with no single canonical filename worth probing — Detect is
        // hidden for them (the section-level Auto-detect button does the discovery). Browse
        // opens a folder picker. x64 is a hard requirement for compilation; flag it so the
        // pill flips to REQUIRED when empty rather than the default OPTIONAL.
        Mingw64Row.BrowseMode = Controls.ToolPathRow.BrowseKind.Folder;
        Mingw64Row.IsRequired = true;
        Mingw32Row.BrowseMode = Controls.ToolPathRow.BrowseKind.Folder;
        MsysRow.BrowseMode    = Controls.ToolPathRow.BrowseKind.Folder;

        // Bundle directories — same: folder picker, no single executable to detect.
        SysinternalsRow.BrowseMode = Controls.ToolPathRow.BrowseKind.Folder;
        SysinternalsRow.DownloadUrl = "https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite";
        ToolsRootRow.BrowseMode    = Controls.ToolPathRow.BrowseKind.Folder;

        // ---- Live bundle context ----
        // Every file row queries BundleDirsProvider() at probe/detect time so it sees what
        // the user JUST typed in SysinternalsRow / ToolsRootRow — not the stale, possibly
        // unsaved ConfigManager.Current values. The lambda is closed over the row references
        // so it always reads the current text on each invocation.
        Func<(string?, string?)> bundleProvider = ()
            => (NullIfBlank(SysinternalsRow.ToolPath), NullIfBlank(ToolsRootRow.ToolPath));

        var fileRows = new[]
        {
            ProcmonRow, SigcheckRow, DependenciesRow,
            X64DbgRow, X32DbgRow, PythonRow, SevenZipRow, InnoUnpRow,
        };
        foreach (var row in fileRows) row.BundleDirsProvider = bundleProvider;

        // When SysinternalsRow / ToolsRootRow change, every file row's pill must be
        // recomputed because "VIA BUNDLE" resolution depends on those values. Without this
        // the pills only refresh on next page load.
        SysinternalsRow.ToolPathChanged += (_, _) => { foreach (var r in fileRows) r.RecomputeStatus(); };
        ToolsRootRow.ToolPathChanged    += (_, _) => { foreach (var r in fileRows) r.RecomputeStatus(); };

        // Per-tool exes — file picker + Detect probes Sysinternals/ToolsRoot/PATH for the candidates.
        ProcmonRow.CandidateNames = ["Procmon64.exe", "Procmon.exe"];
        ProcmonRow.IsRequired = true;
        ProcmonRow.DownloadUrl = "https://learn.microsoft.com/sysinternals/downloads/procmon";

        SigcheckRow.CandidateNames = ["sigcheck64.exe", "sigcheck.exe"];
        SigcheckRow.DownloadUrl = "https://learn.microsoft.com/sysinternals/downloads/sigcheck";

        DependenciesRow.CandidateNames = ["DependenciesGui.exe", "Dependencies.exe"];
        DependenciesRow.DownloadUrl = "https://github.com/lucasg/Dependencies/releases";

        X64DbgRow.CandidateNames = ["x64dbg.exe"];
        X64DbgRow.DownloadUrl = "https://x64dbg.com/";

        X32DbgRow.CandidateNames = ["x32dbg.exe"];
        X32DbgRow.DownloadUrl = "https://x64dbg.com/";

        PythonRow.CandidateNames = ["python.exe", "python3.exe"];
        PythonRow.DownloadUrl = "https://www.python.org/downloads/windows/";

        SevenZipRow.CandidateNames = ["7z.exe"];
        SevenZipRow.DownloadUrl = "https://www.7-zip.org/";

        InnoUnpRow.CandidateNames = ["innounp.exe"];
        InnoUnpRow.DownloadUrl = "https://innounp.sourceforge.net/";
    }

    private void LoadFromConfig()
    {
        var cfg = ConfigManager.Current;

        // MinGW (folders)
        Mingw64Row.ToolPath = cfg.Mingw.Mingw64BinDir;
        Mingw32Row.ToolPath = cfg.Mingw.Mingw32BinDir;
        MsysRow.ToolPath    = cfg.Mingw.MsysUsrBinDir;

        // Bundle directories
        SysinternalsRow.ToolPath = cfg.Tools.SysinternalsDir ?? "";
        ToolsRootRow.ToolPath    = cfg.Tools.ToolsRootDir    ?? "";

        // Per-tool exes
        ProcmonRow.ToolPath      = cfg.Tools.ProcmonPath         ?? "";
        SigcheckRow.ToolPath     = cfg.Tools.SigcheckPath        ?? "";
        DependenciesRow.ToolPath = cfg.Tools.DependenciesGuiPath ?? "";
        X64DbgRow.ToolPath       = cfg.Tools.X64DbgPath          ?? "";
        X32DbgRow.ToolPath       = cfg.Tools.X32DbgPath          ?? "";
        PythonRow.ToolPath       = cfg.Tools.PythonPath          ?? "";
        SevenZipRow.ToolPath     = cfg.Tools.SevenZipPath        ?? "";
        InnoUnpRow.ToolPath      = cfg.Tools.InnoUnpPath         ?? "";

        // NVD key (separate input, not a path)
        NvdApiKeyBox.Text = cfg.Tools.NvdApiKey ?? "";

        // Researcher identity
        ResearcherNameBox.Text   = cfg.Researcher.Name;
        ResearcherHandleBox.Text = cfg.Researcher.Handle;
        ResearcherBlogBox.Text   = cfg.Researcher.Blog;
        ResearcherEmailBox.Text  = cfg.Researcher.Email;
        PgpFingerprintBox.Text   = cfg.Researcher.PgpFingerprint;
        PgpKeyIdBox.Text         = cfg.Researcher.PgpKeyId;
        IncibeOptInBox.IsChecked = cfg.Researcher.IncibeRankingOptIn;
        IncibeDisplayNameBox.Text = cfg.Researcher.IncibePublicDisplayName;

        // Behavior
        AutoCveLookupBox.IsChecked = cfg.AutoCveLookup;

        // Payload defaults
        MsgBoxTitleBox.Text = cfg.Payload.MessageBoxTitle;
        MsgBoxBodyBox.Text = cfg.Payload.MessageBoxBody;
    }

    private void GetNvdKey_Click(object sender, RoutedEventArgs e)
    {
        Helpers.SafeUrl.Open("https://nvd.nist.gov/developers/request-an-api-key");
    }

    private void RescanToolkit_Click(object sender, RoutedEventArgs e)
    {
        CommitToConfig();
        var report = ToolkitChecker.CheckAll();
        SaveStatus.Text = $"Toolkit: {report.AvailableCount}/{report.TotalCount} available — save config to persist";
        SaveStatus.Foreground = new System.Windows.Media.SolidColorBrush(
            report.AllRequiredPresent
                ? System.Windows.Media.Color.FromRgb(0xA6, 0xE3, 0xA1)
                : System.Windows.Media.Color.FromRgb(0xF9, 0xE2, 0xAF));
        _main.Log($"Rescan: {report.AvailableCount}/{report.TotalCount} tools resolved");
    }

    private void AutoDetect_Click(object sender, RoutedEventArgs e)
    {
        // Probe well-known MSYS2 / mingw-w64 install roots and populate the three MinGW rows
        // with whatever exists. Section-level so the user gets all three filled in one click;
        // per-row Detect is hidden for folders since there's no single canonical filename.
        string[] candidates = [
            @"C:\msys64", @"C:\msys32", @"C:\MinGW", @"D:\msys64",
            @"C:\Program Files\mingw-w64", @"C:\mingw64", @"C:\mingw32",
        ];

        foreach (var root in candidates)
        {
            var m64 = Path.Combine(root, "mingw64", "bin");
            var m32 = Path.Combine(root, "mingw32", "bin");
            var usr = Path.Combine(root, "usr", "bin");
            if (Directory.Exists(m64)) Mingw64Row.ToolPath = m64;
            if (Directory.Exists(m32)) Mingw32Row.ToolPath = m32;
            if (Directory.Exists(usr)) MsysRow.ToolPath    = usr;
        }
        ValidateStatus.Text = "Detected — click Validate to confirm";
        ValidateStatus.Foreground = new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(0xF9, 0xE2, 0xAF));
    }

    private async void Validate_Click(object sender, RoutedEventArgs e)
    {
        CommitToConfig();
        Overlay.Show("Validating toolchain", "Probing gcc and windres for x86/x64...");
        string? gcc64 = null, gcc32 = null, wr64 = null, wr32 = null;
        try
        {
            await Task.Run(() =>
            {
                gcc64 = BuildSystem.FindGcc("x64");
                gcc32 = BuildSystem.FindGcc("x86");
                wr64  = BuildSystem.FindWindres("x64");
                wr32  = BuildSystem.FindWindres("x86");
            });
        }
        finally { Overlay.Hide(); }

        var parts = new List<string>();
        parts.Add(gcc64 != null ? "gcc-x64 OK" : "gcc-x64 MISSING");
        parts.Add(gcc32 != null ? "gcc-x86 OK" : "gcc-x86 MISSING");
        parts.Add(wr64  != null ? "windres-x64 OK" : "windres-x64 MISSING");
        parts.Add(wr32  != null ? "windres-x86 OK" : "windres-x86 MISSING");

        var ok = gcc64 != null || gcc32 != null;
        ValidateStatus.Text = string.Join("  |  ", parts);
        ValidateStatus.Foreground = new System.Windows.Media.SolidColorBrush(
            ok ? System.Windows.Media.Color.FromRgb(0xA6, 0xE3, 0xA1)
               : System.Windows.Media.Color.FromRgb(0xF3, 0x8B, 0xA8));
    }

    private void CommitToConfig()
    {
        var cfg = ConfigManager.Current;

        // MinGW (folders)
        cfg.Mingw.Mingw64BinDir = Mingw64Row.ToolPath.Trim();
        cfg.Mingw.Mingw32BinDir = Mingw32Row.ToolPath.Trim();
        cfg.Mingw.MsysUsrBinDir = MsysRow.ToolPath.Trim();

        // Bundle directories
        cfg.Tools.SysinternalsDir = NullIfBlank(SysinternalsRow.ToolPath);
        cfg.Tools.ToolsRootDir    = NullIfBlank(ToolsRootRow.ToolPath);

        // Per-tool exes
        cfg.Tools.ProcmonPath         = NullIfBlank(ProcmonRow.ToolPath);
        cfg.Tools.SigcheckPath        = NullIfBlank(SigcheckRow.ToolPath);
        cfg.Tools.DependenciesGuiPath = NullIfBlank(DependenciesRow.ToolPath);
        cfg.Tools.X64DbgPath          = NullIfBlank(X64DbgRow.ToolPath);
        cfg.Tools.X32DbgPath          = NullIfBlank(X32DbgRow.ToolPath);
        cfg.Tools.PythonPath          = NullIfBlank(PythonRow.ToolPath);
        cfg.Tools.SevenZipPath        = NullIfBlank(SevenZipRow.ToolPath);
        cfg.Tools.InnoUnpPath         = NullIfBlank(InnoUnpRow.ToolPath);

        cfg.Tools.NvdApiKey = NullIfBlank(NvdApiKeyBox.Text);

        // Researcher identity
        cfg.Researcher.Name           = ResearcherNameBox.Text.Trim();
        cfg.Researcher.Handle         = ResearcherHandleBox.Text.Trim();
        cfg.Researcher.Blog           = ResearcherBlogBox.Text.Trim();
        cfg.Researcher.Email          = ResearcherEmailBox.Text.Trim();
        cfg.Researcher.PgpFingerprint = PgpFingerprintBox.Text.Trim();
        cfg.Researcher.PgpKeyId       = PgpKeyIdBox.Text.Trim();
        cfg.Researcher.IncibeRankingOptIn      = IncibeOptInBox.IsChecked == true;
        cfg.Researcher.IncibePublicDisplayName = IncibeDisplayNameBox.Text.Trim();

        cfg.AutoCveLookup = AutoCveLookupBox.IsChecked == true;

        // Payload defaults — fall back to current values when blank so a
        // user emptying the box doesn't generate empty C string literals.
        if (!string.IsNullOrWhiteSpace(MsgBoxTitleBox.Text))
            cfg.Payload.MessageBoxTitle = MsgBoxTitleBox.Text;
        if (!string.IsNullOrWhiteSpace(MsgBoxBodyBox.Text))
            cfg.Payload.MessageBoxBody = MsgBoxBodyBox.Text;
    }

    private static string? NullIfBlank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        CommitToConfig();
        var result = ConfigManager.Save();
        if (result.Success)
        {
            SaveStatus.Text = $"Saved to {ConfigManager.ConfigPath}";
            SaveStatus.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0xA6, 0xE3, 0xA1));
            _main.Log("Config saved");
        }
        else
        {
            SaveStatus.Text = $"Save failed: {result.ErrorMessage}";
            SaveStatus.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0xF3, 0x8B, 0xA8));
            _main.Log($"Config save failed: {result.ErrorMessage}");
            System.Windows.MessageBox.Show(
                $"Could not save configuration:\n\n{result.ErrorMessage}",
                "Save Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Reset_Click(object sender, RoutedEventArgs e)
    {
        var r = System.Windows.MessageBox.Show(
            "Reset all settings to defaults?", "Reset Config",
            MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (r != MessageBoxResult.Yes) return;
        var result = ConfigManager.Reset();
        LoadFromConfig();
        if (result.Success)
        {
            SaveStatus.Text = "Reset to defaults";
            SaveStatus.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0xF9, 0xE2, 0xAF));
        }
        else
        {
            SaveStatus.Text = $"Reset in-memory, but save failed: {result.ErrorMessage}";
            SaveStatus.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0xF3, 0x8B, 0xA8));
        }
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        var dir = Path.GetDirectoryName(ConfigManager.ConfigPath);
        if (string.IsNullOrEmpty(dir))
        {
            _main.Log("Config path has no parent directory");
            return;
        }
        try
        {
            Directory.CreateDirectory(dir);
            // Open explorer.exe with the directory as argument — safer than passing the dir
            // as FileName (which invokes ShellExecute verb 'open', dependent on shell assoc).
            var psi = new ProcessStartInfo
            {
                FileName = "explorer.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add(dir);
            Process.Start(psi);
        }
        catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
        {
            _main.Log($"Failed to open config folder: {ex.Message}");
        }
    }
}
