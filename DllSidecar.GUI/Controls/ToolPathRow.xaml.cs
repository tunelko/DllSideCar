using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DllSidecar.Core.Configuration;

namespace DllSidecar.GUI.Controls;

/// <summary>
/// Reusable row for a single tool path in ConfigPage. Drives the same UX for every tool —
/// label + status pill + path TextBox + browse + detect + optional download link — so we
/// don't repeat XAML for each of the 8+ tools backed by AppConfig.Tools.
///
/// Status semantics:
///   OK       = path set and the file (or folder) exists on disk
///   MISSING  = path set but file/folder is gone — usually means the tool was uninstalled
///   REQUIRED = empty path AND IsRequired=true — must be set for the related flow to work
///   OPTIONAL = empty path AND IsRequired=false — fine to leave blank
/// </summary>
public partial class ToolPathRow : System.Windows.Controls.UserControl
{
    public enum BrowseKind { File, Folder }

    /// <summary>Tool name shown in the header (e.g. "ProcMon").</summary>
    public string Label
    {
        get => LabelText.Text;
        set => LabelText.Text = value;
    }

    /// <summary>Short description shown next to the label.</summary>
    public string Purpose
    {
        get => PurposeText.Text;
        set => PurposeText.Text = value;
    }

    /// <summary>True if the absence of this path blocks a workflow. Affects the empty-state pill.</summary>
    public bool IsRequired { get; set; }

    /// <summary>File picker vs folder picker for the Browse button.</summary>
    public BrowseKind BrowseMode { get; set; } = BrowseKind.File;

    /// <summary>
    /// Filenames to look for under the SysinternalsDir / ToolsRootDir / PATH when the user
    /// presses Detect. Order matters — first match wins. e.g. ["Procmon64.exe", "Procmon.exe"].
    /// Empty means there's nothing meaningful to auto-detect for this row — the Detect button
    /// is hidden so the user isn't prompted with a no-op control.
    /// </summary>
    public string[] CandidateNames
    {
        get => _candidateNames;
        set
        {
            _candidateNames = value ?? [];
            DetectBtn.Visibility = _candidateNames.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
        }
    }
    private string[] _candidateNames = [];

    /// <summary>Optional download/help URL — shows the ↗ button when set.</summary>
    public string? DownloadUrl
    {
        get => _downloadUrl;
        set
        {
            _downloadUrl = value;
            OpenLinkBtn.Visibility = string.IsNullOrWhiteSpace(value) ? Visibility.Collapsed : Visibility.Visible;
        }
    }
    private string? _downloadUrl;

    /// <summary>
    /// Callback returning the CURRENT (in-memory, not committed) bundle directories the row
    /// should probe for resolution. Injected by ConfigPage so Detect and the status pill
    /// reflect what the user just typed in SysinternalsRow / ToolsRootRow — NOT the stale
    /// ConfigManager.Current values. When null, falls back to ConfigManager.Current so the
    /// row works standalone in tests / one-off uses.
    /// </summary>
    public Func<(string? Sysinternals, string? ToolsRoot)>? BundleDirsProvider { get; set; }

    /// <summary>
    /// Fired whenever the user (or a programmatic load via <see cref="ToolPath"/>) changes
    /// the path. ConfigPage subscribes on bundle rows so it can recompute the status pill
    /// of every dependent file row when SysinternalsRow / ToolsRootRow changes.
    /// </summary>
    public event EventHandler? ToolPathChanged;

    /// <summary>Two-way path value. Read by ConfigPage on Save, written on Load.</summary>
    public string ToolPath
    {
        get => PathBox.Text;
        set { PathBox.Text = value ?? ""; UpdateStatus(); }
    }

    public ToolPathRow()
    {
        InitializeComponent();
        Loaded += (_, _) => UpdateStatus();
    }

    private void PathBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        UpdateStatus();
        ToolPathChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Public wrapper so ConfigPage can refresh this row's pill after a bundle row changed.</summary>
    public void RecomputeStatus() => UpdateStatus();

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        if (BrowseMode == BrowseKind.Folder)
        {
            var dlg = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = $"Select folder for {Label}",
                SelectedPath = TryGetExistingDir(PathBox.Text) ?? "",
            };
            if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                ToolPath = dlg.SelectedPath;
        }
        else
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = $"Select {Label} executable",
                Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
                FileName = File.Exists(PathBox.Text) ? PathBox.Text : "",
            };
            if (dlg.ShowDialog() == true) ToolPath = dlg.FileName;
        }
    }

    /// <summary>
    /// Try to auto-discover the tool by probing well-known locations:
    /// SysinternalsDir, ToolsRootDir (1-level deep), then PATH. Mirrors what ToolkitChecker
    /// does internally so what the user sees here matches what the rest of the app sees.
    /// </summary>
    private void Detect_Click(object sender, RoutedEventArgs e)
    {
        if (CandidateNames.Length == 0) return;
        var found = ProbeForTool();
        if (found != null)
        {
            ToolPath = found;
        }
        else
        {
            // Highlight the pill briefly so the user knows we tried but came up empty.
            StatusPill.Text = "NOT FOUND";
            StatusPill.Foreground = new SolidColorBrush(Color.FromRgb(0xF3, 0x8B, 0xA8));
        }
    }

    private void OpenLink_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_downloadUrl)) return;
        Helpers.SafeUrl.Open(_downloadUrl);
    }

    private string? ProbeForTool()
    {
        // Pull bundle dirs from the live provider (set by ConfigPage = current row text)
        // when available; otherwise fall back to ConfigManager.Current. This is what makes
        // Detect and pill resolution see the user's unsaved edits to SysinternalsRow.
        string? sys = null, root2 = null;
        if (BundleDirsProvider != null)
        {
            (sys, root2) = BundleDirsProvider();
        }
        else
        {
            var cfg = ConfigManager.Current;
            sys = cfg.Tools.SysinternalsDir;
            root2 = cfg.Tools.ToolsRootDir;
        }

        var roots = new List<string>();
        if (!string.IsNullOrWhiteSpace(sys))   roots.Add(sys);
        if (!string.IsNullOrWhiteSpace(root2)) roots.Add(root2);

        foreach (var root in roots)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var name in CandidateNames)
            {
                var direct = Path.Combine(root, name);
                if (File.Exists(direct)) return direct;
                // Probe one level of subdirectories (Sysinternals zip extracts flat, but
                // ToolsRoot may have per-tool subfolders).
                try
                {
                    foreach (var sub in Directory.EnumerateDirectories(root))
                    {
                        var nested = Path.Combine(sub, name);
                        if (File.Exists(nested)) return nested;
                    }
                }
                catch { /* permission denied — skip */ }
            }
        }

        // Fallback to PATH search
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            foreach (var name in CandidateNames)
            {
                try
                {
                    var p = Path.Combine(dir, name);
                    if (File.Exists(p)) return p;
                }
                catch { /* malformed PATH entry */ }
            }
        }
        return null;
    }

    private void UpdateStatus()
    {
        var raw = (PathBox.Text ?? "").Trim();
        if (string.IsNullOrEmpty(raw))
        {
            // Empty path is fine if the bundle/root probe would resolve it — that's what
            // ToolkitChecker does at runtime, and the pill should reflect "the app will
            // find it" rather than scaring the user with REQUIRED. Pill copy: "VIA BUNDLE"
            // (teal) so it's visually distinct from a hard-coded OK.
            if (CandidateNames.Length > 0)
            {
                var resolved = ProbeForTool();
                if (!string.IsNullOrEmpty(resolved))
                {
                    StatusPill.Text = "VIA BUNDLE";
                    StatusPill.Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xE2, 0xD5));
                    StatusPill.ToolTip = $"Resolved by ToolkitChecker at: {resolved}";
                    return;
                }
            }
            if (IsRequired)
            {
                StatusPill.Text = "REQUIRED";
                StatusPill.Foreground = new SolidColorBrush(Color.FromRgb(0xF3, 0x8B, 0xA8));
            }
            else
            {
                StatusPill.Text = "OPTIONAL";
                StatusPill.Foreground = new SolidColorBrush(Color.FromRgb(0x6C, 0x70, 0x86));
            }
            StatusPill.ToolTip = null;
            return;
        }

        var exists = BrowseMode == BrowseKind.Folder ? Directory.Exists(raw) : File.Exists(raw);
        if (exists)
        {
            StatusPill.Text = "OK";
            StatusPill.Foreground = new SolidColorBrush(Color.FromRgb(0xA6, 0xE3, 0xA1));
            StatusPill.ToolTip = null;
        }
        else
        {
            StatusPill.Text = "MISSING";
            StatusPill.Foreground = new SolidColorBrush(Color.FromRgb(0xF9, 0xE2, 0xAF));
            StatusPill.ToolTip = $"Path set but not found on disk: {raw}";
        }
    }

    private static string? TryGetExistingDir(string? p)
    {
        if (string.IsNullOrWhiteSpace(p)) return null;
        if (Directory.Exists(p)) return p;
        try
        {
            var parent = Path.GetDirectoryName(p);
            return Directory.Exists(parent) ? parent : null;
        }
        catch { return null; }
    }
}
