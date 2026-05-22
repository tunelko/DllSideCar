using System.IO;
using System.Text;
using System.Windows;
using DllSidecar.Core.Models.Advisory;
using DllSidecar.Core.Models.Wizard;
using DllSidecar.Core.Services.Advisory;
using DllSidecar.Core.Logging;
using Markdig;

namespace DllSidecar.GUI.Views.Wizard.Stages;

public partial class ReportStage : System.Windows.Controls.UserControl, IWizardStage
{
    private readonly WizardSession _session;
    private readonly WizardPage _shell;
    private readonly MainWindow _main;

    public ReportStage(WizardSession session, WizardPage shell, MainWindow main)
    {
        _session = session;
        _shell = shell;
        _main = main;
        InitializeComponent();
        Loaded += async (_, _) => await OnLoadedAsync();
    }

    private async Task OnLoadedAsync()
    {
        // Auto-run NVD dedup against the picked target so the advisory can include it.
        // Uses cache if recent — cheap. Only runs if we don't already have results + we
        // have an existing PE (phantoms skip: no vendor/product metadata to query with).
        if (_session.CveDedup == null && _session.ChosenExisting != null)
        {
            _shell.ShowOverlay("Running NVD dedup", "Auto-check before drafting advisory...");
            try
            {
                _session.CveDedup = await Core.Services.Cve.CveDedupService.QueryAsync(_session.ChosenExisting.Dll);
            }
            catch (Exception ex)
            {
                Log.Warn("wizard.report.cve", "NVD dedup skipped", ex);
            }
            finally { _shell.HideOverlay(); }
        }
        BuildAdvisory();
    }

    public bool CanSkip => false;

    public Task<bool> ValidateAndCommit()
    {
        _session.AdvisoryMarkdown = MdView.Text;
        // Stash advisory state into MainWindow so AdvisoryPage picks it up after Finish.
        // For phantom-only flows ChosenExisting is null → CurrentAnalysis would be null
        // and AdvisoryPage would show empty placeholders. Pass the context + markdown
        // explicitly so AdvisoryPage adopts them verbatim (preserving the user's edits
        // inside MdView over the auto-generated draft).
        _main.CurrentAnalysis = _session.ChosenExisting?.Dll;
        _main.CurrentDllPath  = _session.ChosenExisting?.Dll.Path ?? _session.BuiltDllPath;
        _main.LastScanResults = _session.ScanResults;
        _main.LastScanDir = _session.SurveyRootDir;
        _main.PendingAdvisoryContext = _session.Advisory;
        _main.PendingAdvisoryMarkdown = MdView.Text;
        return Task.FromResult(true);
    }

    public Task OnSkip() => Task.CompletedTask;

    private void BuildAdvisory()
    {
        var ctx = new AdvisoryContext();
        var pe = _session.ChosenExisting?.Dll;

        if (pe != null)
        {
            ctx.PePath = pe.Path;
            ctx.PeFilename = pe.Filename;
            ctx.Architecture = pe.Arch;
            ctx.Product = string.IsNullOrEmpty(pe.ProductName) ? pe.Filename : pe.ProductName;
            // Host-EXE vendor (resolved by CraftStage when the user picked the host) wins
            // over whatever the target PE's own CompanyName says — Host is the signed
            // process that actually loads the sideloaded DLL, so it's the real vendor.
            ctx.Vendor = !string.IsNullOrWhiteSpace(_session.Vendor)
                ? _session.Vendor
                : Core.Services.Advisory.VendorResolver.Extract(pe);
            ctx.Version = pe.FileVersion;
            ctx.InstallDirectory = Path.GetDirectoryName(pe.Path);

            if (_session.ChosenExisting != null)
            {
                ctx.Privesc = _session.ChosenExisting.Privesc;
                ctx.DirectoryLowPrivWritable = _session.ChosenExisting.Dir.IsLowPrivWritable;
                ctx.WritableByPrincipals = string.Join(", ", _session.ChosenExisting.Dir.WritableBy);
                ctx.ImporterExe = _session.ChosenExisting.Importers.FirstOrDefault()?.ExeFilename;
            }
        }
        else if (_session.ChosenPhantom != null)
        {
            var p = _session.ChosenPhantom;
            ctx.PeFilename = p.DllName;
            ctx.InstallDirectory = p.DirectoryPath;
            ctx.Privesc = p.Privesc;
            ctx.DirectoryLowPrivWritable = p.Dir.IsLowPrivWritable;
            ctx.WritableByPrincipals = string.Join(", ", p.Dir.WritableBy);
            ctx.ImporterExe = p.Importers.FirstOrDefault()?.ExeFilename;
            // Phantom has no target PE to read CompanyName from — the Host EXE chosen in
            // CraftStage is the only reliable vendor source here.
            if (!string.IsNullOrWhiteSpace(_session.Vendor))
                ctx.Vendor = _session.Vendor;

            // Title placeholder {Product} resolves from ctx.Product. Phantom flow used
            // to leave Product null and the rendered title read "DLL Sideloading in via
            // bcrypt.dll" — the empty space between "in" and "via" gave the bug away.
            // Resolve from PE version info on the Host EXE if available, then walk down
            // a deterministic fallback ladder so Product is *always* populated.
            ctx.Product = ResolveProductForPhantom(p, _session.CraftHostExePath);
            ctx.PePath = _session.CraftHostExePath; // so the importer EXE path is visible in the advisory header

            // Architecture from the host EXE (when available) so the advisory matches the
            // arch CraftStage picked. Falls back to "x64" — phantom flow has no PE to read.
            if (!string.IsNullOrEmpty(_session.CraftHostExePath) && File.Exists(_session.CraftHostExePath))
            {
                try { ctx.Architecture = Core.Services.PeAnalyzer.Analyze(_session.CraftHostExePath).Arch; }
                catch { }
            }
        }

        ctx.GeneratedDllPath = _session.BuiltDllPath ?? _session.GeneratedOutputDir;
        ctx.CveDedup = _session.CveDedup;

        // CVSS defaults
        ctx.Cvss = new CvssVector();
        var (score, sev) = CvssCalculator.Compute(ctx.Cvss);
        ctx.CvssScore = score;
        ctx.CvssSeverity = sev;

        // Pull researcher identity (Name / Handle / Blog / Email / PGP) from Configuration.
        // Without this the Report stage hands off a context with blank Researcher fields to
        // AdvisoryPage and the renderers print "Researcher: ()" even when the user has filled
        // in Configuration.
        ctx.ApplyResearcherFromConfig();

        _session.Advisory = ctx;
        // Prefer the user's previous edits (stored on session) over the freshly rendered
        // template so Back → Continue navigation doesn't wipe their draft work.
        MdView.Text = string.IsNullOrEmpty(_session.AdvisoryMarkdown)
            ? AdvisoryTemplate.Render(ctx)
            : _session.AdvisoryMarkdown;

        MdView.TextChanged -= MdView_TextChanged;
        MdView.TextChanged += MdView_TextChanged;
    }

    private void MdView_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        _session.AdvisoryMarkdown = MdView.Text;
        _shell.RefreshChrome(); // disk snapshot checkpoint
    }

    /// <summary>
    /// Determine a non-empty Product name for a phantom-flow advisory. Order:
    ///  1. Host EXE's PE ProductName (richest — author-curated product label).
    ///  2. Host EXE's filename without extension (e.g. "Battle.net").
    ///  3. Any importer's PE ProductName (still author-curated).
    ///  4. First importer's filename without extension.
    ///  5. Phantom directory leaf (e.g. "Battle.net" from "C:\Program Files\Battle.net").
    ///  6. Phantom DLL basename without extension.
    ///  7. "Unknown product" — never let the title render with an empty {Product}.
    /// </summary>
    private static string ResolveProductForPhantom(Core.Models.PhantomCandidate p, string? hostExePath)
    {
        string? FromPeProduct(string? path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            try
            {
                var pn = Core.Services.PeAnalyzer.Analyze(path).ProductName;
                return string.IsNullOrWhiteSpace(pn) ? null : pn;
            }
            catch { return null; }
        }

        var fromHost = FromPeProduct(hostExePath);
        if (!string.IsNullOrWhiteSpace(fromHost)) return fromHost;

        if (!string.IsNullOrWhiteSpace(hostExePath))
        {
            var basename = Path.GetFileNameWithoutExtension(hostExePath);
            if (!string.IsNullOrWhiteSpace(basename)) return basename;
        }

        foreach (var imp in p.Importers)
        {
            var fromImp = FromPeProduct(imp.ExePath);
            if (!string.IsNullOrWhiteSpace(fromImp)) return fromImp;
        }

        var firstImp = p.Importers.FirstOrDefault();
        if (firstImp != null)
        {
            var basename = Path.GetFileNameWithoutExtension(firstImp.ExeFilename ?? firstImp.ExePath ?? "");
            if (!string.IsNullOrWhiteSpace(basename)) return basename;
        }

        if (!string.IsNullOrEmpty(p.DirectoryPath))
        {
            var leaf = new DirectoryInfo(p.DirectoryPath).Name;
            if (!string.IsNullOrWhiteSpace(leaf)) return leaf;
        }

        var dllBase = Path.GetFileNameWithoutExtension(p.DllName ?? "");
        if (!string.IsNullOrWhiteSpace(dllBase)) return dllBase;

        return "Unknown product";
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        try { System.Windows.Clipboard.SetText(MdView.Text); }
        catch (Exception ex) { Log.Warn("wizard.report", "Clipboard failed", ex); }
    }

    private void SaveMd_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "Markdown (*.md)|*.md|All files|*.*",
            FileName = SuggestedFilename(".md"),
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            File.WriteAllText(dlg.FileName, MdView.Text, new UTF8Encoding(false));
            _main.Log($"Wizard advisory saved: {dlg.FileName}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Save failed: {ex.Message}", "Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExportPdf_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "PDF (*.pdf)|*.pdf|All files|*.*",
            FileName = SuggestedFilename(".pdf"),
        };
        if (dlg.ShowDialog() != true) return;

        _shell.ShowOverlay("Exporting PDF", "Rendering...");
        try
        {
            // Shares the same engine as AdvisoryPage's export — pure C# QuestPDF,
            // no headless Chrome (which left blank-content PDFs on Edge 148+ for
            // researchers with Edge already running under their default profile).
            var title = _session.Advisory?.ResolveTitle();
            if (string.IsNullOrWhiteSpace(title)) title = "Advisory";
            Services.MarkdownPdfRenderer.Render(MdView.Text ?? "", title, dlg.FileName);

            _session.AdvisoryPdfPath = dlg.FileName;
            var size = new FileInfo(dlg.FileName).Length;
            _main.Log($"Wizard PDF exported: {dlg.FileName}  ({size:N0} bytes)");

            // Auto-open with the system's default viewer.
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = dlg.FileName,
                    UseShellExecute = true,
                });
            }
            catch (Exception openEx)
            {
                Log.Warn("wizard.report.pdf", $"Auto-open failed: {openEx.Message}");
            }
        }
        catch (Exception ex)
        {
            Log.Error("wizard.report.pdf", "PDF export failed", ex);
            MessageBox.Show($"PDF export failed: {ex.GetType().Name}: {ex.Message}", "Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { _shell.HideOverlay(); }
    }

    private string SuggestedFilename(string ext)
    {
        // Slug each part so the resulting filename has no spaces / non-ASCII —
        // Edge's file:// shell-open splits on spaces, which previously broke open.
        var vendor = Slugify(_session.Advisory?.Vendor ?? "vendor");
        var file = Slugify(Path.GetFileNameWithoutExtension(_session.Advisory?.PeFilename ?? "dll"));
        var date = DateTime.Today.ToString("yyyyMMdd");
        return $"advisory_{vendor}_{file}_{date}{ext}";
    }

    private static string Slugify(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return "unknown";
        var sb = new StringBuilder(input.Length);
        foreach (var ch in input.ToLowerInvariant())
        {
            if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')
                sb.Append(ch);
            else
                sb.Append('_');
        }
        var s = sb.ToString();
        while (s.Contains("__")) s = s.Replace("__", "_");
        s = s.Trim('_');
        return string.IsNullOrEmpty(s) ? "unknown" : s;
    }
}
