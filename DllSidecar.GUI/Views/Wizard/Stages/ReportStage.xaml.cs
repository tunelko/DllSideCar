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
        }

        ctx.GeneratedDllPath = _session.BuiltDllPath ?? _session.GeneratedOutputDir;
        ctx.CveDedup = _session.CveDedup;

        // CVSS defaults
        ctx.Cvss = new CvssVector();
        var (score, sev) = CvssCalculator.Compute(ctx.Cvss);
        ctx.CvssScore = score;
        ctx.CvssSeverity = sev;

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

    private async void ExportPdf_Click(object sender, RoutedEventArgs e)
    {
        var chromium = FindChromium();
        if (chromium == null)
        {
            MessageBox.Show("Chrome or Edge not found — required for PDF export.",
                "Wizard", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "PDF (*.pdf)|*.pdf|All files|*.*",
            FileName = SuggestedFilename(".pdf"),
        };
        if (dlg.ShowDialog() != true) return;

        _shell.ShowOverlay("Exporting PDF", "Rendering via Chromium...");
        try
        {
            var pipeline = new MarkdownPipelineBuilder().UseAdvancedExtensions().UsePipeTables().Build();
            var html = Markdown.ToHtml(MdView.Text, pipeline);
            var fullHtml = WrapPdfCss(html);
            var tmp = Path.Combine(Path.GetTempPath(), $"wizard-{Guid.NewGuid():N}.html");
            await File.WriteAllTextAsync(tmp, fullHtml, new UTF8Encoding(false));

            try { await RunHeadless(chromium, tmp, dlg.FileName); }
            finally { try { File.Delete(tmp); } catch (IOException) { } }

            _session.AdvisoryPdfPath = dlg.FileName;
            _main.Log($"Wizard PDF exported: {dlg.FileName}");
        }
        catch (Exception ex)
        {
            Log.Error("wizard.report.pdf", "PDF export failed", ex);
            MessageBox.Show($"PDF export failed: {ex.Message}", "Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { _shell.HideOverlay(); }
    }

    private string SuggestedFilename(string ext)
    {
        var vendor = (_session.Advisory?.Vendor ?? "vendor").ToLowerInvariant();
        var file = Path.GetFileNameWithoutExtension(_session.Advisory?.PeFilename ?? "dll").ToLowerInvariant();
        var date = DateTime.Today.ToString("yyyyMMdd");
        return $"advisory_{vendor}_{file}_{date}{ext}";
    }

    private static string? FindChromium()
    {
        string[] cands = [
            Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            Environment.ExpandEnvironmentVariables(@"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
            Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            Environment.ExpandEnvironmentVariables(@"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        ];
        foreach (var c in cands) if (File.Exists(c)) return c;
        return null;
    }

    private static async Task RunHeadless(string chrome, string htmlPath, string pdfPath)
    {
        var uri = new Uri(htmlPath).AbsoluteUri;
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = chrome, RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false, CreateNoWindow = true,
        };
        psi.ArgumentList.Add("--headless=new");
        psi.ArgumentList.Add("--disable-gpu");
        psi.ArgumentList.Add("--no-pdf-header-footer");
        psi.ArgumentList.Add("--no-sandbox");
        psi.ArgumentList.Add($"--print-to-pdf={pdfPath}");
        psi.ArgumentList.Add(uri);
        using var p = System.Diagnostics.Process.Start(psi)!;
        await p.WaitForExitAsync();
        if (p.ExitCode != 0)
            throw new InvalidOperationException($"Chromium exit {p.ExitCode}: {await p.StandardError.ReadToEndAsync()}");
    }

    private static string WrapPdfCss(string html) =>
        "<!DOCTYPE html><html><head><meta charset='utf-8'><style>" +
        "body{font-family:'Segoe UI',Arial,sans-serif;color:#171717;font-size:11pt;line-height:1.5;}" +
        "h1{font-size:20pt;margin:0 0 14pt;border-bottom:1px solid #888;padding-bottom:6pt;}" +
        "h2{font-size:15pt;margin:18pt 0 8pt;}" +
        "h3{font-size:12pt;margin:12pt 0 6pt;}" +
        "code{background:#f0f0f0;color:#b00020;padding:1pt 4pt;font-family:Consolas,monospace;}" +
        "pre{background:#f8f8f8;border:1px solid #ccc;padding:8pt;}" +
        "table{border-collapse:collapse;margin:8pt 0;}" +
        "th,td{border:1px solid #bbb;padding:5pt 10pt;}" +
        "th{background:#f0f0f0;font-weight:bold;}" +
        "blockquote{border-left:3pt solid #f39c12;margin:8pt 0;padding:4pt 10pt;background:#fff8e6;}" +
        "strong{color:#000;}</style></head><body>" + html + "</body></html>";
}
