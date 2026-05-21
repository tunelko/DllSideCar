using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
using Markdig;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Advisory;
using DllSidecar.Core.Models.Privesc;
using DllSidecar.Core.Services.Advisory;
using DllSidecar.Core.Services.Advisory.Rendering;

namespace DllSidecar.GUI.Views;

public partial class AdvisoryPage : Page
{
    private readonly MainWindow _main;
    private AdvisoryContext _ctx = new();
    private readonly MarkdownPipeline _mdPipeline;
    private readonly DispatcherTimer _previewTimer;
    private bool _suppressCvssChanged;
    private bool _suppressForm;
    private IAdvisoryRenderer _activeRenderer = AdvisoryRenderers.All[0]; // default to Markdown

    // Dirty-flag protection — re-rendering from a template wholesale replaces the editor
    // content. Track whether the user has manually edited the editor since the last
    // programmatic load/render so destructive actions (template change, CVSS apply, Template
    // Fields apply, vendor edit on non-Markdown) can prompt before discarding manual work.
    // _suppressEditorDirty must wrap ALL programmatic MdEditor.Text writes so that internal
    // re-renders do not flip the flag.
    private bool _editorDirty;
    private bool _suppressEditorDirty;
    // Tracks the combo index actually applied to the editor. If a destructive change is
    // cancelled, we revert TemplateCombo.SelectedIndex to this — without it the combo would
    // show the new template while the editor still holds the old content.
    private int _lastAppliedTemplateIndex;
    private bool _suppressTemplateChanged;

    public AdvisoryPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();

        _mdPipeline = new MarkdownPipelineBuilder()
            .UseAdvancedExtensions()
            .UsePipeTables()
            .UseAutoLinks()
            .Build();

        // Debounced preview refresh — avoid re-rendering on every keystroke
        _previewTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
        _previewTimer.Tick += (_, _) => { _previewTimer.Stop(); RefreshPreview(); };

        PopulateCvssCombos();
        PopulateTemplateCombo();
        ReloadContext();
        UpdateDynamicLabels();
    }

    // ---------- Context load ----------

    private void ReloadContext_Click(object sender, RoutedEventArgs e)
    {
        // Guard against the urlmon-class bug: if the editor is currently bound to an
        // existing Library record, rebuilding ctx from CurrentAnalysis (a possibly
        // unrelated PE) would silently swap identity. Force the user to be explicit.
        if (!string.IsNullOrEmpty(_main.PendingAdvisoryRecordId))
        {
            var pe = _main.CurrentAnalysis;
            var newPe = pe?.Filename ?? "(no PE loaded)";
            var choice = MessageBox.Show(
                "This editor is bound to an existing Library record.\n" +
                $"'Reload context' will rebuild the form from the current PE analysis ({newPe})\n" +
                "and DROP the link to the existing record. The next Save will create a NEW advisory.\n\n" +
                "Continue?",
                "Detach from record?",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning,
                MessageBoxResult.Cancel);
            if (choice != MessageBoxResult.OK) return;
            // Detach explicitly so Save creates new instead of overwriting the old record.
            _main.PendingAdvisoryRecordId = null;
        }
        ReloadContext();
    }

    private void ReloadContext()
    {
        // Wizard handoff — if ReportStage stashed an AdvisoryContext + markdown,
        // adopt them verbatim (preserves any edits the user made inside the Report
        // stage's MdView). Consume once so a later manual "Reload context" rebuilds
        // from CurrentAnalysis as normal.
        if (_main.PendingAdvisoryContext != null)
        {
            _ctx = _main.PendingAdvisoryContext;
            var md = _main.PendingAdvisoryMarkdown;
            var templateId = _main.PendingAdvisoryTemplateId;
            _main.PendingAdvisoryContext = null;
            _main.PendingAdvisoryMarkdown = null;
            _main.PendingAdvisoryTemplateId = null;

            // Restore the renderer that was active when the advisory was last saved BEFORE any
            // render call — otherwise an INCIBE/GHSA body would briefly fall through the Markdown
            // renderer and a subsequent Template Fields apply would silently overwrite it.
            ApplyPendingTemplate(templateId);

            _suppressCvssChanged = true;
            SetComboByKey(CvssAv, _ctx.Cvss.AttackVector);
            SetComboByKey(CvssAc, _ctx.Cvss.AttackComplexity);
            SetComboByKey(CvssPr, _ctx.Cvss.PrivilegesRequired);
            SetComboByKey(CvssUi, _ctx.Cvss.UserInteraction);
            SetComboByKey(CvssS,  _ctx.Cvss.Scope);
            SetComboByKey(CvssC,  _ctx.Cvss.Confidentiality);
            SetComboByKey(CvssI,  _ctx.Cvss.Integrity);
            SetComboByKey(CvssA,  _ctx.Cvss.Availability);
            _suppressCvssChanged = false;
            RecomputeCvss();

            PushCtxIntoForm();
            SetEditorTextSilently(md ?? _activeRenderer.Render(_ctx));

            var head = _ctx.PeFilename ?? "(wizard phantom)";
            ContextLine.Text = $"{head}  ·  handed off from Research Wizard";
            ContextHint.Text = !string.IsNullOrEmpty(_ctx.InstallDirectory)
                ? $"Phantom slot / install dir: {_ctx.InstallDirectory}"
                : "Wizard session complete — edit, save .md or export PDF.";
            FooterStatus.Text = "Advisory drafted by wizard · ready to edit/export.";
            return;
        }

        // Fresh context — drop any pending library record id so next "Save to Library"
        // creates a new row instead of overwriting the one that was last opened.
        _main.PendingAdvisoryRecordId = null;

        var pe = _main.CurrentAnalysis;
        _ctx = BuildContextFromSession(pe);

        // Push CVSS vector into the combos
        _suppressCvssChanged = true;
        SetComboByKey(CvssAv, _ctx.Cvss.AttackVector);
        SetComboByKey(CvssAc, _ctx.Cvss.AttackComplexity);
        SetComboByKey(CvssPr, _ctx.Cvss.PrivilegesRequired);
        SetComboByKey(CvssUi, _ctx.Cvss.UserInteraction);
        SetComboByKey(CvssS,  _ctx.Cvss.Scope);
        SetComboByKey(CvssC,  _ctx.Cvss.Confidentiality);
        SetComboByKey(CvssI,  _ctx.Cvss.Integrity);
        SetComboByKey(CvssA,  _ctx.Cvss.Availability);
        _suppressCvssChanged = false;
        RecomputeCvss();

        // Sync inline Vendor textbox and render through the active template.
        PushCtxIntoForm();
        SetEditorTextSilently(_activeRenderer.Render(_ctx));

        if (pe == null)
        {
            ContextLine.Text = "(no analysis loaded — template shows placeholders)";
            ContextHint.Text = "Go to Analyze PE or Scan Directory → pick a target, then return here with 'Reload context'.";
            FooterStatus.Text = "No context — draft is generic.";
        }
        else
        {
            ContextLine.Text = $"{pe.Filename}  ·  {pe.Arch}  ·  {pe.ProductName}";
            ContextHint.Text = $"Path: {pe.Path}";
            if (_ctx.Privesc?.Findings.Count > 0)
                ContextHint.Text += $"  ·  Privesc: {_ctx.Privesc.PrimaryVector} ({_ctx.Privesc.HighestSeverity})";
            FooterStatus.Text = "Advisory drafted from current context.";
        }
    }

    /// <summary>
    /// Build an AdvisoryContext from whatever the session currently holds. Pulls from
    /// CurrentAnalysis, and — if the last scan contains a candidate matching this PE —
    /// enriches with privesc + directory ACL data.
    /// </summary>
    private AdvisoryContext BuildContextFromSession(PeAnalysis? pe)
    {
        var ctx = new AdvisoryContext();

        if (pe != null)
        {
            ctx.PePath = pe.Path;
            ctx.PeFilename = pe.Filename;
            ctx.Architecture = pe.Arch;
            ctx.Product = string.IsNullOrEmpty(pe.ProductName) ? pe.Filename : pe.ProductName;
            ctx.Vendor = ExtractVendorHint(pe);
            ctx.Version = pe.FileVersion;
            ctx.InstallDirectory = Path.GetDirectoryName(pe.Path);

            // Attach the matching candidate from last scan if available
            var match = _main.LastScanResults?.Existing
                .FirstOrDefault(c => string.Equals(c.Dll.Path, pe.Path, StringComparison.OrdinalIgnoreCase));
            if (match != null)
            {
                ctx.Privesc = match.Privesc;
                ctx.DirectoryLowPrivWritable = match.Dir.IsLowPrivWritable;
                if (match.Dir.WritableBy.Count > 0)
                    ctx.WritableByPrincipals = string.Join(", ", match.Dir.WritableBy);
                ctx.ImporterExe = match.Importers.FirstOrDefault()?.ExeFilename;
                if (match.Privesc != null)
                    ctx.RelevantPrivescFindings = match.Privesc.Findings.ToList();
            }

            // Infer CVSS defaults from context
            ctx.Cvss = InferCvssFrom(ctx);
        }

        // Compute score
        var (score, severity) = CvssCalculator.Compute(ctx.Cvss);
        ctx.CvssScore = score;
        ctx.CvssSeverity = severity;

        // Pull researcher identity (Name / Handle / Blog / Email / PGP / INCIBE display)
        // from Configuration so the renderers don't emit "Researcher: ()" placeholders.
        ctx.ApplyResearcherFromConfig();

        return ctx;
    }

    private static string? ExtractVendorHint(PeAnalysis pe)
    {
        // Prefer Authenticode Subject CN (cryptographically bound to publisher) over the
        // self-reported version-info CompanyName. Falls back to Extract(pe) on unsigned files.
        if (!string.IsNullOrWhiteSpace(pe.Path) && System.IO.File.Exists(pe.Path))
        {
            var fromCert = Core.Services.Advisory.VendorResolver.ResolveFromFile(pe.Path);
            if (!string.IsNullOrWhiteSpace(fromCert)) return fromCert;
        }
        return Core.Services.Advisory.VendorResolver.Extract(pe);
    }

    private static CvssVector InferCvssFrom(AdvisoryContext ctx)
    {
        var v = new CvssVector(); // defaults L/L/L/N/U/H/H/H

        // User interaction: if importer is an EXE the user launches, Required. If service/task, None.
        if (ctx.Privesc?.Findings.Any(f => f.Vector == PrivescVector.ServiceSystem || f.Vector == PrivescVector.ScheduledTask) == true)
            v.UserInteraction = 'N';
        else
            v.UserInteraction = 'R';

        // Scope: changed when privesc crosses integrity boundaries (user → SYSTEM)
        if (ctx.Privesc?.HasSystemPath == true) v.Scope = 'C';

        // PR: none if writable by low-priv principals + phantom (no prior file to replace)
        if (ctx.DirectoryLowPrivWritable) v.PrivilegesRequired = 'L';

        return v;
    }

    // ---------- CVSS combos ----------

    private void PopulateTemplateCombo()
    {
        foreach (var r in AdvisoryRenderers.All) TemplateCombo.Items.Add(r.DisplayName);
        TemplateCombo.SelectedIndex = 0; // Markdown by default
        _lastAppliedTemplateIndex = 0;
    }

    private void TemplateCombo_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if (_suppressTemplateChanged) return;

        // Destructive: switching template re-renders the editor from scratch. If the user
        // has manual edits and cancels the prompt, we have to revert the combo to the
        // previously applied index — without _suppressTemplateChanged this would re-enter.
        if (!ConfirmDestructiveRerender())
        {
            _suppressTemplateChanged = true;
            try { TemplateCombo.SelectedIndex = _lastAppliedTemplateIndex; }
            finally { _suppressTemplateChanged = false; }
            return;
        }

        _activeRenderer = AdvisoryRenderers.All[TemplateCombo.SelectedIndex];
        _lastAppliedTemplateIndex = TemplateCombo.SelectedIndex;
        UpdateDynamicLabels();
        RerenderEditor();
    }

    private void RerenderEditor()
    {
        SetEditorTextSilently(_activeRenderer.Render(_ctx));
        _previewTimer.Stop();
        _previewTimer.Start();
    }

    /// <summary>
    /// Replace MdEditor.Text without flipping the dirty flag. Use for every programmatic
    /// write (template re-render, fresh load, CVSS apply, Template Fields apply). The
    /// guard is reset in <c>finally</c> so an exception during assignment can't leave the
    /// page in a state where genuine user edits no longer mark dirty.
    /// </summary>
    private void SetEditorTextSilently(string text)
    {
        _suppressEditorDirty = true;
        try { MdEditor.Text = text; }
        finally
        {
            _editorDirty = false;
            _suppressEditorDirty = false;
        }
    }

    /// <summary>
    /// Prompt before any action that wholesale replaces editor content. Returns true if the
    /// caller may proceed (no manual edits, or user accepted the discard).
    /// </summary>
    private bool ConfirmDestructiveRerender()
    {
        if (!_editorDirty) return true;
        var res = MessageBox.Show(
            "The current draft has manual edits. Re-rendering from the template will replace the editor content. Continue?",
            "Discard manual edits?",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Warning,
            MessageBoxResult.Cancel);
        return res == MessageBoxResult.OK;
    }

    /// <summary>
    /// Restore the renderer that was active when the advisory was last saved. Resolves the id
    /// against <see cref="AdvisoryRenderers.ById"/>; falls back to Markdown if the id is null,
    /// blank, or unknown (e.g. a renderer was removed in a future build). Caller must invoke
    /// this BEFORE any RerenderEditor / Render call so the editor doesn't briefly hold Markdown
    /// content for an INCIBE/GHSA advisory.
    /// </summary>
    /// <summary>
    /// Refresh button labels and tooltips that depend on the active renderer or on whether
    /// the editor is bound to an existing Library record. Centralised so every state change
    /// (template switch, Save creating a record, Reload context detaching, etc.) lands here.
    /// </summary>
    private void UpdateDynamicLabels()
    {
        if (_activeRenderer == null) return;
        var ext = System.IO.Path.GetExtension(_activeRenderer.DefaultFilename);
        if (string.IsNullOrEmpty(ext)) ext = ".txt";

        if (SaveSourceBtn != null)
        {
            SaveSourceBtn.Content = $"Save {ext}";
            SaveSourceBtn.ToolTip = $"Save the editor content as a standalone {ext} file (no Library write).";
        }

        if (SaveHtmlBtn != null)
        {
            // HTML export only meaningful for Markdown — INCIBE TXT and GHSA YAML have no
            // markup the converter would render usefully, just escape the whole thing as <pre>.
            SaveHtmlBtn.Visibility = _activeRenderer.Id == "markdown"
                ? System.Windows.Visibility.Visible
                : System.Windows.Visibility.Collapsed;
        }

        if (ModeLabel != null)
        {
            // Replace the generic "Output: advisory.md" with the renderer's display name + ext
            // so the user can scan and know which format the editor body represents.
            ModeLabel.Text = $"{_activeRenderer.DisplayName.ToUpperInvariant()} SOURCE  ·  {_activeRenderer.DefaultFilename}";
        }

        if (SaveToLibraryBtn != null)
        {
            var existingId = _main?.PendingAdvisoryRecordId;
            SaveToLibraryBtn.Content = string.IsNullOrEmpty(existingId)
                ? "Create library record"
                : $"Update record · {existingId}";
        }
    }

    private void ApplyPendingTemplate(string? templateId)
    {
        var renderer = string.IsNullOrWhiteSpace(templateId)
            ? AdvisoryRenderers.All[0]
            : AdvisoryRenderers.ById(templateId!) ?? AdvisoryRenderers.All[0];
        _activeRenderer = renderer;
        var idx = AdvisoryRenderers.All.ToList().FindIndex(r => r.Id == renderer.Id);
        if (idx >= 0)
        {
            // Suppress the change handler — this is a programmatic load, not a user-driven
            // template switch; we don't want to prompt or re-render here.
            _suppressTemplateChanged = true;
            try { TemplateCombo.SelectedIndex = idx; }
            finally { _suppressTemplateChanged = false; }
            _lastAppliedTemplateIndex = idx;
        }
        UpdateDynamicLabels();
    }

    /// <summary>Sync the inline Vendor textbox into ctx.Vendor on each keystroke.</summary>
    private void VendorBox_Changed(object sender, TextChangedEventArgs e)
    {
        if (_suppressForm || !IsLoaded) return;
        _ctx.Vendor = NullIfBlank(VendorBox.Text);
        // For non-Markdown templates the vendor name is interpolated into the rendered text,
        // so we'd normally re-render to reflect it. Skip the re-render entirely if the user
        // has manual edits — the keystroke alone shouldn't trigger a destructive prompt on
        // every character. They can pick up the new vendor by hitting "Apply CVSS" or
        // re-selecting the template once they're ready to lose manual edits.
        if (_activeRenderer.Id != "markdown" && !_editorDirty) RerenderEditor();
    }

    /// <summary>
    /// Opens the dedicated Template Fields modal. The dialog mutates <see cref="_ctx"/> in place
    /// when the user clicks Apply; we then re-render the editor so the new values show up.
    /// Prompts before re-render if there are manual edits, since the new render replaces them.
    /// </summary>
    private void OpenFormFields_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new TemplateFieldsDialog(_ctx, _activeRenderer) { Owner = Window.GetWindow(this) };
        if (dlg.ShowDialog() != true) return;

        if (!ConfirmDestructiveRerender())
        {
            // _ctx already mutated — fields persist on next Save and on the next intentional
            // re-render — but the editor stays as-is so manual edits aren't lost.
            FooterStatus.Text = "Template fields stored. Editor not re-rendered (manual edits preserved).";
            return;
        }
        RerenderEditor();
        FooterStatus.Text = $"Template fields applied to {_activeRenderer.DisplayName}.";
    }

    private static string? NullIfBlank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    /// <summary>
    /// Build the canonical SourceCandidateKey stored on the advisory record. ScanPage later
    /// queries this key to stamp a REPORTED badge on rows that match. Keys must be stable
    /// across sessions — we use lowercased absolute paths, no trailing slashes.
    /// </summary>
    private static string? BuildSourceKey(AdvisoryContext ctx)
    {
        if (!string.IsNullOrWhiteSpace(ctx.PePath))
            return $"existing|{ctx.PePath.Trim().ToLowerInvariant()}";
        if (!string.IsNullOrWhiteSpace(ctx.InstallDirectory) && !string.IsNullOrWhiteSpace(ctx.PeFilename))
            return $"phantom|{ctx.InstallDirectory.Trim().ToLowerInvariant()}|{ctx.PeFilename.Trim().ToLowerInvariant()}";
        return null;
    }

    private static string? BuildSourceKind(AdvisoryContext ctx) =>
        !string.IsNullOrWhiteSpace(ctx.PePath) ? "Existing" :
        !string.IsNullOrWhiteSpace(ctx.InstallDirectory) && !string.IsNullOrWhiteSpace(ctx.PeFilename) ? "Phantom" :
        null;

    /// <summary>Push ctx.Vendor into the inline Vendor textbox. Called on ctx reloads.</summary>
    private void PushCtxIntoForm()
    {
        _suppressForm = true;
        try { VendorBox.Text = _ctx.Vendor ?? ""; }
        finally { _suppressForm = false; }
    }

    private void PopulateCvssCombos()
    {
        CvssAv.ItemsSource = new[] { Item("L", "Local"), Item("A", "Adjacent"), Item("N", "Network"), Item("P", "Physical") };
        CvssAc.ItemsSource = new[] { Item("L", "Low"), Item("H", "High") };
        CvssPr.ItemsSource = new[] { Item("N", "None"), Item("L", "Low"), Item("H", "High") };
        CvssUi.ItemsSource = new[] { Item("N", "None"), Item("R", "Required") };
        CvssS.ItemsSource  = new[] { Item("U", "Unchanged"), Item("C", "Changed") };
        CvssC.ItemsSource  = new[] { Item("N", "None"), Item("L", "Low"), Item("H", "High") };
        CvssI.ItemsSource  = new[] { Item("N", "None"), Item("L", "Low"), Item("H", "High") };
        CvssA.ItemsSource  = new[] { Item("N", "None"), Item("L", "Low"), Item("H", "High") };
    }

    private record CvssItem(string Key, string Label)
    {
        public override string ToString() => $"{Key} · {Label}";
    }
    private static CvssItem Item(string k, string l) => new(k, l);

    private static void SetComboByKey(System.Windows.Controls.ComboBox combo, char key)
    {
        foreach (var item in combo.Items)
        {
            if (item is CvssItem ci && ci.Key.Length > 0 && ci.Key[0] == key)
            {
                combo.SelectedItem = item;
                return;
            }
        }
        if (combo.Items.Count > 0) combo.SelectedIndex = 0;
    }

    private static char GetKeyFromCombo(System.Windows.Controls.ComboBox combo) =>
        combo.SelectedItem is CvssItem ci && ci.Key.Length > 0 ? ci.Key[0] : '\0';

    private void Cvss_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressCvssChanged) return;
        RecomputeCvss();
    }

    private void RecomputeCvss()
    {
        if (CvssAv.SelectedItem == null) return;
        _ctx.Cvss.AttackVector       = GetKeyFromCombo(CvssAv);
        _ctx.Cvss.AttackComplexity   = GetKeyFromCombo(CvssAc);
        _ctx.Cvss.PrivilegesRequired = GetKeyFromCombo(CvssPr);
        _ctx.Cvss.UserInteraction    = GetKeyFromCombo(CvssUi);
        _ctx.Cvss.Scope              = GetKeyFromCombo(CvssS);
        _ctx.Cvss.Confidentiality    = GetKeyFromCombo(CvssC);
        _ctx.Cvss.Integrity          = GetKeyFromCombo(CvssI);
        _ctx.Cvss.Availability       = GetKeyFromCombo(CvssA);

        var (score, sev) = CvssCalculator.Compute(_ctx.Cvss);
        _ctx.CvssScore = score;
        _ctx.CvssSeverity = sev;
        CvssResult.Text = $"Score: {score:0.0} {sev}";
    }

    private void ApplyCvss_Click(object sender, RoutedEventArgs e)
    {
        // Non-destructive: recompute the CVSS score from the current combo selection and
        // update the score label only. The editor body is NOT touched — manual edits to
        // the document survive intact. The new score is persisted to _ctx and will be
        // reflected in the next intentional re-render or in any future Save (which writes
        // _ctx.CvssScore to the record regardless of editor body).
        RecomputeCvss();
        FooterStatus.Text = $"CVSS recomputed: {_ctx.CvssScore:0.0} {_ctx.CvssSeverity}  ·  editor body unchanged";
    }

    // ---------- Editor + preview ----------

    private void MdEditor_TextChanged(object sender, TextChangedEventArgs e)
    {
        // Only flag dirty for genuine user edits — programmatic writes via SetEditorTextSilently
        // are bracketed by _suppressEditorDirty and clear the flag in their finally block.
        if (!_suppressEditorDirty) _editorDirty = true;
        _previewTimer.Stop();
        _previewTimer.Start();
    }

    // ---------- Mode toggle (Edit / Preview in same pane) ----------

    private void EditMode_Checked(object sender, RoutedEventArgs e)
    {
        if (PreviewModeBtn != null) PreviewModeBtn.IsChecked = false;
        if (MdEditor != null) MdEditor.Visibility = Visibility.Visible;
        if (Preview != null) Preview.Visibility = Visibility.Collapsed;
        if (ModeLabel != null) ModeLabel.Text = "MARKDOWN SOURCE";
    }

    private void PreviewMode_Checked(object sender, RoutedEventArgs e)
    {
        if (EditModeBtn != null) EditModeBtn.IsChecked = false;
        if (MdEditor != null) MdEditor.Visibility = Visibility.Collapsed;
        if (Preview != null) Preview.Visibility = Visibility.Visible;
        if (ModeLabel != null) ModeLabel.Text = "PREVIEW (HTML)";
        RefreshPreview();
    }

    private void RefreshPreview()
    {
        try
        {
            var src = MdEditor.Text ?? "";
            string body;
            // Markdig is meaningful for every markdown-producing renderer. We key off the
            // active renderer's FileExtension ("md") instead of the renderer Id so future
            // markdown variants (e.g. a slimmer 'vendor-email.md') auto-render without
            // having to touch this switch. INCIBE keeps its plain pre.raw path because
            // its template is ASCII-art bordered text Markdig would mangle into stray
            // <em>/<p> wrappers.
            if (string.Equals(_activeRenderer.FileExtension, ".md", StringComparison.OrdinalIgnoreCase))
            {
                body = Markdown.ToHtml(src, _mdPipeline);
            }
            else
            {
                // Plain monospace preview that mirrors the editor 1:1 — no transformation,
                // just HTML-escape and wrap in <pre> so the WebBrowser respects whitespace.
                var escaped = System.Net.WebUtility.HtmlEncode(src);
                body = $"<pre class='raw'>{escaped}</pre>";
            }
            Preview.NavigateToString(WrapWithCss(body));
        }
        catch (Exception ex)
        {
            Log.Warn("advisory.preview", "Preview render failed", ex);
        }
    }

    /// <summary>Wrap the HTML with a dark-ish stylesheet so preview matches the app theme.</summary>
    private static string WrapWithCss(string html)
    {
        return "<!DOCTYPE html><html><head><meta charset='utf-8'>" +
               "<style>" +
               "body{background:#0a0a0a;color:#ededed;font-family:'Segoe UI',Arial,sans-serif;" +
                    "line-height:1.55;padding:24px;font-size:14px;margin:0;}" +
               "h1{font-size:24px;font-weight:600;margin:0 0 16px;color:#ffffff;border-bottom:1px solid #262626;padding-bottom:8px;}" +
               "h2{font-size:18px;font-weight:600;margin:24px 0 10px;color:#ffffff;}" +
               "h3{font-size:15px;font-weight:600;margin:18px 0 8px;color:#ededed;}" +
               "p{margin:0 0 10px;color:#d4d4d4;}" +
               "ul,ol{margin:0 0 10px 20px;padding:0;}" +
               "li{margin:2px 0;}" +
               "a{color:#52a8ff;text-decoration:none;}" +
               "a:hover{text-decoration:underline;}" +
               "code{background:#1a1a1a;color:#00f0a3;padding:2px 5px;border-radius:3px;" +
                    "font-family:'Cascadia Mono',Consolas,monospace;font-size:12px;}" +
               "pre{background:#111111;border:1px solid #262626;border-radius:6px;padding:12px;overflow:auto;}" +
               "pre code{background:transparent;color:#ededed;padding:0;}" +
               // pre.raw is used by the non-markdown preview path (INCIBE TXT) — full
               // viewport, no border/wrapper, so the ASCII-art INCIBE banner doesn't get clipped.
               "pre.raw{background:transparent;border:none;padding:16px;margin:0;color:#ededed;" +
                       "font-family:'Cascadia Mono',Consolas,monospace;font-size:12px;line-height:1.45;white-space:pre;}" +
               "table{border-collapse:collapse;margin:12px 0;}" +
               "th,td{border:1px solid #262626;padding:6px 12px;text-align:left;}" +
               "th{background:#1a1a1a;color:#a1a1a1;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;}" +
               "blockquote{border-left:3px solid #F5A524;margin:10px 0;padding:6px 14px;background:#1a1508;color:#d4d4d4;}" +
               "hr{border:none;border-top:1px solid #262626;margin:20px 0;}" +
               "strong{color:#ffffff;font-weight:600;}" +
               "</style></head><body>" + html + "</body></html>";
    }

    // ---------- Library (Fase 7c.1) ----------

    private async void SaveToLibrary_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            SaveToLibraryBtn.IsEnabled = false;
            var repo = new Core.Services.AdvisoryLibrary.AdvisoryRepository();
            await repo.InitializeAsync();

            var editorContent = MdEditor.Text ?? "";
            var existingId = _main.PendingAdvisoryRecordId;
            string recordId;

            if (!string.IsNullOrEmpty(existingId))
            {
                var record = await repo.GetAsync(existingId);
                if (record != null)
                {
                    // Identity guard: refuse to silently overwrite a record's PE identity.
                    // If the user opened existing record A and then re-loaded context from a
                    // different PE B (Reload context, or wizard handoff), continuing the Save
                    // would replace A's metadata with B's — the bug that destroyed urlmon.
                    var ctxPe = (_ctx.PeFilename ?? "").Trim();
                    var recPe = (record.PeFilename ?? "").Trim();
                    var identityChanged = !string.IsNullOrEmpty(ctxPe)
                                       && !string.IsNullOrEmpty(recPe)
                                       && !string.Equals(ctxPe, recPe, StringComparison.OrdinalIgnoreCase);
                    if (identityChanged)
                    {
                        var choice = MessageBox.Show(
                            $"This advisory was created for '{recPe}' but the editor now describes '{ctxPe}'.\n\n" +
                            "Yes  — overwrite '" + recPe + "' with the new content (the original metadata is lost).\n" +
                            "No   — save as a NEW advisory record (recommended; '" + recPe + "' is preserved).\n" +
                            "Cancel — do nothing.",
                            "Different PE detected",
                            MessageBoxButton.YesNoCancel,
                            MessageBoxImage.Warning,
                            MessageBoxResult.No);
                        if (choice == MessageBoxResult.Cancel)
                        {
                            FooterStatus.Text = "Save cancelled (identity mismatch).";
                            return;
                        }
                        if (choice == MessageBoxResult.No)
                        {
                            // Fall into the create-new path. Drop the pending id so the next
                            // Save also goes to the new record, not back to the old one.
                            _main.PendingAdvisoryRecordId = null;
                            existingId = null;
                            record = null;
                        }
                    }
                }

                if (record != null)
                {
                    ApplyContextToRecord(_ctx, record);
                    record.MarkdownBody = editorContent;
                    record.LastTemplateId = _activeRenderer.Id;
                    await repo.SaveDraftAsync(record);
                    recordId = record.Id;
                    FooterStatus.Text = $"Updated in library (id: {record.Id}).";
                    _main.Log($"Advisory {record.Id} updated in library");
                }
                else if (!string.IsNullOrEmpty(existingId))
                {
                    var created = await repo.CreateFromContextAsync(_ctx, editorContent,
                        new Core.Models.AdvisoryLibrary.AdvisoryCreateOptions { LastTemplateId = _activeRenderer.Id });
                    _main.PendingAdvisoryRecordId = created.Id;
                    recordId = created.Id;
                    FooterStatus.Text = $"Saved to library as Draft (id: {created.Id}).";
                    _main.Log($"Advisory {created.Id} saved to library");
                }
                else
                {
                    // Identity-mismatch user chose "Save as NEW" — fall through to the
                    // standard create path below by leaving recordId unset; we re-enter
                    // the else branch via flow.
                    var options = new Core.Models.AdvisoryLibrary.AdvisoryCreateOptions
                    {
                        SourceScanDir = _main.LastScanDir,
                        SourceCandidateKind = BuildSourceKind(_ctx),
                        SourceCandidateKey = BuildSourceKey(_ctx),
                        LastTemplateId = _activeRenderer.Id,
                    };
                    var created = await repo.CreateFromContextAsync(_ctx, editorContent, options);
                    _main.PendingAdvisoryRecordId = created.Id;
                    recordId = created.Id;
                    FooterStatus.Text = $"Saved to library as new Draft (id: {created.Id}).";
                    _main.Log($"Advisory {created.Id} saved as new (identity differed from previous record)");
                }
            }
            else
            {
                // Stamp SourceCandidateKey so ScanPage's REPORTED badge can cross-reference later.
                var options = new Core.Models.AdvisoryLibrary.AdvisoryCreateOptions
                {
                    SourceScanDir = _main.LastScanDir,
                    SourceCandidateKind = BuildSourceKind(_ctx),
                    SourceCandidateKey = BuildSourceKey(_ctx),
                    LastTemplateId = _activeRenderer.Id,
                };
                var created = await repo.CreateFromContextAsync(_ctx, editorContent, options);
                _main.PendingAdvisoryRecordId = created.Id;
                recordId = created.Id;
                FooterStatus.Text = $"Saved to library as Draft (id: {created.Id}).";
                _main.Log($"Advisory {created.Id} saved to library");
            }

            // Persist the editor content as an Artifact under the active template's folder.
            // The editor IS the canonical draft at save time, so the file on disk must mirror
            // it verbatim — re-rendering from _ctx here would silently discard manual edits to
            // INCIBE/GHSA bodies (DB MarkdownBody would have them, disk artifact would not).
            try
            {
                var kind = _activeRenderer.Id switch
                {
                    "markdown" => Core.Models.AdvisoryLibrary.ArtifactKind.Markdown,
                    _ => Core.Models.AdvisoryLibrary.ArtifactKind.Attachment,
                };
                var art = await repo.WriteArtifactAsync(recordId, _activeRenderer.Id, kind, editorContent);
                _main.Log($"Artifact saved: {art.Path}");
                FooterStatus.Text += $"   →   {_activeRenderer.DisplayName} rendered at {art.Path}";

                // Keep all the advisory's other rendered artifacts (markdown / incibe / ghsa)
                // consistent with the new metadata. Without this, a Save with a different vendor
                // or title leaves stale renders on disk that contradict the DB record (this is
                // the second half of the urlmon class of bug — the .md said urlmon but the
                // record said profapi). Manual edits to non-active templates aren't possible
                // through the UI today, so re-rendering is safe.
                try
                {
                    var existing = await repo.GetArtifactsForAdvisoryAsync(recordId);
                    foreach (var other in existing)
                    {
                        if (string.IsNullOrEmpty(other.TemplateId)) continue;
                        if (string.Equals(other.TemplateId, _activeRenderer.Id, StringComparison.OrdinalIgnoreCase)) continue;
                        var otherRenderer = AdvisoryRenderers.ById(other.TemplateId);
                        if (otherRenderer == null) continue;
                        var rendered = otherRenderer.Render(_ctx);
                        var otherKind = otherRenderer.Id == "markdown"
                            ? Core.Models.AdvisoryLibrary.ArtifactKind.Markdown
                            : Core.Models.AdvisoryLibrary.ArtifactKind.Attachment;
                        await repo.WriteArtifactAsync(recordId, otherRenderer.Id, otherKind, rendered);
                        _main.Log($"Re-rendered {otherRenderer.DisplayName} for consistency");
                    }
                }
                catch (Exception rex)
                {
                    _main.Log($"Sibling re-render skipped: {rex.Message}");
                }
            }
            catch (Exception aex)
            {
                _main.Log($"Artifact write skipped: {aex.Message}");
            }

            // Save complete — editor matches DB + disk, so manual-edits flag is clean.
            _editorDirty = false;
            // Pending record id may have flipped (new record created OR detach via identity-mismatch);
            // refresh the Save button label so the user sees the right "Update / Create" wording next time.
            UpdateDynamicLabels();
        }
        catch (Exception ex)
        {
            FooterStatus.Text = $"Library save failed: {ex.Message}";
            _main.Log($"Save to library failed: {ex.Message}");
        }
        finally
        {
            SaveToLibraryBtn.IsEnabled = true;
        }
    }

    private static void ApplyContextToRecord(Core.Models.Advisory.AdvisoryContext ctx,
        Core.Models.AdvisoryLibrary.AdvisoryRecord record)
    {
        record.Title = ctx.Title
            .Replace("{Product}", ctx.Product ?? "")
            .Replace("{Filename}", ctx.PeFilename ?? "")
            .Replace("{Vendor}", ctx.Vendor ?? "")
            .Replace("  ", " ").Trim();
        // Preserve whatever vendor the DB already has if ctx.Vendor comes in empty — the
        // user may have just renamed it in the Library tree and re-saving from here would
        // otherwise blank it. Only overwrite when AdvisoryPage has an explicit value.
        if (!string.IsNullOrWhiteSpace(ctx.Vendor))
            record.Vendor = ctx.Vendor;
        record.Product = ctx.Product;
        record.ProductVersion = ctx.Version;
        record.Architecture = ctx.Architecture;
        record.PePath = ctx.PePath;
        record.PeFilename = ctx.PeFilename;
        record.InstallDirectory = ctx.InstallDirectory;
        record.VulnerabilityType = ctx.VulnType;
        record.CweId = ctx.Cwe;
        record.CweName = ctx.CweName;
        record.PayloadDescription = ctx.PayloadDescription;
        record.ImporterExe = ctx.ImporterExe;
        record.GeneratedDllPath = ctx.GeneratedDllPath;
        record.DirectoryLowPrivWritable = ctx.DirectoryLowPrivWritable;
        record.WritableByPrincipals = ctx.WritableByPrincipals;
        record.CvssVector = ctx.Cvss?.VectorString;
        record.CvssScore = ctx.CvssScore > 0 ? ctx.CvssScore : null;
        record.CvssSeverity = ctx.CvssSeverity;
        record.DisclosurePolicy = ctx.DisclosurePolicy;
        record.DiscoveredOn = ctx.DiscoveredOn == default ? null : ctx.DiscoveredOn;
        record.ReportedOn = ctx.ReportedOn;
        record.DisclosedOn = ctx.DisclosedOn;

        // Template Fields (schema v4) — these come from TemplateFieldsDialog and live entirely
        // on the record. Researcher PGP / INCIBE rank fields are persisted verbatim; on Load we
        // fall back to ConfigManager.Current.Researcher when the record's value is blank.
        record.AttackType = ctx.AttackType.ToString();
        record.ImpactCategory = ctx.ImpactCategory.ToString();
        record.VulnerabilityTypeText = NullIfBlank(ctx.VulnerabilityTypeText);
        record.VendorUrl = NullIfBlank(ctx.VendorUrl);
        record.VendorPocName = NullIfBlank(ctx.VendorPocName);
        record.VendorPocEmail = NullIfBlank(ctx.VendorPocEmail);
        record.DeviceUrlReference = NullIfBlank(ctx.DeviceUrlReference);
        record.DeviceBriefSummary = NullIfBlank(ctx.DeviceBriefSummary);
        record.AffectedComponents = NullIfBlank(ctx.AffectedComponents);
        record.PreviousRequirements = NullIfBlank(ctx.PreviousRequirements);
        record.ProposedSolution = NullIfBlank(ctx.ProposedSolution);
        record.HasContactedVendorNote = NullIfBlank(ctx.HasContactedVendorNote);
        record.CvssV4Vector = NullIfBlank(ctx.CvssV4?.VectorString);
        record.CvssV4Score = ctx.CvssV4Score > 0 ? ctx.CvssV4Score : null;
        record.CvssV4Severity = NullIfBlank(ctx.CvssV4Severity);
        record.ResearcherPgpFingerprint = NullIfBlank(ctx.ResearcherPgpFingerprint);
        record.ResearcherPgpKeyId = NullIfBlank(ctx.ResearcherPgpKeyId);
        record.IncibeRankingOptIn = ctx.IncibeRankingOptIn;
        record.IncibePublicDisplayName = NullIfBlank(ctx.IncibePublicDisplayName);
    }

    // ---------- Save / Print / Copy ----------

    private void CopyAll_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Windows.Clipboard.SetText(MdEditor.Text ?? "");
            FooterStatus.Text = "Markdown copied to clipboard.";
        }
        catch (Exception ex)
        {
            Log.Warn("advisory", "Clipboard failed", ex);
            FooterStatus.Text = $"Clipboard unavailable: {ex.Message}";
        }
    }

    private void SaveMd_Click(object sender, RoutedEventArgs e)
    {
        var suggested = BuildSuggestedFilename(".md");
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "Markdown (*.md)|*.md|All files|*.*",
            FileName = suggested,
            Title = "Save advisory as Markdown",
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            File.WriteAllText(dlg.FileName, MdEditor.Text ?? "", new UTF8Encoding(false));
            FooterStatus.Text = $"Saved: {dlg.FileName}";
            _main.Log($"Advisory saved: {dlg.FileName}");
        }
        catch (Exception ex)
        {
            Log.Error("advisory", "Save failed", ex);
            MessageBox.Show($"Save failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SaveHtml_Click(object sender, RoutedEventArgs e)
    {
        var suggested = BuildSuggestedFilename(".html");
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "HTML (*.html)|*.html|All files|*.*",
            FileName = suggested,
            Title = "Save advisory as HTML",
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var html = Markdown.ToHtml(MdEditor.Text ?? "", _mdPipeline);
            File.WriteAllText(dlg.FileName, WrapWithPdfCss(html, _ctx.Title), new UTF8Encoding(false));
            FooterStatus.Text = $"Saved HTML: {dlg.FileName}";
            _main.Log($"Advisory HTML saved: {dlg.FileName}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Save failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// Professional PDF export via Chrome/Edge headless print. No Windows print dialog,
    /// no external library — uses the Chromium PDF engine that ships with Chrome or Edge
    /// (both present on every modern Windows install). Renders our full CSS exactly as
    /// the preview shows it, produces archival-quality PDFs.
    /// </summary>
    private async void ExportPdf_Click(object sender, RoutedEventArgs e)
    {
        var browsers = FindBrowsers();
        if (browsers.Count == 0)
        {
            var fallback = MessageBox.Show(
                "Chrome or Edge was not found — neither is required per se, but headless print needs one of them.\n\n" +
                "Fallback: save the HTML and use your browser's Ctrl+P → Save as PDF.\n\n" +
                "Do you want to save as HTML instead?",
                "PDF export", MessageBoxButton.YesNo, MessageBoxImage.Information);
            if (fallback == MessageBoxResult.Yes) SaveHtml_Click(sender, e);
            return;
        }

        var suggested = BuildSuggestedFilename(".pdf");
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "PDF (*.pdf)|*.pdf|All files|*.*",
            FileName = suggested,
            Title = "Export advisory as PDF",
        };
        if (dlg.ShowDialog() != true) return;

        var outPdf = dlg.FileName;
        Overlay.Show("Exporting PDF", $"Rendering via {Path.GetFileName(browsers[0])}...");
        try
        {
            var html = Markdown.ToHtml(MdEditor.Text ?? "", _mdPipeline);
            var fullHtml = WrapWithPdfCss(html, _ctx.Title);

            // Write HTML to a temp file — headless print takes a file:// URL
            var tempHtml = Path.Combine(Path.GetTempPath(), $"dllsidecar-advisory-{Guid.NewGuid():N}.html");
            await File.WriteAllTextAsync(tempHtml, fullHtml, new UTF8Encoding(false));

            try
            {
                // Try every located browser in order. Edge with corporate policies that
                // forbid headless mode exits 0 but writes nothing — try Chrome next.
                Exception? lastError = null;
                foreach (var browser in browsers)
                {
                    try
                    {
                        if (browser != browsers[0])
                            Overlay.Show("Exporting PDF", $"Retrying via {Path.GetFileName(browser)}...");
                        await RunHeadlessPrintAsync(browser, tempHtml, outPdf);
                        if (File.Exists(outPdf) && new FileInfo(outPdf).Length >= 200)
                        {
                            lastError = null;
                            break;
                        }
                        // Missing/undersized output — keep the exception cause for the
                        // user even when this was the last browser candidate.
                        lastError = new InvalidOperationException(
                            $"{Path.GetFileName(browser)} exited successfully but no PDF was written.");
                    }
                    catch (Exception ex)
                    {
                        lastError = ex;
                        Log.Warn("advisory.pdf", $"{Path.GetFileName(browser)} attempt failed: {ex.Message}");
                    }
                    finally
                    {
                        try { if (File.Exists(outPdf) && new FileInfo(outPdf).Length < 200) File.Delete(outPdf); }
                        catch (IOException) { }
                    }
                }
                if (lastError != null) throw lastError;

                FooterStatus.Text = $"Exported PDF: {outPdf}";
                _main.Log($"Advisory PDF exported: {outPdf}  ({new FileInfo(outPdf).Length:N0} bytes)");
            }
            finally
            {
                try { File.Delete(tempHtml); } catch (IOException) { /* keep for debugging */ }
            }
        }
        catch (Exception ex)
        {
            Log.Error("advisory.pdf", "Export failed", ex);
            MessageBox.Show($"PDF export failed: {ex.Message}\n\nTry 'Save HTML' and Ctrl+P → Save as PDF from your browser.",
                "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { Overlay.Hide(); }
    }

    /// <summary>
    /// Locate every Chrome / Edge binary present on the system, ordered by preference.
    /// Chrome first when available — corporate Edge installs occasionally honour a
    /// HeadlessMode policy that makes --headless --print-to-pdf exit 0 without writing
    /// the PDF. Trying Chrome as a fallback recovers cleanly in that case.
    /// </summary>
    private static List<string> FindBrowsers()
    {
        string[] candidates =
        [
            Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            Environment.ExpandEnvironmentVariables(@"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
            Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            Environment.ExpandEnvironmentVariables(@"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        ];
        var found = new List<string>();
        foreach (var c in candidates)
            if (File.Exists(c)) found.Add(c);
        return found;
    }

    private static async Task RunHeadlessPrintAsync(string chromium, string htmlPath, string pdfPath)
    {
        // Build a file:// URI for the input HTML
        var uri = new Uri(htmlPath).AbsoluteUri;

        // Dedicated profile dir — without --user-data-dir, --headless=new shares the
        // user's default profile and silently no-ops (exit 0, no file written) when
        // the user has Edge/Chrome already running. The profile dir gets removed
        // after the process exits.
        var tempProfile = Path.Combine(Path.GetTempPath(), $"dllsidecar-headless-{Guid.NewGuid():N}");

        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = chromium,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        // Modern headless print-to-pdf flag set. `--run-all-compositor-stages-before-draw`
        // replaces `--virtual-time-budget` as the recommended way to wait for compositor
        // work to finish before snapshotting — virtual-time-budget started returning
        // exit 0 without writing the PDF on some Edge/Chrome 124+ builds, especially
        // when the host process runs elevated (DllSidecar requires admin).
        psi.ArgumentList.Add("--headless=new");
        psi.ArgumentList.Add("--disable-gpu");
        psi.ArgumentList.Add("--no-sandbox");
        psi.ArgumentList.Add("--disable-extensions");
        psi.ArgumentList.Add("--disable-background-networking");
        psi.ArgumentList.Add("--run-all-compositor-stages-before-draw");
        psi.ArgumentList.Add($"--user-data-dir={tempProfile}");
        psi.ArgumentList.Add("--no-pdf-header-footer");
        psi.ArgumentList.Add($"--print-to-pdf={pdfPath}");
        psi.ArgumentList.Add(uri);

        var browserName = Path.GetFileName(chromium);
        Log.Info("advisory.pdf", $"{browserName} {string.Join(" ", psi.ArgumentList)}");

        try
        {
            using var proc = System.Diagnostics.Process.Start(psi)
                ?? throw new InvalidOperationException($"Could not start {browserName}");

            await proc.WaitForExitAsync();

            // Capture stderr regardless of exit code — it is the only diagnostic the
            // user has in the failure path, since WPF apps don't surface a console.
            var err = (await proc.StandardError.ReadToEndAsync()).Trim();

            if (proc.ExitCode != 0)
                throw new InvalidOperationException($"{browserName} exit {proc.ExitCode}: {Truncate(err, 600)}");

            if (!File.Exists(pdfPath) || new FileInfo(pdfPath).Length < 200)
                throw new InvalidOperationException(
                    $"{browserName} exited 0 but no PDF was written. stderr: {Truncate(err, 600)}");

            if (!string.IsNullOrEmpty(err))
                Log.Warn("advisory.pdf", $"{browserName} stderr (exit 0): {err}");
        }
        finally
        {
            // Best-effort profile cleanup. Chromium may still hold file handles for
            // a brief window — swallow IOExceptions and let the next run's GUID
            // create a fresh dir.
            try { if (Directory.Exists(tempProfile)) Directory.Delete(tempProfile, true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) ? "(empty)" : (s.Length <= max ? s : s.Substring(0, max) + "…");

    /// <summary>
    /// Light-theme CSS for PDF output — printable on white paper with dark ink.
    /// HtmlRenderer supports a subset of CSS2.1; keeps it simple.
    /// </summary>
    private static string WrapWithPdfCss(string html, string title)
    {
        var safeTitle = System.Net.WebUtility.HtmlEncode(title ?? "Advisory");
        return "<!DOCTYPE html><html><head><meta charset='utf-8'>" +
               $"<title>{safeTitle}</title>" +
               "<style>" +
               "body{font-family:'Segoe UI',Arial,sans-serif;color:#171717;font-size:11pt;line-height:1.5;}" +
               "h1{font-size:20pt;color:#000;margin:0 0 14pt;border-bottom:1px solid #888;padding-bottom:6pt;}" +
               "h2{font-size:15pt;color:#000;margin:18pt 0 8pt;}" +
               "h3{font-size:12pt;color:#222;margin:12pt 0 6pt;}" +
               "p{margin:0 0 8pt;}" +
               "ul,ol{margin:0 0 8pt 20pt;}" +
               "li{margin:2pt 0;}" +
               "code{background:#f0f0f0;color:#b00020;padding:1pt 4pt;font-family:Consolas,monospace;font-size:10pt;}" +
               "pre{background:#f8f8f8;border:1px solid #ccc;padding:8pt;font-family:Consolas,monospace;font-size:9.5pt;}" +
               "pre code{background:transparent;color:#171717;padding:0;}" +
               "table{border-collapse:collapse;margin:8pt 0;}" +
               "th,td{border:1px solid #bbb;padding:5pt 10pt;text-align:left;}" +
               "th{background:#f0f0f0;font-weight:bold;}" +
               "blockquote{border-left:3pt solid #f39c12;margin:8pt 0;padding:4pt 10pt;background:#fff8e6;}" +
               "hr{border:none;border-top:1px solid #bbb;margin:14pt 0;}" +
               "strong{color:#000;}" +
               "a{color:#0a72ef;text-decoration:none;}" +
               "</style></head><body>" + html + "</body></html>";
    }

    private string BuildSuggestedFilename(string ext)
    {
        var vendor = (_ctx.Vendor ?? "vendor").ToLowerInvariant();
        var product = (_ctx.Product ?? "product").Split(' ').FirstOrDefault()?.ToLowerInvariant() ?? "product";
        var file = Path.GetFileNameWithoutExtension(_ctx.PeFilename ?? "dll").ToLowerInvariant();
        var date = DateTime.Today.ToString("yyyyMMdd");
        var safe = $"advisory_{vendor}_{product}_{file}_{date}{ext}";
        // Strip filesystem-unsafe chars
        foreach (var c in Path.GetInvalidFileNameChars()) safe = safe.Replace(c, '_');
        return safe;
    }
}
