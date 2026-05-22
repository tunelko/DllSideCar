using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using DllSidecar.Core.Models.Advisory;
using DllSidecar.Core.Services.Advisory;
using DllSidecar.Core.Services.Advisory.Rendering;

namespace DllSidecar.GUI.Views;

/// <summary>
/// Dedicated modal for editing the template-specific fields of an AdvisoryContext.
/// Shows / hides rows based on the active renderer's <see cref="IAdvisoryRenderer.FieldHints"/>
/// so the researcher only sees inputs the destination format actually consumes.
///
/// Lifecycle:
///   - ctor takes the working AdvisoryContext + renderer; populates controls from ctx
///   - Apply: pulls all visible controls back into ctx (mutates in-place) → DialogResult=true
///   - Cancel: leaves ctx untouched
/// </summary>
public partial class TemplateFieldsDialog : Window
{
    private readonly AdvisoryContext _ctx;
    private readonly IAdvisoryRenderer _renderer;

    public TemplateFieldsDialog(AdvisoryContext ctx, IAdvisoryRenderer renderer)
    {
        _ctx = ctx;
        _renderer = renderer;
        InitializeComponent();
        Services.WindowChromeHelper.Apply(this, $"Template fields — {renderer.DisplayName}");
        ActiveLabel.Text = $"Active template: {renderer.DisplayName}   ·   output: {renderer.DefaultFilename}";
        ApplyFieldVisibility();
        PushCtxIntoControls();
    }

    private void ApplyFieldVisibility()
    {
        var hints = _renderer.FieldHints;
        RowVulnType.Visibility      = hints.Contains(AdvisoryField.VulnerabilityTypeText) ? Visibility.Visible : Visibility.Collapsed;
        RowVendorPoc.Visibility     = hints.Contains(AdvisoryField.VendorPocName)         ? Visibility.Visible : Visibility.Collapsed;
        RowAffected.Visibility      = hints.Contains(AdvisoryField.AffectedComponents)    ? Visibility.Visible : Visibility.Collapsed;
        RowRequirements.Visibility  = hints.Contains(AdvisoryField.PreviousRequirements)  ? Visibility.Visible : Visibility.Collapsed;
        RowSolution.Visibility      = hints.Contains(AdvisoryField.ProposedSolution)      ? Visibility.Visible : Visibility.Collapsed;
        RowCvssV4.Visibility        = hints.Contains(AdvisoryField.CvssV4)                ? Visibility.Visible : Visibility.Collapsed;
    }

    private void PushCtxIntoControls()
    {
        TbVulnType.Text     = _ctx.VulnerabilityTypeText ?? "";
        TbPocName.Text      = _ctx.VendorPocName ?? "";
        TbPocEmail.Text     = _ctx.VendorPocEmail ?? "";
        TbAffected.Text     = _ctx.AffectedComponents ?? "";
        TbRequirements.Text = _ctx.PreviousRequirements ?? "";
        TbSolution.Text     = _ctx.ProposedSolution ?? "";
        TbV4Vector.Text     = _ctx.CvssV4?.VectorString ?? "";
        TbV4Score.Text      = _ctx.CvssV4Score > 0
            ? _ctx.CvssV4Score.ToString("0.0", CultureInfo.InvariantCulture)
            : "";
    }

    private void PullControlsIntoCtx()
    {
        if (!string.IsNullOrWhiteSpace(TbVulnType.Text))
            _ctx.VulnerabilityTypeText = TbVulnType.Text.Trim();

        _ctx.VendorPocName       = Nullable(TbPocName.Text);
        _ctx.VendorPocEmail      = Nullable(TbPocEmail.Text);
        _ctx.AffectedComponents  = TbAffected.Text ?? "";
        _ctx.PreviousRequirements = TbRequirements.Text ?? "";
        _ctx.ProposedSolution    = TbSolution.Text ?? "";

        var v4 = TbV4Vector.Text?.Trim();
        if (!string.IsNullOrEmpty(v4))
        {
            var parsed = CvssV4Calculator.ParseVector(v4);
            if (parsed != null) _ctx.CvssV4 = parsed;
        }
        if (double.TryParse(TbV4Score.Text, NumberStyles.Any, CultureInfo.InvariantCulture, out var sc))
        {
            _ctx.CvssV4Score = sc;
            _ctx.CvssV4Severity = sc switch
            {
                0 => "NONE",
                < 4 => "LOW",
                < 7 => "MEDIUM",
                < 9 => "HIGH",
                _ => "CRITICAL",
            };
        }
    }

    private static string? Nullable(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        PullControlsIntoCtx();
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
