using System.Text;
using System.Windows;
using System.Windows.Controls;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

/// <summary>
/// Modal that disassembles a PE on open, lists every call/jmp through the IAT
/// to a dynamic-loading API, and lets the user filter and copy the results.
/// </summary>
public partial class CallsitesWindow : Window
{
    private readonly string _pePath;
    private List<Row> _all = [];
    private Dictionary<string, int> _trackedImports = new();

    public CallsitesWindow(string pePath, string? archHint = null)
    {
        _pePath = pePath;
        InitializeComponent();
        Services.WindowChromeHelper.Apply(this, "Callsites — dynamic loader API calls");
        HeaderTitle.Text = $"Loader-API callsites — {System.IO.Path.GetFileName(pePath)}"
                           + (string.IsNullOrEmpty(archHint) ? "" : $" ({archHint})");
        Loaded += (_, _) => Load();
    }

    private void Load()
    {
        try
        {
            Status.Text = "Scanning...";
            var scan = CallsiteScanner.Scan(_pePath);
            _all = scan.Callsites.Select(s => new Row(s)).ToList();
            _trackedImports = scan.TrackedImports;
            ApplyFilter();
        }
        catch (NotSupportedException ex)
        {
            Status.Text = $"Unsupported: {ex.Message}";
        }
        catch (Exception ex)
        {
            Status.Text = $"Scan failed: {ex.GetType().Name}: {ex.Message}";
        }
    }

    private void ApplyFilter()
    {
        if (Grid == null || FilterBox == null || Status == null) return;

        var q = FilterBox.Text.Trim();
        IEnumerable<Row> rows = _all;
        if (q.Length > 0)
        {
            rows = rows.Where(r =>
                r.RvaText.Contains(q, StringComparison.OrdinalIgnoreCase)
                || r.TargetApi.Contains(q, StringComparison.OrdinalIgnoreCase)
                || r.TargetModule.Contains(q, StringComparison.OrdinalIgnoreCase)
                || r.CallerHint.Contains(q, StringComparison.OrdinalIgnoreCase)
                || r.Disasm.Contains(q, StringComparison.OrdinalIgnoreCase));
        }

        var visible = rows.OrderBy(r => r.Source.CallRva).ToList();
        Grid.ItemsSource = visible;

        Status.Text = BuildStatusText(visible.Count);
    }

    /// <summary>
    /// Three states the user wants disambiguated:
    /// 1) callsites > 0 — show count + per-API breakdown.
    /// 2) callsites == 0 AND tracked imports == 0 — DLL doesn't import any
    ///    of the tracked loader APIs at all (most service DLLs). Suggest
    ///    trying a binary that explicitly does dynamic loading.
    /// 3) callsites == 0 AND tracked imports > 0 — imports exist but are
    ///    never reached via direct IAT call/jmp. Likely paths: delay-load,
    ///    GetProcAddress(LoadLibrary), or only referenced from non-executable
    ///    sections. Surface the tracked imports so the user can confirm.
    /// </summary>
    private string BuildStatusText(int visibleCount)
    {
        if (_all.Count > 0)
        {
            var byApi = _all.GroupBy(r => r.TargetApi).OrderByDescending(g => g.Count())
                .Select(g => $"{g.Key}={g.Count()}");
            return visibleCount == _all.Count
                ? $"{_all.Count} callsites · {string.Join(" ", byApi)}"
                : $"{visibleCount} of {_all.Count} callsites match · {string.Join(" ", byApi)}";
        }

        if (_trackedImports.Count == 0)
            return "0 callsites · no LoadLibrary*/LdrLoadDll/GetModuleHandle* in IAT — this PE doesn't directly import any loader API (try a binary that loads DLLs at runtime)";

        var importsLine = string.Join(" ", _trackedImports
            .OrderByDescending(kv => kv.Value)
            .Select(kv => $"{kv.Key}={kv.Value}"));
        return $"0 callsites · imports tracked: {importsLine} (no direct IAT calls — likely delay-load or GetProcAddress)";
    }

    private void Filter_Changed(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        if (Grid.ItemsSource is not IEnumerable<Row> rows) return;
        var sb = new StringBuilder();
        sb.AppendLine("RVA\tOp\tModule\tAPI\tCaller\tDisassembly");
        foreach (var r in rows)
            sb.AppendLine($"{r.RvaText}\t{r.Mnemonic}\t{r.TargetModule}\t{r.TargetApi}\t{r.CallerHint}\t{r.Disasm}");
        try
        {
            System.Windows.Clipboard.SetText(sb.ToString());
            Status.Text = "Copied to clipboard";
        }
        catch (Exception ex)
        {
            Status.Text = $"Copy failed: {ex.Message}";
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) { DialogResult = false; Close(); }

    private class Row
    {
        public Callsite Source { get; }
        public string RvaText => $"0x{Source.CallRva:X8}";
        public string Mnemonic => Source.Mnemonic;
        public string TargetModule => Source.TargetModule;
        public string TargetApi => Source.TargetApi;
        public string CallerHint => Source.CallerHint;
        public string Disasm => Source.Disasm;
        public Row(Callsite c) { Source = c; }
    }
}
