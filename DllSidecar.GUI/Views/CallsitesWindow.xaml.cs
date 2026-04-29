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
            var sites = CallsiteScanner.Scan(_pePath);
            _all = sites.Select(s => new Row(s)).ToList();
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

        // Per-API counts surface which loader API is called most — useful triage
        // signal (lots of LoadLibraryW callsites = high dynamic-load surface).
        var byApi = _all.GroupBy(r => r.TargetApi).OrderByDescending(g => g.Count())
            .Select(g => $"{g.Key}={g.Count()}");
        Status.Text = visible.Count == _all.Count
            ? $"{_all.Count} callsites · {string.Join(" ", byApi)}"
            : $"{visible.Count} of {_all.Count} callsites match · {string.Join(" ", byApi)}";
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
