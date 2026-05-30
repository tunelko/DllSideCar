using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

/// <summary>Machine-wide service audit modal — pick a service, send its image/ServiceDll to AnalyzePage. Exposes <see cref="SelectedAnalyzePath"/> on accept.</summary>
public partial class ServiceAuditWindow : Window
{
    private List<ServiceRow> _all = [];

    public string? SelectedAnalyzePath { get; private set; }

    public ServiceAuditWindow()
    {
        InitializeComponent();
        Services.WindowChromeHelper.Apply(this, "SYSTEM service audit — pick a target binary to scan");
        Loaded += (_, _) => Load();
    }

    private void Load()
    {
        try
        {
            var infos = ServiceEnumerator.Enumerate(includeDrivers: true);
            _all = infos.Select(s => new ServiceRow(s)).ToList();
            ApplyFilter();
        }
        catch (Exception ex)
        {
            Status.Text = $"Failed to enumerate: {ex.GetType().Name}: {ex.Message}";
        }
    }

    private void ApplyFilter()
    {
        if (Grid == null || FilterBox == null || Status == null) return;

        var q = FilterBox.Text.Trim();
        var localOnly = ChkLocalSystem.IsChecked == true;
        var runningOnly = ChkRunningOnly.IsChecked == true;
        var hideDrivers = ChkHideDrivers.IsChecked == true;
        var svcDllOnly = ChkSvcDllOnly.IsChecked == true;

        bool Matches(ServiceRow r)
        {
            if (hideDrivers && r.Source.IsDriver) return false;
            if (localOnly && !ServiceEnumerator.IsLocalSystem(r.Source)) return false;
            if (runningOnly && r.Source.State != ServiceState.Running) return false;
            if (svcDllOnly && string.IsNullOrEmpty(r.Source.ServiceDll)) return false;
            if (q.Length == 0) return true;
            return r.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
                || r.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase)
                || r.ImageFile.Contains(q, StringComparison.OrdinalIgnoreCase)
                || r.ServiceDllFile.Contains(q, StringComparison.OrdinalIgnoreCase)
                || r.AccountText.Contains(q, StringComparison.OrdinalIgnoreCase);
        }

        var visible = _all.Where(Matches).OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList();
        Grid.ItemsSource = visible;
        var withDll = visible.Count(r => !string.IsNullOrEmpty(r.Source.ServiceDll));
        Status.Text = $"{visible.Count} services · {withDll} with ServiceDll · {_all.Count} total";
    }

    // ---------- Handlers ----------

    private void Filter_Changed(object sender, RoutedEventArgs e) => ApplyFilter();
    private void Filter_Changed(object sender, TextChangedEventArgs e) => ApplyFilter();
    private void Refresh_Click(object sender, RoutedEventArgs e) => Load();

    private void Grid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var r = Grid.SelectedItem as ServiceRow;
        AnalyzeImageBtn.IsEnabled = r != null
            && !string.IsNullOrEmpty(ResolveImagePath(r.Source));
        AnalyzeDllBtn.IsEnabled = r != null
            && !string.IsNullOrEmpty(r.Source.ServiceDll)
            && File.Exists(r.Source.ServiceDll);
    }

    private void Grid_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        // Double-click: ServiceDll if present, otherwise host image.
        if (Grid.SelectedItem is not ServiceRow r) return;
        if (!string.IsNullOrEmpty(r.Source.ServiceDll) && File.Exists(r.Source.ServiceDll))
            AcceptWith(r.Source.ServiceDll);
        else
        {
            var img = ResolveImagePath(r.Source);
            if (!string.IsNullOrEmpty(img)) AcceptWith(img);
        }
    }

    private void AnalyzeImage_Click(object sender, RoutedEventArgs e)
    {
        if (Grid.SelectedItem is not ServiceRow r) return;
        var img = ResolveImagePath(r.Source);
        if (!string.IsNullOrEmpty(img)) AcceptWith(img);
    }

    private void AnalyzeDll_Click(object sender, RoutedEventArgs e)
    {
        if (Grid.SelectedItem is not ServiceRow r) return;
        if (!string.IsNullOrEmpty(r.Source.ServiceDll) && File.Exists(r.Source.ServiceDll))
            AcceptWith(r.Source.ServiceDll);
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) { DialogResult = false; Close(); }

    private void AcceptWith(string path)
    {
        SelectedAnalyzePath = path;
        DialogResult = true;
        Close();
    }

    /// <summary>Strip args/quotes and expand env vars from a registry ImagePath.</summary>
    private static string ResolveImagePath(ServiceInfo s)
    {
        var p = Core.Helpers.ServiceImagePathParser.ExtractPath(s.ImagePath);
        if (string.IsNullOrEmpty(p)) return "";
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), p[12..]);
        try { p = Environment.ExpandEnvironmentVariables(p); } catch { }
        return File.Exists(p) ? p : "";
    }

    // ---------- View row ----------

    private class ServiceRow
    {
        public ServiceInfo Source { get; }
        public string Name => Source.Name;
        public string DisplayName => Source.DisplayName;
        public string ImageFile => Source.ImageFile;
        public string ServiceDllFile => string.IsNullOrEmpty(Source.ServiceDll) ? "" : Path.GetFileName(Source.ServiceDll);
        public string AccountText => string.IsNullOrEmpty(Source.Account) ? "LocalSystem" : Source.Account;
        public string StateText => Source.State switch
        {
            ServiceState.Running => "Running",
            ServiceState.Stopped => "Stopped",
            ServiceState.StartPending => "Starting",
            ServiceState.StopPending => "Stopping",
            ServiceState.Paused => "Paused",
            _ => "—",
        };

        public ServiceRow(ServiceInfo s) { Source = s; }
    }
}
