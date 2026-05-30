using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views;

/// <summary>Modal to pick a Windows service for Watch-by-Name; exposes SCM key + image basename.</summary>
public partial class ServicePickerDialog : Window
{
    private List<ServiceRow> _all = [];

    public string? SelectedServiceName { get; private set; }
    public string? SelectedImageFile { get; private set; }
    /// <summary>Cmd-line substring filter ("-s ServiceName") used for shared-image hosts like svchost.</summary>
    public string? SelectedCmdLineFilter { get; private set; }

    public ServicePickerDialog()
    {
        InitializeComponent();
        Services.WindowChromeHelper.Apply(this, "Watch a service — pick from registered Windows services");
        Loaded += (_, _) => Load();
    }

    // ---------- Load ----------

    private void Load()
    {
        try
        {
            // Enumerate drivers so the checkbox toggle is instant (hidden by default).
            var infos = ServiceEnumerator.Enumerate(includeDrivers: true);
            _all = infos.Select(s => new ServiceRow(s)).ToList();
            ApplyFilter();
        }
        catch (Exception ex)
        {
            Status.Text = $"Failed to enumerate: {ex.GetType().Name}: {ex.Message}";
        }
    }

    // ---------- Filter ----------

    private void ApplyFilter()
    {
        if (Grid == null || FilterBox == null || Status == null) return;

        var q = FilterBox.Text.Trim();
        var localOnly = ChkLocalSystem.IsChecked == true;
        var runningOnly = ChkRunningOnly.IsChecked == true;
        var hideDrivers = ChkHideDrivers.IsChecked == true;

        bool Matches(ServiceRow r)
        {
            if (hideDrivers && r.Source.IsDriver) return false;
            if (localOnly && !ServiceEnumerator.IsLocalSystem(r.Source)) return false;
            if (runningOnly && r.Source.State != ServiceState.Running) return false;
            if (q.Length == 0) return true;
            return r.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
                || r.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase)
                || r.ImageFile.Contains(q, StringComparison.OrdinalIgnoreCase)
                || r.AccountText.Contains(q, StringComparison.OrdinalIgnoreCase);
        }

        var visible = _all.Where(Matches).OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList();
        Grid.ItemsSource = visible;
        Status.Text = $"{visible.Count} services · {_all.Count} total";
    }

    // ---------- Handlers ----------

    private void Filter_Changed(object sender, RoutedEventArgs e) => ApplyFilter();
    private void Filter_Changed(object sender, TextChangedEventArgs e) => ApplyFilter();
    private void Refresh_Click(object sender, RoutedEventArgs e) => Load();

    private void Grid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Grid.SelectedItem is ServiceRow r)
        {
            SelectedServiceName = r.Name;
            SelectedImageFile = r.ImageFile;
            // Shared-image hosts (svchost) need "-s ServiceName" to avoid adopting unrelated PIDs.
            SelectedCmdLineFilter = IsSharedHost(r.ImageFile)
                ? $"-s {r.Name}"
                : null;
            OkBtn.IsEnabled = !string.IsNullOrEmpty(r.ImageFile);
        }
        else
        {
            SelectedServiceName = null;
            SelectedImageFile = null;
            SelectedCmdLineFilter = null;
            OkBtn.IsEnabled = false;
        }
    }

    private static bool IsSharedHost(string imageFile) =>
        imageFile.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)
        || imageFile.Equals("dllhost.exe", StringComparison.OrdinalIgnoreCase)
        || imageFile.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase);

    private void Grid_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (Grid.SelectedItem is ServiceRow) Accept();
    }

    private void Ok_Click(object sender, RoutedEventArgs e) => Accept();
    private void Cancel_Click(object sender, RoutedEventArgs e) { DialogResult = false; Close(); }

    private void Accept()
    {
        if (Grid.SelectedItem is not ServiceRow r) return;
        if (string.IsNullOrEmpty(r.ImageFile)) return;
        DialogResult = true;
        Close();
    }

    // ---------- View row ----------

    private class ServiceRow
    {
        public ServiceInfo Source { get; }
        public string Name => Source.Name;
        public string DisplayName => Source.DisplayName;
        public string ImageFile => Source.ImageFile;
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
        public string StartText => Source.StartType switch
        {
            ServiceStartType.Boot => "Boot",
            ServiceStartType.System => "System",
            ServiceStartType.Auto => "Auto",
            ServiceStartType.Manual => "Manual",
            ServiceStartType.Disabled => "Disabled",
            _ => "—",
        };

        public ServiceRow(ServiceInfo s) { Source = s; }
    }
}
