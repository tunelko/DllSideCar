using System.Reflection;
using System.Windows;
using System.Windows.Navigation;

namespace DllSidecar.GUI.Views;

public partial class AboutDialog : Window
{
    public AboutDialog()
    {
        InitializeComponent();
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        VersionText.Text = v != null ? $"v{v.Major}.{v.Minor}.{v.Build}" : "v?";
    }

    private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Helpers.SafeUrl.Open(e.Uri.ToString());
        e.Handled = true;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
