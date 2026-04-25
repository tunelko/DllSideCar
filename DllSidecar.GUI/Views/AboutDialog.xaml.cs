using System.Reflection;
using System.Windows;
using System.Windows.Input;
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

    // With WindowStyle=None there is no title bar to drag from. Mounting the
    // handler on the info card (instead of the root) keeps the logo area free
    // for hover/right-click later, and only the visible card surface acts as a
    // drag handle, which feels right.
    private void Card_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left) DragMove();
    }
}
