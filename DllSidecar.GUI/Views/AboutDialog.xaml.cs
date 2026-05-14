using System;
using System.Reflection;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Navigation;
using DllSidecar.Core.Configuration;

namespace DllSidecar.GUI.Views;

public partial class AboutDialog : Window
{
    public AboutDialog()
    {
        InitializeComponent();
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        VersionText.Text = v != null ? $"v{v.Major}.{v.Minor}.{v.Build}" : "v?";

        // Researcher fields hydrate from ConfigManager so the dialog reflects
        // whoever configured the local install — never the project maintainer.
        // Empty fields collapse their row entirely so a fresh install shows a
        // clean "Version / Repo / License" trio instead of placeholder strings.
        var r = ConfigManager.Current.Researcher;
        var name   = (r.Name   ?? "").Trim();
        var handle = (r.Handle ?? "").Trim();
        var blog   = (r.Blog   ?? "").Trim();

        if (name.Length > 0 || handle.Length > 0)
        {
            AuthorText.Text = name.Length > 0 && handle.Length > 0
                ? $"{name} ({handle})"
                : (name.Length > 0 ? name : handle);
        }
        else
        {
            AuthorLabel.Visibility = Visibility.Collapsed;
            AuthorText.Visibility = Visibility.Collapsed;
        }

        if (blog.Length > 0)
        {
            // Coerce blog into a valid absolute URI — silently drop the row when
            // the configured value can't be turned into one rather than crashing
            // the dialog at construction time.
            if (!blog.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                && !blog.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                blog = "https://" + blog;
            if (Uri.TryCreate(blog, UriKind.Absolute, out var uri))
            {
                var display = uri.Host + (uri.AbsolutePath.Length > 1 ? uri.AbsolutePath : "");
                var run = new Run(display)
                {
                    FontFamily = (System.Windows.Media.FontFamily)FindResource("FontMono"),
                    FontSize = 11,
                };
                var link = new Hyperlink(run)
                {
                    NavigateUri = uri,
                    Foreground = (System.Windows.Media.Brush)FindResource("Mauve"),
                };
                link.RequestNavigate += Hyperlink_RequestNavigate;
                BlogContainer.Inlines.Add(link);
            }
            else
            {
                BlogLabel.Visibility = Visibility.Collapsed;
                BlogContainer.Visibility = Visibility.Collapsed;
            }
        }
        else
        {
            BlogLabel.Visibility = Visibility.Collapsed;
            BlogContainer.Visibility = Visibility.Collapsed;
        }
    }

    private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Helpers.SafeUrl.Open(e.Uri.ToString());
        e.Handled = true;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
