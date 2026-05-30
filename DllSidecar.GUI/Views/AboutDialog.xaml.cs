using System;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Navigation;
using DllSidecar.Core;
using DllSidecar.Core.Configuration;

namespace DllSidecar.GUI.Views;

public partial class AboutDialog : Window
{
    public AboutDialog()
    {
        InitializeComponent();
        VersionText.Text = AppInfo.VersionDisplay;

        // Researcher fields come from ConfigManager; empty fields collapse their row.
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
            // Coerce to absolute URI; drop the row silently on failure.
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
