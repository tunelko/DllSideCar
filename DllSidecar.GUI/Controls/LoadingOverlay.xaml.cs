using System.Windows;

namespace DllSidecar.GUI.Controls;

public partial class LoadingOverlay : System.Windows.Controls.UserControl
{
    public LoadingOverlay()
    {
        InitializeComponent();
    }

    public void Show(string title, string? subtitle = null)
    {
        TitleText.Text = title;
        SubtitleText.Text = subtitle ?? "";
        SubtitleText.Visibility = string.IsNullOrEmpty(subtitle) ? Visibility.Collapsed : Visibility.Visible;
        Visibility = Visibility.Visible;
    }

    public void UpdateSubtitle(string subtitle)
    {
        SubtitleText.Text = subtitle;
        SubtitleText.Visibility = string.IsNullOrEmpty(subtitle) ? Visibility.Collapsed : Visibility.Visible;
    }

    public void Hide()
    {
        Visibility = Visibility.Collapsed;
    }
}
