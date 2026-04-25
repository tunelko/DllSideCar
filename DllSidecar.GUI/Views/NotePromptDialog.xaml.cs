using System.Windows;

namespace DllSidecar.GUI.Views;

public partial class NotePromptDialog : Window
{
    public string? NoteText { get; private set; }

    public NotePromptDialog()
    {
        InitializeComponent();
        Services.WindowChromeHelper.Apply(this, "Add note");
        Loaded += (_, _) => NoteBox.Focus();
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        NoteText = NoteBox.Text?.Trim();
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
