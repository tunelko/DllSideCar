using System.Windows;
using System.Windows.Controls;
using DllSidecar.Core.Models.AdvisoryLibrary;

namespace DllSidecar.GUI.Views;

public partial class StatusPickerDialog : Window
{
    public AdvisoryStatus Selected { get; private set; }
    public string? NoteText { get; private set; }

    public StatusPickerDialog(AdvisoryStatus current)
    {
        InitializeComponent();
        Services.WindowChromeHelper.Apply(this, "Change status");
        Selected = current;
        for (int i = 0; i < StatusCombo.Items.Count; i++)
        {
            if (StatusCombo.Items[i] is ComboBoxItem it
                && it.Content is string s
                && Enum.TryParse<AdvisoryStatus>(s, out var st)
                && st == current)
            {
                StatusCombo.SelectedIndex = i;
                break;
            }
        }
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (StatusCombo.SelectedItem is ComboBoxItem it
            && it.Content is string s
            && Enum.TryParse<AdvisoryStatus>(s, out var st))
        {
            Selected = st;
        }
        NoteText = string.IsNullOrWhiteSpace(NoteBox.Text) ? null : NoteBox.Text.Trim();
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
