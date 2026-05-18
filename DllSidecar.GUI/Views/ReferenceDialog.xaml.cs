using System.Windows;

namespace DllSidecar.GUI.Views;

public partial class ReferenceDialog : Window
{
    public ReferenceDialog()
    {
        InitializeComponent();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
