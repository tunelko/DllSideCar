using System.Windows;
using System.Windows.Controls;
using DllSidecar.Core.Configuration;

namespace DllSidecar.GUI.Views;

/// <summary>First-run landing page. Either button marks WelcomeSeen.</summary>
public partial class WelcomePage : Page
{
    private readonly MainWindow _main;

    public WelcomePage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
    }

    private void OpenConfig_Click(object sender, RoutedEventArgs e)
    {
        MarkSeen();
        _main.NavigateTo(new ConfigPage(_main));
    }

    private void Skip_Click(object sender, RoutedEventArgs e)
    {
        MarkSeen();
        _main.NavigateTo(new Wizard.WizardPage(_main));
    }

    private static void MarkSeen()
    {
        ConfigManager.Current.WelcomeSeen = true;
        ConfigManager.Save();
    }
}
