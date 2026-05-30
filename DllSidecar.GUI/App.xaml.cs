using System.Diagnostics;
using QuestPDF.Infrastructure;

namespace DllSidecar.GUI;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        // Elevation check FIRST: relaunch via runas and shut down before WPF starts.
        if (!Helpers.Elevation.IsElevated)
        {
            try
            {
                var exe = Process.GetCurrentProcess().MainModule?.FileName;
                if (exe != null)
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = exe,
                        Verb = "runas",
                        UseShellExecute = true,
                    });
                }
            }
            catch { }
            Shutdown();
            return;
        }

        // QuestPDF Community license must be set before any PDF generation call.
        QuestPDF.Settings.License = LicenseType.Community;

        // MUST run BEFORE base.OnStartup — once MainWindow opens library.db, File.Delete fails.
        PostInstallReset.RunIfNeeded();

        base.OnStartup(e);
    }
}
