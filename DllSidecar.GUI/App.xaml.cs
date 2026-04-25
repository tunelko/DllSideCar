using System.Diagnostics;

namespace DllSidecar.GUI;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        base.OnStartup(e);

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
        }
    }
}
