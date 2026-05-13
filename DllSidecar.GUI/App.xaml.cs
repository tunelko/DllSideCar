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
            return;
        }

        // Runs once per install: wipes per-researcher state (advisories DB,
        // identity, NVD API key) when the install marker version differs
        // from the recorded last-launched version. Dev mode has no marker
        // so this is a no-op there.
        PostInstallReset.RunIfNeeded();
    }
}
