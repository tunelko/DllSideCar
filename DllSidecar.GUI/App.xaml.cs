using System.Diagnostics;

namespace DllSidecar.GUI;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        // Elevation check FIRST. If we're not elevated we relaunch via runas
        // and shut this instance down before WPF does anything else.
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
        //
        // MUST run BEFORE base.OnStartup — WPF processes StartupUri inside
        // base.OnStartup, which constructs MainWindow, which opens
        // library.db via SqliteConnection. Once the SQLite connection holds
        // the file, File.Delete throws IOException and the swallowed catch
        // silently keeps the old DB. Order matters here.
        PostInstallReset.RunIfNeeded();

        base.OnStartup(e);
    }
}
