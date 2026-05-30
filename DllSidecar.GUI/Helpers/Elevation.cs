using System.Diagnostics;
using System.Security.Principal;
using DllSidecar.Core.Logging;

namespace DllSidecar.GUI.Helpers;

/// <summary>Elevation helpers; some detectors return partial results without admin.</summary>
public static class Elevation
{
    private static readonly Lazy<bool> _isElevated = new(ComputeElevated);
    public static bool IsElevated => _isElevated.Value;

    private static bool ComputeElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            var p = new WindowsPrincipal(id);
            return p.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex)
        {
            Log.Warn("elevation", "Could not determine elevation", ex);
            return false;
        }
    }

    /// <summary>Relaunch via "runas" verb and exit; returns false on UAC cancel or failure.</summary>
    public static bool RelaunchElevated()
    {
        try
        {
            var exePath = Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(exePath)) return false;

            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,   // required for Verb="runas"
                Verb = "runas",
                WorkingDirectory = System.IO.Path.GetDirectoryName(exePath) ?? "",
            };
            Process.Start(psi);
            System.Windows.Application.Current.Shutdown();
            return true;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // User cancelled the UAC prompt
            Log.Info("elevation", "User cancelled UAC elevation");
            return false;
        }
        catch (Exception ex)
        {
            Log.Error("elevation", "Relaunch as admin failed", ex);
            return false;
        }
    }
}
