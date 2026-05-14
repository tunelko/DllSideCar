using System.Diagnostics;
using System.IO;
using System.Windows;
using DllSidecar.GUI.Views;

namespace DllSidecar.GUI.Helpers;

/// <summary>
/// Post-build confirmation modal. Surfaces the on-disk location of the compiled
/// PoC so the researcher doesn't have to scroll the log to find it, with a
/// one-click Open-in-Explorer action. Used by BuildPage (standalone compile) and
/// GeneratePage (one-click generate-and-build) so both code paths land on the
/// same UX.
/// </summary>
public static class BuildCompleteDialog
{
    /// <summary>
    /// Show the success modal. <paramref name="outputDllPath"/> is the full path
    /// to the compiled DLL; the dialog displays the parent directory as the
    /// thing the user will navigate to. On <c>Yes</c> the parent folder opens
    /// in Explorer (selecting the DLL itself when possible via <c>/select,</c>).
    /// </summary>
    public static void Show(Window? owner, string outputDllPath)
    {
        if (string.IsNullOrWhiteSpace(outputDllPath)) return;

        var folder = Path.GetDirectoryName(outputDllPath) ?? "";
        var size = SafeFileSize(outputDllPath);
        var body = $"PoC compiled successfully.\n\n" +
                   $"Output:\n{outputDllPath}\n\n" +
                   (size > 0 ? $"Size: {size:N0} bytes\n\n" : "") +
                   $"Open the output folder?";

        var result = AppDialog.Show(
            owner,
            body,
            "Build complete",
            MessageBoxButton.YesNo,
            MessageBoxImage.Information,
            MessageBoxResult.Yes);

        if (result == MessageBoxResult.Yes) OpenInExplorer(outputDllPath, folder);
    }

    private static long SafeFileSize(string path)
    {
        try { return File.Exists(path) ? new FileInfo(path).Length : 0; }
        catch (IOException) { return 0; }
        catch (UnauthorizedAccessException) { return 0; }
    }

    /// <summary>
    /// Launch Explorer with /select,&lt;path&gt; so the DLL is highlighted inside the
    /// folder. Falls back to plain folder open when /select fails (path with
    /// special chars, network share, etc.).
    /// </summary>
    private static void OpenInExplorer(string dllPath, string folder)
    {
        try
        {
            if (File.Exists(dllPath))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    UseShellExecute = false,
                };
                psi.ArgumentList.Add("/select,");
                psi.ArgumentList.Add(dllPath);
                Process.Start(psi);
                return;
            }
        }
        catch (System.ComponentModel.Win32Exception) { /* fall through */ }

        if (!Directory.Exists(folder)) return;
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = folder,
                UseShellExecute = true,
            });
        }
        catch (System.ComponentModel.Win32Exception) { /* nothing to do */ }
    }
}
