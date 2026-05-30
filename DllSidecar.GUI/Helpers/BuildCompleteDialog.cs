using System.Diagnostics;
using System.IO;
using System.Windows;
using DllSidecar.GUI.Views;

namespace DllSidecar.GUI.Helpers;

/// <summary>Post-build confirmation modal with one-click Open-in-Explorer action.</summary>
public static class BuildCompleteDialog
{
    /// <summary>Show the success modal; opens the parent folder in Explorer on Yes.</summary>
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

    /// <summary>Launch Explorer with /select,&lt;path&gt;; falls back to plain folder open.</summary>
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
