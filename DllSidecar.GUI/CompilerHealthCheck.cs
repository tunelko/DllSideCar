using System.Diagnostics;
using System.Windows;
using DllSidecar.Core.Services;
using DllSidecar.GUI.Views;

namespace DllSidecar.GUI;

/// <summary>Probes for MinGW-w64 (gcc + windres) at startup and warns if missing.</summary>
internal static class CompilerHealthCheck
{
    private const string RepoUrl =
        "https://github.com/tunelko/DllSideCar/blob/main/src/README.md#compiler-setup-msys2--mingw";

    public static void WarnIfMissing(Window owner)
    {
        var gcc64 = BuildSystem.FindGcc("x64");
        var gcc32 = BuildSystem.FindGcc("x86");
        var windres = BuildSystem.FindWindres("x64") ?? BuildSystem.FindWindres("x86");

        if (gcc64 != null && gcc32 != null) return;

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("DllSidecar needs the MinGW-w64 toolchain (via MSYS2) to compile generated proof-of-concept DLLs. The following components were not found on your system:");
        sb.AppendLine();
        if (gcc64 == null) sb.AppendLine("  • MinGW gcc (x64) — package: mingw-w64-x86_64-gcc");
        if (gcc32 == null) sb.AppendLine("  • MinGW gcc (x86) — package: mingw-w64-i686-gcc");
        if (windres == null) sb.AppendLine("  • windres (resource compiler) — bundled with the gcc packages above");
        sb.AppendLine();
        sb.AppendLine("Quick setup once MSYS2 is installed:");
        sb.AppendLine("    pacman -S mingw-w64-x86_64-gcc mingw-w64-i686-gcc");
        sb.AppendLine();
        sb.AppendLine("Analysis features (Analyze, Scan, ETW Runtime Trace, Advisories) work without a compiler — only code generation + build steps are blocked.");
        sb.AppendLine();
        sb.AppendLine("Open the full setup instructions in your browser now?");

        var result = AppDialog.Show(
            owner,
            sb.ToString(),
            "Compiler toolchain not detected",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.Yes);

        if (result == MessageBoxResult.Yes)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = RepoUrl,
                    UseShellExecute = true,
                });
            }
            catch (System.ComponentModel.Win32Exception)
            {
                AppDialog.Show(owner,
                    $"Open this URL manually:\n\n{RepoUrl}",
                    "DllSidecar",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
        }
    }
}
