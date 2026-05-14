using System.Diagnostics;
using System.Windows;
using DllSidecar.Core.Services;
using DllSidecar.GUI.Views;

namespace DllSidecar.GUI;

/// <summary>
/// Probes the host for MinGW-w64 (gcc + windres) at startup. When the
/// compilers are missing, surfaces a modal warning that tells the
/// researcher exactly which toolchain is missing and offers a one-click
/// shortcut to the build-prerequisites section of the project README.
///
/// Rationale: the application's compile flow (GeneratePage / BuildPage /
/// AutoBuild) silently fails when gcc is not on the system. Without an
/// upfront check the user discovers the missing toolchain at the worst
/// possible moment — after spending time on PE analysis, payload picks,
/// and evasion configuration. This check fires once per session, never
/// blocks startup, and goes away automatically the moment a working
/// MSYS2/MinGW install is found on PATH.
///
/// Design choices:
///   · Warns about x64 AND x86 — both architectures are first-class
///     code-gen targets; missing either is a defect the researcher
///     should know about up-front.
///   · No persistent "skip" flag. The warning only surfaces when the
///     toolchain is genuinely missing; installing MSYS2 resolves it.
///   · Runs on the UI thread via Dispatcher because BuildSystem.FindGcc
///     does cheap File.Exists probes — no async overhead needed here.
/// </summary>
internal static class CompilerHealthCheck
{
    private const string RepoUrl =
        "https://github.com/tunelko/DllSideCar/blob/main/src/README.md#compiler-setup-msys2--mingw";

    public static void WarnIfMissing(Window owner)
    {
        var gcc64 = BuildSystem.FindGcc("x64");
        var gcc32 = BuildSystem.FindGcc("x86");
        var windres = BuildSystem.FindWindres("x64") ?? BuildSystem.FindWindres("x86");

        // Nothing to warn about — both compilers resolved.
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
                // Browser refused to launch — degrade to a copy-paste hint.
                AppDialog.Show(owner,
                    $"Open this URL manually:\n\n{RepoUrl}",
                    "DllSidecar",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
        }
    }
}
