using System.IO;

namespace DllSidecar.GUI;

/// <summary>Resolves where bundled .h templates live and where generated PoCs go (dev vs installed).</summary>
internal static class AppPaths
{
    private static readonly Lazy<bool> _isInstalled = new(() =>
        File.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "templates", "dinvoke.h")));

    public static bool IsInstalledMode => _isInstalled.Value;

    public static string TemplatesDir => IsInstalledMode
        ? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "templates")
        : Path.Combine(DevSrcRoot, "templates");

    public static string OutputRoot => IsInstalledMode
        ? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DllSidecar", "output")
        : Path.Combine(DevSrcRoot, "output");

    private static string DevSrcRoot => Path.GetFullPath(
        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
}
