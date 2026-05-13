using System.IO;

namespace DllSidecar.GUI;

/// <summary>
/// Resolves where the bundled .h templates live and where generated PoCs go.
/// Dev and installed mode have very different on-disk layouts:
///
///   Dev   : exe at src/DllSidecar.GUI/bin/{Debug|Release}/net9.0-windows/
///           templates at src/templates/, output at src/output/  (four dirs up)
///
///   Inst. : exe at {app}\DllSidecar.exe  (e.g. C:\Program Files\DllSidecar\)
///           templates at {app}\templates\  (bundled by setup.iss)
///           output at %LOCALAPPDATA%\DllSidecar\output\  (writable, no admin)
///
/// Walking four parents from C:\Program Files\DllSidecar\ ends at C:\, so the
/// old `ProjectRoot = ..\..\..\..` pattern produced C:\templates and
/// C:\output — neither writable nor existing. Detection here is the presence
/// of templates\dinvoke.h next to the exe (bundled in installed builds; in
/// dev that path naturally misses because dev exes live nested under bin/).
/// </summary>
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
