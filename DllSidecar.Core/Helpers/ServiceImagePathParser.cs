namespace DllSidecar.Core.Helpers;

/// <summary>
/// Extract the binary path from a Windows service ImagePath registry value.
///
/// The challenge is that ImagePath is loosely formatted: many services properly quote
/// the executable when the path contains spaces, but a non-trivial number of legacy
/// services, in-house tools, and self-installed binaries register an unquoted path with
/// space-separated arguments after it. A naive "split at first space" parser truncates
/// <c>C:\Program Files\Vendor\svc.exe -k group</c> to <c>C:\Program</c>, silently
/// breaking the audit (File.Exists returns false, the service drops out of the report).
///
/// This helper handles both shapes:
///   1. Quoted: take everything between the first pair of <c>"</c>.
///   2. Unquoted: scan for an executable extension (.exe / .dll / .com / .bat / .cmd
///      / .sys) that is followed by whitespace or end-of-string — that's the actual
///      path terminator. The earliest such boundary wins so we don't accidentally
///      capture an argument that looks like another binary path.
///
/// Falls back to the first-space split when no recognized extension is present (kernel
/// driver entries that come through as <c>\??\C:\Foo\driver.sys</c> never carry args,
/// so the fallback is harmless there).
/// </summary>
public static class ServiceImagePathParser
{
    private static readonly string[] ExecutableExtensions =
    [
        ".exe", ".dll", ".com", ".bat", ".cmd", ".sys",
    ];

    /// <summary>
    /// Return the executable path portion of an ImagePath value, without arguments and
    /// without surrounding quotes. Empty input returns empty string.
    /// </summary>
    public static string ExtractPath(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return "";
        var s = imagePath.Trim();

        if (s.StartsWith('"'))
        {
            var end = s.IndexOf('"', 1);
            return end > 1 ? s[1..end] : s.Trim('"');
        }

        // Find the earliest executable-extension boundary in the string. We don't pick
        // the longest match because a service's argument list can contain other paths
        // (e.g. -DLL=C:\Foo\plugin.dll) that would otherwise win and produce a longer
        // but wrong "path".
        var bestEnd = -1;
        foreach (var ext in ExecutableExtensions)
        {
            var idx = s.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
            while (idx >= 0)
            {
                var end = idx + ext.Length;
                if (end == s.Length || char.IsWhiteSpace(s[end]))
                {
                    if (bestEnd < 0 || end < bestEnd) bestEnd = end;
                    break;
                }
                idx = s.IndexOf(ext, end, StringComparison.OrdinalIgnoreCase);
            }
        }

        if (bestEnd > 0) return s[..bestEnd];

        // No recognised extension — preserve the legacy behaviour so kernel/driver paths
        // and other non-PE service registrations keep working.
        var sp = s.IndexOf(' ');
        return sp > 0 ? s[..sp] : s;
    }
}
