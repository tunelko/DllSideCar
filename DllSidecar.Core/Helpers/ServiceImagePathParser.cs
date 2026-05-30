namespace DllSidecar.Core.Helpers;

/// <summary>Extract the binary path from a Windows service ImagePath registry value, handling quoted and unquoted forms.</summary>
public static class ServiceImagePathParser
{
    private static readonly string[] ExecutableExtensions =
    [
        ".exe", ".dll", ".com", ".bat", ".cmd", ".sys",
    ];

    /// <summary>Executable path portion of an ImagePath, without arguments or quotes; "" when empty.</summary>
    public static string ExtractPath(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return "";
        var s = imagePath.Trim();

        if (s.StartsWith('"'))
        {
            var end = s.IndexOf('"', 1);
            return end > 1 ? s[1..end] : s.Trim('"');
        }

        // Earliest extension boundary wins so arg-embedded paths (e.g. -DLL=C:\Foo\plugin.dll) don't capture.
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

        // No recognised extension: fall back to first-space split (covers driver \??\... entries).
        var sp = s.IndexOf(' ');
        return sp > 0 ? s[..sp] : s;
    }
}
