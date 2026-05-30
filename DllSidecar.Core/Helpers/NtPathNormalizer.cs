using System.Runtime.InteropServices;
using System.Text;

namespace DllSidecar.Core.Helpers;

/// <summary>Translates kernel device paths (\Device\HarddiskVolumeN\...) to drive-letter form (C:\...).</summary>
public static class NtPathNormalizer
{
    private static readonly Lazy<Dictionary<string, string>> _devToLetter = new(BuildMap);

    public static string Normalize(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;
        if (!path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) return path;

        var map = _devToLetter.Value;
        foreach (var kv in map)
        {
            if (path.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase))
            {
                var tail = path.Substring(kv.Key.Length);
                if (tail.Length > 0 && tail[0] != '\\') tail = "\\" + tail;
                return kv.Value + tail;
            }
        }
        return path;
    }

    private static Dictionary<string, string> BuildMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var sb = new StringBuilder(260);
        for (char c = 'A'; c <= 'Z'; c++)
        {
            sb.Clear();
            sb.EnsureCapacity(260);
            var letter = c + ":";
            uint n = QueryDosDevice(letter, sb, 260);
            if (n == 0) continue;
            var target = sb.ToString();
            if (string.IsNullOrEmpty(target)) continue;
            map[target] = letter;
        }
        return map;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);
}
