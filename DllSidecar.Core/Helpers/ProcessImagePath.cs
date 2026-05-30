using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DllSidecar.Core.Helpers;

/// <summary>Resolve the full disk path of a live process via Win32 QueryFullProcessImageName (cross-architecture).</summary>
public static class ProcessImagePath
{
    /// <summary>Full image path for the running PID, or null if gone / inaccessible.</summary>
    public static string? TryGet(int pid)
    {
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            uint cap = (uint)sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref cap) ? sb.ToString() : null;
        }
        finally { CloseHandle(h); }
    }

    /// <summary>First running process matching the basename (no ext) and its full path.</summary>
    public static string? TryGetByName(string processNameNoExt)
    {
        if (string.IsNullOrWhiteSpace(processNameNoExt)) return null;
        foreach (var p in Process.GetProcessesByName(processNameNoExt))
        {
            try
            {
                var full = TryGet(p.Id);
                if (!string.IsNullOrEmpty(full)) return full;
            }
            finally { p.Dispose(); }
        }
        return null;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);
}
