using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DllSidecar.Core.Helpers;

/// <summary>
/// Resolve the full disk path of a live process via Win32 `QueryFullProcessImageName`.
/// This works cross-architecture (an x64 host can read the path of an x86 process and
/// vice versa) — `Process.MainModule.FileName` throws Win32Exception "A 32 bit process
/// cannot access modules of a 64 bit process" (and the other direction) on Windows
/// 11 when a managed app runs at the opposite bitness from its target. ETW captures
/// the kernel device path in `ProcessTraceData.ImageFileName` which TraceEvent
/// normalises imperfectly; using the Win32 user-mode call instead gives us the
/// canonical drive-letter path every time the process is still alive.
/// </summary>
public static class ProcessImagePath
{
    /// <summary>Returns the full image path for the running PID, or null if the
    /// process is gone / inaccessible.</summary>
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

    /// <summary>Find a running process by image basename (without extension) and
    /// return its full path. Returns the first match — caller should disambiguate
    /// if multiple instances are running.</summary>
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
