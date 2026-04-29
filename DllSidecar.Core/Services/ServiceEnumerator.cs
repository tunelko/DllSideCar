using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace DllSidecar.Core.Services;

public enum ServiceState { Unknown, Stopped, StartPending, StopPending, Running, ContinuePending, PausePending, Paused }

public enum ServiceStartType { Unknown, Boot, System, Auto, Manual, Disabled }

public record ServiceInfo(
    string Name,
    string DisplayName,
    string ImagePath,      // raw ImagePath value (may include args, env vars, leading quotes)
    string ImageFile,      // resolved image basename without args, e.g. "splunkd.exe"
    string Account,        // ObjectName ("" → LocalSystem)
    ServiceState State,
    ServiceStartType StartType,
    bool IsDriver);

/// <summary>
/// Enumerates Windows services by walking HKLM\SYSTEM\CurrentControlSet\Services
/// and overlaying live state from the SCM (EnumServicesStatusW). Used to populate
/// the Service Picker dialog and (later) the SYSTEM-service DLL audit scan.
/// </summary>
public static class ServiceEnumerator
{
    public static List<ServiceInfo> Enumerate(bool includeDrivers = false)
    {
        var stateByName = QueryAllStates();
        var result = new List<ServiceInfo>(512);

        using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (root == null) return result;

        foreach (var name in root.GetSubKeyNames())
        {
            using var key = root.OpenSubKey(name);
            if (key == null) continue;

            var typeRaw = (key.GetValue("Type") as int?) ?? 0;
            var isDriver = (typeRaw & 0x1) != 0 || (typeRaw & 0x2) != 0; // KERNEL_DRIVER | FILE_SYSTEM_DRIVER
            var isWin32 = (typeRaw & 0x10) != 0 || (typeRaw & 0x20) != 0; // OWN_PROCESS | SHARE_PROCESS
            if (!isWin32 && !isDriver) continue;
            if (isDriver && !includeDrivers) continue;

            var imagePath = (key.GetValue("ImagePath", null,
                                          RegistryValueOptions.DoNotExpandEnvironmentNames) as string) ?? "";
            var displayName = ResolveDisplayName(key, name);
            var account = (key.GetValue("ObjectName") as string) ?? "";
            var startRaw = (key.GetValue("Start") as int?) ?? 3;

            stateByName.TryGetValue(name, out var state);
            result.Add(new ServiceInfo(
                Name: name,
                DisplayName: displayName,
                ImagePath: imagePath,
                ImageFile: ExtractImageFile(imagePath),
                Account: account,
                State: state,
                StartType: MapStartType(startRaw),
                IsDriver: isDriver));
        }

        return result;
    }

    /// <summary>
    /// True when the service runs as LocalSystem (the empty/null ObjectName default,
    /// or an explicit "LocalSystem"). NetworkService and LocalService are excluded.
    /// </summary>
    public static bool IsLocalSystem(ServiceInfo s) =>
        string.IsNullOrEmpty(s.Account)
        || s.Account.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// DisplayName is sometimes a "@dll,-resId" indirect string. We strip those
    /// because they don't expand without LoadIndirectString and the friendly
    /// fallback is just the service name.
    /// </summary>
    private static string ResolveDisplayName(RegistryKey key, string serviceName)
    {
        var dn = (key.GetValue("DisplayName") as string) ?? "";
        if (dn.StartsWith("@", StringComparison.Ordinal)) return serviceName;
        return string.IsNullOrEmpty(dn) ? serviceName : dn;
    }

    /// <summary>
    /// ImagePath may be: '"C:\foo\bar.exe" -k arg', 'C:\foo\bar.exe -k arg',
    /// '\??\C:\foo\bar.sys', '%SystemRoot%\System32\svchost.exe -k netsvcs'.
    /// Returns just the filename of the executable, no args, no env-var
    /// expansion.
    /// </summary>
    private static string ExtractImageFile(string imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return "";
        var s = imagePath.Trim();

        if (s.StartsWith('"'))
        {
            var end = s.IndexOf('"', 1);
            if (end > 1) s = s[1..end];
        }
        else
        {
            var sp = s.IndexOf(' ');
            if (sp > 0) s = s[..sp];
        }

        // Strip NT prefixes (driver paths) and any directory components.
        if (s.StartsWith(@"\??\", StringComparison.Ordinal)) s = s[4..];
        if (s.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) s = s[12..];

        try { return Path.GetFileName(s); } catch { return s; }
    }

    private static ServiceStartType MapStartType(int v) => v switch
    {
        0 => ServiceStartType.Boot,
        1 => ServiceStartType.System,
        2 => ServiceStartType.Auto,
        3 => ServiceStartType.Manual,
        4 => ServiceStartType.Disabled,
        _ => ServiceStartType.Unknown,
    };

    // ---------- SCM enumeration for live state ----------

    /// <summary>
    /// Single SCM call returns the current state of every Win32 + driver service.
    /// Errors fail soft with an empty map — the picker still works without state.
    /// </summary>
    private static Dictionary<string, ServiceState> QueryAllStates()
    {
        var map = new Dictionary<string, ServiceState>(StringComparer.OrdinalIgnoreCase);
        var hScm = OpenSCManagerW(null, null, SC_MANAGER_ENUMERATE_SERVICE);
        if (hScm == IntPtr.Zero) return map;
        try
        {
            uint resumeHandle = 0;
            // First call to size the buffer.
            EnumServicesStatusW(hScm, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,
                IntPtr.Zero, 0, out var bytesNeeded, out _, ref resumeHandle);
            if (bytesNeeded == 0) return map;

            var buf = Marshal.AllocHGlobal((int)bytesNeeded);
            try
            {
                resumeHandle = 0;
                var size = bytesNeeded;
                while (true)
                {
                    var ok = EnumServicesStatusW(hScm, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,
                        buf, size, out bytesNeeded, out var returned, ref resumeHandle);
                    var entrySize = Marshal.SizeOf<ENUM_SERVICE_STATUS>();
                    for (int i = 0; i < returned; i++)
                    {
                        var entry = Marshal.PtrToStructure<ENUM_SERVICE_STATUS>(
                            IntPtr.Add(buf, i * entrySize));
                        var name = Marshal.PtrToStringUni(entry.lpServiceName) ?? "";
                        if (name.Length > 0)
                            map[name] = MapState(entry.ServiceStatus.dwCurrentState);
                    }
                    if (ok || resumeHandle == 0) break;
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        finally { CloseServiceHandle(hScm); }
        return map;
    }

    private static ServiceState MapState(uint v) => v switch
    {
        1 => ServiceState.Stopped,
        2 => ServiceState.StartPending,
        3 => ServiceState.StopPending,
        4 => ServiceState.Running,
        5 => ServiceState.ContinuePending,
        6 => ServiceState.PausePending,
        7 => ServiceState.Paused,
        _ => ServiceState.Unknown,
    };

    private const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
    private const uint SERVICE_TYPE_ALL = 0x0000003F;
    private const uint SERVICE_STATE_ALL = 0x00000003;

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ENUM_SERVICE_STATUS
    {
        public IntPtr lpServiceName;
        public IntPtr lpDisplayName;
        public SERVICE_STATUS ServiceStatus;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "EnumServicesStatusW")]
    private static extern bool EnumServicesStatusW(
        IntPtr hSCManager,
        uint dwServiceType,
        uint dwServiceState,
        IntPtr lpServices,
        uint cbBufSize,
        out uint pcbBytesNeeded,
        out uint lpServicesReturned,
        ref uint lpResumeHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);
}
