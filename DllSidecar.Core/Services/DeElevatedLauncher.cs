using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using DllSidecar.Core.Logging;

namespace DllSidecar.Core.Services;

/// <summary>
/// Launch at the shell's IL via explorer.exe's token + CreateProcessWithTokenW. Requires SeImpersonatePrivilege.
/// </summary>
public static class DeElevatedLauncher
{
    /// <summary>
    /// Launch at the shell's IL; null when no interactive shell. Throws <see cref="Win32Exception"/> on API failure.
    /// </summary>
    public static int? Launch(string exePath, string? arguments = null, string? workingDirectory = null)
    {
        var shellWnd = GetShellWindow();
        if (shellWnd == IntPtr.Zero)
        {
            Log.Warn("launcher", "No shell window — cannot de-elevate (kiosk/Session 0?)");
            return null;
        }

        GetWindowThreadProcessId(shellWnd, out uint shellPid);

        var hShellProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, shellPid);
        if (hShellProc == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess(explorer)");

        try
        {
            if (!OpenProcessToken(hShellProc, TOKEN_DUPLICATE, out IntPtr hShellToken))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken(explorer)");

            try
            {
                if (!DuplicateTokenEx(
                        hShellToken, TOKEN_ALL_ACCESS, IntPtr.Zero,
                        SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        TOKEN_TYPE.TokenPrimary, out IntPtr hPrimary))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx");

                try
                {
                    var si = new STARTUPINFO { cb = (uint)Marshal.SizeOf<STARTUPINFO>() };
                    var cmd = string.IsNullOrEmpty(arguments) ? $"\"{exePath}\"" : $"\"{exePath}\" {arguments}";
                    // CreateProcessWithTokenW may modify the buffer — use StringBuilder
                    var cmdBuffer = new System.Text.StringBuilder(cmd, cmd.Length + 1);
                    var cwd = workingDirectory ?? Path.GetDirectoryName(exePath) ?? "";

                    if (!CreateProcessWithTokenW(
                            hPrimary,
                            LOGON_WITH_PROFILE,
                            exePath, cmdBuffer,
                            CREATE_UNICODE_ENVIRONMENT,
                            IntPtr.Zero, cwd,
                            ref si, out PROCESS_INFORMATION pi))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessWithTokenW");

                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    Log.Info("launcher", $"De-elevated launch OK — PID {pi.dwProcessId} (shell PID {shellPid})");
                    return (int)pi.dwProcessId;
                }
                finally { CloseHandle(hPrimary); }
            }
            finally { CloseHandle(hShellToken); }
        }
        finally { CloseHandle(hShellProc); }
    }

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_ALL_ACCESS = 0x000F01FF;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint LOGON_WITH_PROFILE = 0x00000001;

    private enum SECURITY_IMPERSONATION_LEVEL
    { SecurityAnonymous, SecurityIdentification, SecurityImpersonation, SecurityDelegation }

    private enum TOKEN_TYPE { TokenPrimary = 1, TokenImpersonation = 2 }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public uint cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr GetShellWindow();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desired, bool inherit, uint pid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr hProc, uint desired, out IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExisting, uint desired, IntPtr attrs,
        SECURITY_IMPERSONATION_LEVEL level, TOKEN_TYPE type, out IntPtr hNew);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(
        IntPtr hToken, uint logonFlags,
        string? appName, System.Text.StringBuilder? cmdLine,
        uint creationFlags, IntPtr env, string? cwd,
        ref STARTUPINFO si, out PROCESS_INFORMATION pi);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);
}
