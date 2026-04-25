namespace DllSidecar.Core.Helpers;

public static class KnownDlls
{
    private static readonly HashSet<string> Set = new(StringComparer.OrdinalIgnoreCase)
    {
        "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll",
        "gdi32.dll", "advapi32.dll", "shell32.dll", "ole32.dll",
        "oleaut32.dll", "msvcrt.dll", "rpcrt4.dll", "combase.dll",
        "sechost.dll", "bcryptprimitives.dll", "ws2_32.dll",
        "comdlg32.dll", "normaliz.dll", "imagehlp.dll", "psapi.dll",
        "setupapi.dll", "cfgmgr32.dll", "clbcatq.dll", "difxapi.dll",
        "iertutil.dll", "imm32.dll", "msctf.dll", "shcore.dll",
        "shlwapi.dll", "wldap32.dll", "wow64.dll", "wow64cpu.dll",
        "wow64win.dll", "crypt32.dll",
    };

    public static bool IsKnown(string dllName) => Set.Contains(dllName);
}
