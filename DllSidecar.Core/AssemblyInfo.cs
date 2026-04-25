using System.Runtime.InteropServices;

// CA5392 — restrict DLL search to System32 for every P/Invoke in this assembly.
// All native imports target Windows system DLLs (kernel32, user32, advapi32,
// wintrust, ntdll, shell32), so System32 alone is sufficient. Closes the
// planted-DLL-in-CWD attack surface (which is exactly the class of vuln this
// tool researches in third-party software).
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
