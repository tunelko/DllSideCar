using System.Runtime.InteropServices;
using System.Windows;

// CA5392 — restrict DLL search to System32 for every P/Invoke in this assembly.
// All native imports target Windows system DLLs (kernel32, user32, advapi32,
// wintrust, ntdll, shell32), so System32 alone is sufficient. Closes the
// planted-DLL-in-CWD attack surface (which is exactly the class of vuln this
// tool researches in third-party software).
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

[assembly:ThemeInfo(
    ResourceDictionaryLocation.None,            //where theme specific resource dictionaries are located
                                                //(used if a resource is not found in the page,
                                                // or application resource dictionaries)
    ResourceDictionaryLocation.SourceAssembly   //where the generic resource dictionary is located
                                                //(used if a resource is not found in the page,
                                                // app, or any theme specific resource dictionaries)
)]
