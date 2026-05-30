using System.Runtime.InteropServices;
using System.Windows;

// CA5392 — restrict DLL search to System32 for every P/Invoke (kernel32, user32, advapi32, wintrust, ntdll, shell32).
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

[assembly:ThemeInfo(
    ResourceDictionaryLocation.None,            //where theme specific resource dictionaries are located
                                                //(used if a resource is not found in the page,
                                                // or application resource dictionaries)
    ResourceDictionaryLocation.SourceAssembly   //where the generic resource dictionary is located
                                                //(used if a resource is not found in the page,
                                                // app, or any theme specific resource dictionaries)
)]
