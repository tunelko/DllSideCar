namespace DllSidecar.Core.Models;

/// <summary>
/// One indirect call/jmp through the IAT to a dynamic-loading API. Produced
/// by <see cref="DllSidecar.Core.Services.CallsiteScanner"/>.
///
/// Adapted (for sideloading research) from SandboxEscaper's analyze_createfile.py
/// Patreon post: instead of CreateFile, we hunt LoadLibrary* / LdrLoadDll /
/// GetModuleHandle* — every callsite is a potential dynamic load that static
/// IAT analysis alone would miss the *context* of.
/// </summary>
public record Callsite(
    ulong CallRva,         // RVA of the call/jmp instruction
    string Mnemonic,       // "call" or "jmp"
    string TargetModule,   // e.g. "kernel32.dll"
    string TargetApi,      // e.g. "LoadLibraryExW"
    string CallerHint,     // nearest exported symbol + offset, or "<no export nearby>"
    string Disasm);        // formatted instruction (NASM syntax) for display

/// <summary>
/// Wraps a scan run so the caller can distinguish "no callsites because the
/// DLL doesn't import any of the tracked APIs" from "imports them but never
/// calls through the IAT" (delay-load, GetProcAddress, etc.).
/// <see cref="TrackedImports"/> is keyed by "module!api" (e.g. "kernel32.dll!LoadLibraryW").
/// </summary>
public record CallsiteScanResult(
    List<Callsite> Callsites,
    Dictionary<string, int> TrackedImports);
