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
    string Disasm,         // formatted instruction (NASM syntax) for display
    // Extracted by walking backward from the call. Both null when the args were
    // computed (built on the stack, GetProcAddress, register chain we don't
    // follow, etc.) — that's still useful info: "static-resolvable" callsites
    // are the actionable ones for sideloading.
    string? LoadedName,    // first-arg string, e.g. "amfrt64.dll" or "C:\\...\\foo.dll"
    uint? LoadFlags);      // LoadLibraryEx flags (LOAD_WITH_ALTERED_SEARCH_PATH, etc.)

/// <summary>
/// Wraps a scan run so the caller can distinguish "no callsites because the
/// DLL doesn't import any of the tracked APIs" from "imports them but never
/// calls through the IAT" (delay-load, GetProcAddress, etc.).
/// <see cref="TrackedImports"/> is keyed by "module!api" (e.g. "kernel32.dll!LoadLibraryW").
/// </summary>
public record CallsiteScanResult(
    List<Callsite> Callsites,
    Dictionary<string, int> TrackedImports);
