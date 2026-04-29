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
