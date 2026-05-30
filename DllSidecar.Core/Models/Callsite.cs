namespace DllSidecar.Core.Models;

/// <summary>One indirect call/jmp through the IAT to a dynamic-loading API.</summary>
public record Callsite(
    ulong CallRva,
    string Mnemonic,
    string TargetModule,
    string TargetApi,
    string CallerHint,
    string Disasm,
    string? LoadedName,    // null when first-arg was not a static literal
    uint? LoadFlags);      // LoadLibraryEx flags

/// <summary>Scan result; TrackedImports keyed by "module!api" (e.g. "kernel32.dll!LoadLibraryW").</summary>
public record CallsiteScanResult(
    List<Callsite> Callsites,
    Dictionary<string, int> TrackedImports);
