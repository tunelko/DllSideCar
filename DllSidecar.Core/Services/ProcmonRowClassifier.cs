using DllSidecar.Core.Helpers;

namespace DllSidecar.Core.Services;

/// <summary>
/// Tristate classification of a DLL surfaced by a ProcMon NAME-NOT-FOUND row,
/// used by ProcmonPage to drive the Mode column + the Promote action.
///
///   · <see cref="KnownDll"/>   — listed in the Windows KnownDLLs registry key
///                                 (we ship a hardcoded subset via
///                                 <see cref="KnownDlls"/>). These ALWAYS load
///                                 from %SystemRoot%\System32 regardless of the
///                                 caller's search path, so classic sideload
///                                 cannot intercept them. Useful to filter out.
///   · <see cref="Resolvable"/> — a canonical copy exists in System32 (x64) or
///                                 SysWOW64 (x86). Most likely Proxy-capable
///                                 because system DLLs almost always export
///                                 functions; the exact export count is
///                                 verified at Promote time by running the
///                                 canonical through PeAnalyzer.
///   · <see cref="Phantom"/>     — no canonical copy anywhere on disk. Only the
///                                 Sideload mode applies (DllMain-only payload,
///                                 no forwards). This is the most common case
///                                 for application-private DLLs that simply
///                                 don't exist.
/// </summary>
public enum ProcmonRowMode
{
    KnownDll,
    Resolvable,
    Phantom,
}

public record ProcmonRowClassification(ProcmonRowMode Mode, string? CanonicalPath);

public static class ProcmonRowClassifier
{
    // Resolved once at type init — the System / SystemX86 folders never change at
    // runtime on a normal Windows session, so caching avoids the SHGetFolderPath
    // round-trip per row when the user parses a 5000-row CSV.
    private static readonly string System32Dir =
        Environment.GetFolderPath(Environment.SpecialFolder.System);

    // On 64-bit Windows, SpecialFolder.SystemX86 → C:\Windows\SysWOW64. On x86-
    // only hosts it falls back to System32, which is harmless: File.Exists on
    // the same path twice just makes the call a no-op.
    private static readonly string SysWOW64Dir =
        Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);

    /// <summary>
    /// Cheap classification — KnownDlls table lookup + two File.Exists probes.
    /// Returns the canonical path when found so the caller doesn't have to
    /// re-derive it. Skipped on the hot path during Parse so a 1000-row CSV
    /// classifies in under a second; expensive PE analysis is deferred to the
    /// Promote action.
    /// </summary>
    public static ProcmonRowClassification Classify(string dllName)
    {
        if (string.IsNullOrWhiteSpace(dllName))
            return new(ProcmonRowMode.Phantom, null);

        if (KnownDlls.IsKnown(dllName))
            return new(ProcmonRowMode.KnownDll, null);

        var p64 = Path.Combine(System32Dir, dllName);
        if (File.Exists(p64)) return new(ProcmonRowMode.Resolvable, p64);

        if (!string.Equals(System32Dir, SysWOW64Dir, StringComparison.OrdinalIgnoreCase))
        {
            var p32 = Path.Combine(SysWOW64Dir, dllName);
            if (File.Exists(p32)) return new(ProcmonRowMode.Resolvable, p32);
        }

        return new(ProcmonRowMode.Phantom, null);
    }
}
