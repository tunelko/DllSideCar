using DllSidecar.Core.Helpers;

namespace DllSidecar.Core.Services;

/// <summary>
/// Tristate classification for a ProcMon NAME-NOT-FOUND DLL: KnownDll (loaded from System32), Resolvable (canonical exists), or Phantom (absent).
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
    private static readonly string System32Dir =
        Environment.GetFolderPath(Environment.SpecialFolder.System);

    // On x86-only hosts SystemX86 falls back to System32 (harmless duplicate probe).
    private static readonly string SysWOW64Dir =
        Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);

    /// <summary>
    /// Lookup + two File.Exists probes; returns canonical path when found.
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
