using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Locates well-known system DLLs and reads their export table.
/// Used by the phantom → Generate handoff to decide whether to emit a full Proxy
/// (DLL has exports the host depends on) or a minimal Sideload stub (no exports).
/// Without this, a synthesized <see cref="PeAnalysis"/> for a phantom has an empty
/// Exports list and the template produces a DLL that fails Windows loader import
/// resolution in the host — payload never fires.
/// </summary>
public static class SystemDllResolver
{
    /// <summary>
    /// Find the canonical system copy of <paramref name="dllName"/> for the given
    /// <paramref name="arch"/> ("x64" or "x86"), analyze it, and return the result.
    /// Returns null if the file doesn't exist or the PE can't be parsed (malformed,
    /// access denied, arch mismatch).
    /// </summary>
    /// <remarks>
    /// x64 → %SYSTEMROOT%\System32 (native 64-bit DLLs on a 64-bit OS).
    /// x86 → %SYSTEMROOT%\SysWOW64 (32-bit DLLs for WoW64 processes).
    /// Callers should treat a null return as "not a system-known DLL; fall back
    /// to Sideload stub mode and warn the user the host may reject it".
    /// </remarks>
    public static ResolvedSystemDll? Resolve(string dllName, string arch)
    {
        if (string.IsNullOrWhiteSpace(dllName)) return null;
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(windir)) return null;

        var subdir = arch == "x86" ? "SysWOW64" : "System32";
        var candidate = Path.Combine(windir, subdir, dllName);
        if (!File.Exists(candidate)) return null;

        try
        {
            var pe = PeAnalyzer.Analyze(candidate);
            return new ResolvedSystemDll
            {
                Path = candidate,
                Analysis = pe,
            };
        }
        catch
        {
            // Malformed, access denied, arch mismatch — let the caller decide fallback.
            return null;
        }
    }
}

public class ResolvedSystemDll
{
    public required string Path { get; set; }
    public required PeAnalysis Analysis { get; set; }
    public int ExportCount => Analysis.Exports.Count;
}
