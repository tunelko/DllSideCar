using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Locates well-known system DLLs and reads their exports for phantom -> Proxy vs Sideload handoff.
/// </summary>
public static class SystemDllResolver
{
    /// <summary>
    /// Find and analyze the canonical system copy of <paramref name="dllName"/>; x64 -> System32, x86 -> SysWOW64.
    /// </summary>
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
