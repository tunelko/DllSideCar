using DllSidecar.Core.Helpers;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>Finds phantom imports: DLL names that do not resolve under the Windows loader search sequence (KnownDLLs / importer dir / System32 or SysWOW64).</summary>
public static class PhantomDetector
{
    private static readonly string System32Dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
    private static readonly string SysWow64Dir = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
    private static readonly bool Is64BitOs = Environment.Is64BitOperatingSystem;

    public class PhantomHit
    {
        public required string DllName { get; set; }
        public required string ImporterPath { get; set; }
        public required string ImporterDirectory { get; set; }
        public bool IsDelayLoad { get; set; }
        public List<string> SearchedLocations { get; set; } = [];
    }

    public static List<PhantomHit> Find(PeAnalysis importer)
    {
        var hits = new List<PhantomHit>();
        var importerDir = Path.GetDirectoryName(importer.Path) ?? "";
        if (string.IsNullOrEmpty(importerDir)) return hits;

        foreach (var imp in importer.Imports)
        {
            var name = imp.DllName;
            if (string.IsNullOrEmpty(name)) continue;

            if (IsApiSet(name)) continue;
            if (KnownDlls.IsKnown(name)) continue;

            var searched = new List<string>();

            var localPath = Path.Combine(importerDir, name);
            searched.Add(localPath);
            if (File.Exists(localPath)) continue;

            var sysDir = (importer.Arch == "x86" && Is64BitOs) ? SysWow64Dir : System32Dir;
            var sysPath = Path.Combine(sysDir, name);
            searched.Add(sysPath);
            if (File.Exists(sysPath)) continue;

            var otherSys = sysDir == System32Dir ? SysWow64Dir : System32Dir;
            if (!string.IsNullOrEmpty(otherSys))
            {
                var otherPath = Path.Combine(otherSys, name);
                searched.Add(otherPath);
                if (File.Exists(otherPath)) continue;
            }

            hits.Add(new PhantomHit
            {
                DllName = name,
                ImporterPath = importer.Path,
                ImporterDirectory = importerDir,
                IsDelayLoad = imp.IsDelayLoad,
                SearchedLocations = searched,
            });
        }

        return hits;
    }

    private static bool IsApiSet(string name)
    {
        var lower = name.ToLowerInvariant();
        return lower.StartsWith("api-ms-win-") || lower.StartsWith("ext-ms-win-");
    }
}
