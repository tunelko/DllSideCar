using System.IO;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Logging;

namespace DllSidecar.GUI;

/// <summary>
/// Runs once per (re)install. The installer drops {app}\.install-marker.txt with
/// the version on every install. App startup compares that marker against the
/// last-launched-version recorded in %APPDATA%\DllSidecar\.last-launched-version;
/// when they differ (fresh install OR upgrade), per-user state that should not
/// carry over between releases is wiped:
///
///   · advisories\library.db   — SQLite library, fully reset
///   · config.Researcher       — Name / Handle / Blog / Email / PGP fields cleared
///   · config.Tools.NvdApiKey  — researcher-specific NVD API key cleared
///
/// Preserved (these are environment, not identity):
///   · Tools paths (sysinternals, procmon, sigcheck, 7-Zip, innounp, x64dbg …)
///   · MSYS / MinGW paths
///   · UI state (last paths, window sizes, console height …)
///   · XOR preset keys
///
/// Dev mode never sees the marker (installer doesn't run in dev), so the reset
/// is a no-op there — researcher config persists across dotnet run invocations.
/// </summary>
internal static class PostInstallReset
{
    private static readonly string MarkerPath = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory, ".install-marker.txt");

    private static readonly string LastLaunchedPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "DllSidecar", ".last-launched-version");

    public static void RunIfNeeded()
    {
        if (!File.Exists(MarkerPath)) return;

        string installVer;
        try { installVer = File.ReadAllText(MarkerPath).Trim(); }
        catch (IOException ex) { Log.Warn("post-install", $"marker unreadable: {ex.Message}"); return; }

        string lastLaunched = "";
        if (File.Exists(LastLaunchedPath))
        {
            try { lastLaunched = File.ReadAllText(LastLaunchedPath).Trim(); }
            catch (IOException) { /* treat as first-launch */ }
        }

        if (string.Equals(lastLaunched, installVer, StringComparison.Ordinal))
            return; // already reset for this install

        Log.Info("post-install", $"version transition {lastLaunched} -> {installVer}: clearing per-install state");
        ClearAdvisoryDb();
        ClearResearcherIdentity();
        RecordVersion(installVer);
    }

    private static void ClearAdvisoryDb()
    {
        try
        {
            var db = Core.Services.AdvisoryLibrary.AdvisoryRepository.DbPath;
            if (File.Exists(db))
            {
                File.Delete(db);
                Log.Info("post-install", $"deleted {db}");
            }
            // SQLite WAL/SHM siblings — leftovers from an open connection would
            // otherwise resurrect the deleted DB on next open.
            foreach (var sidecar in new[] { db + "-wal", db + "-shm", db + "-journal" })
                if (File.Exists(sidecar)) File.Delete(sidecar);
        }
        catch (IOException ex) { Log.Warn("post-install", $"db delete failed: {ex.Message}"); }
        catch (UnauthorizedAccessException ex) { Log.Warn("post-install", $"db delete denied: {ex.Message}"); }
    }

    private static void ClearResearcherIdentity()
    {
        try
        {
            var cfg = ConfigManager.Current;
            cfg.Researcher = new ResearcherConfig();
            cfg.Tools.NvdApiKey = null;
            ConfigManager.Save();
            Log.Info("post-install", "researcher fields + NvdApiKey cleared");
        }
        catch (Exception ex) { Log.Warn("post-install", $"config reset failed: {ex.Message}"); }
    }

    private static void RecordVersion(string installVer)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LastLaunchedPath)!);
            File.WriteAllText(LastLaunchedPath, installVer);
        }
        catch (IOException ex) { Log.Warn("post-install", $"version stamp failed: {ex.Message}"); }
    }
}
