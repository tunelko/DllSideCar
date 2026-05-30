using System.IO;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Services;
using DllSidecar.Core.Services.Wizard;

namespace DllSidecar.GUI;

/// <summary>Runs once per install: wipes advisory DB, researcher identity, NVD key, sessions, welcome flag.</summary>
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
        ClearSessionSnapshots();
        ResetWelcomeFlag();
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
            // SQLite WAL/SHM siblings.
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

    private static void ClearSessionSnapshots()
    {
        try
        {
            AppSessionStore.DeleteAll();
            Log.Info("post-install", "session snapshots cleared");
        }
        catch (Exception ex) { Log.Warn("post-install", $"session clear failed: {ex.Message}"); }
    }

    private static void ResetWelcomeFlag()
    {
        try
        {
            ConfigManager.Current.WelcomeSeen = false;
            ConfigManager.Save();
            Log.Info("post-install", "welcome flag reset");
        }
        catch (Exception ex) { Log.Warn("post-install", $"welcome flag reset failed: {ex.Message}"); }
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
