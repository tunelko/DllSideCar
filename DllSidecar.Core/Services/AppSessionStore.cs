using System.Text.Json;
using System.Text.Json.Serialization;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services.Wizard;

namespace DllSidecar.Core.Services;

/// <summary>
/// Per-page inputs + active page for save/restore. Re-derivable results are re-run; non-derivable ones live in companion files.
/// </summary>
public sealed class AppSessionSnapshot
{
    public DateTime SavedAtUtc { get; set; }

    /// <summary>Page name to navigate to on restore; unknown values fall back to wizard.</summary>
    public string? ActivePage { get; set; }

    public string? CurrentDllPath { get; set; }
    public string? LastScanDir { get; set; }
    public string? LastProcmonCsvPath { get; set; }
    public string? LastRuntimeLaunchExe { get; set; }

    public string? PendingAdvisoryMarkdown { get; set; }
    public string? PendingAdvisoryRecordId { get; set; }
    public string? PendingAdvisoryTemplateId { get; set; }
}

/// <summary>
/// Persists the app-level session snapshot to %LOCALAPPDATA%\DllSidecar\app_session.json.
/// </summary>
public static class AppSessionStore
{
    private static readonly string Dir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DllSidecar");

    public static string FilePath => Path.Combine(Dir, "app_session.json");

    // Companion files for non-re-derivable heavy results.
    private static string EtwResultPath => Path.Combine(Dir, "etw_result.json");
    private static string ScanResultsPath => Path.Combine(Dir, "scan_results.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        // Needed: TracedProcess tree shares nodes between RootProcess and ProcessTree.
        ReferenceHandler = ReferenceHandler.Preserve,
    };

    public static bool HasSession() =>
        File.Exists(FilePath) || File.Exists(EtwResultPath) || WizardSessionStore.HasSession();

    public static void Save(AppSessionSnapshot snap)
    {
        // Throw on error so MainWindow.OnClosing can log it.
        Directory.CreateDirectory(Dir);
        snap.SavedAtUtc = DateTime.UtcNow;
        File.WriteAllText(FilePath, JsonSerializer.Serialize(snap, JsonOpts));
    }

    public static AppSessionSnapshot? TryLoad()
    {
        if (!File.Exists(FilePath)) return null;
        try
        {
            var json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<AppSessionSnapshot>(json, JsonOpts);
        }
        catch (Exception ex)
        {
            Log.Warn("session.load", $"app_session.json deserialize failed: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    /// <summary>Persist the live trace result; null clears the on-disk copy.</summary>
    public static void SaveEtwResult(EtwTraceResult? result)
    {
        if (result == null) { TryDelete(EtwResultPath); return; }
        Directory.CreateDirectory(Dir);
        File.WriteAllText(EtwResultPath, JsonSerializer.Serialize(result, JsonOpts));
    }

    public static EtwTraceResult? TryLoadEtwResult()
    {
        if (!File.Exists(EtwResultPath)) return null;
        try
        {
            var result = JsonSerializer.Deserialize<EtwTraceResult>(File.ReadAllText(EtwResultPath), JsonOpts);
            if (result != null)
                Log.Info("session.load",
                    $"etw_result.json loaded — {result.FilteredEvents} events, {result.ProcessTree.Count} procs");
            return result;
        }
        catch (Exception ex)
        {
            Log.Warn("session.load", $"etw_result.json deserialize failed: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    /// <summary>Persist in-memory ScanResults; null clears the on-disk copy.</summary>
    public static void SaveScanResults(ScanResults? results)
    {
        if (results == null) { TryDelete(ScanResultsPath); return; }
        Directory.CreateDirectory(Dir);
        File.WriteAllText(ScanResultsPath, JsonSerializer.Serialize(results, JsonOpts));
    }

    public static ScanResults? TryLoadScanResults()
    {
        if (!File.Exists(ScanResultsPath)) return null;
        try
        {
            var result = JsonSerializer.Deserialize<ScanResults>(File.ReadAllText(ScanResultsPath), JsonOpts);
            if (result != null)
                Log.Info("session.load",
                    $"scan_results.json loaded — {result.ExistingCount} existing + {result.PhantomCount} phantoms");
            return result;
        }
        catch (Exception ex)
        {
            Log.Warn("session.load", $"scan_results.json deserialize failed: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    /// <summary>Delete app snapshot, every companion file, and the wizard snapshot.</summary>
    public static void DeleteAll()
    {
        TryDelete(FilePath);
        TryDelete(EtwResultPath);
        TryDelete(ScanResultsPath);
        WizardSessionStore.Delete();
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* ignore */ }
    }
}
