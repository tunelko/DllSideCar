using System.Text.Json;
using System.Text.Json.Serialization;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services.Wizard;

namespace DllSidecar.Core.Services;

/// <summary>
/// Lightweight DTO that captures the per-page inputs and the active page so a researcher
/// who saved on exit lands on the same screen with the same paths typed in. Heavy results
/// that *can* be re-derived (PeAnalysis from a path, ProcmonParser.ParseResult from a CSV)
/// are re-run on restore; heavy results that *cannot* be re-derived (an EtwTraceResult,
/// which represents an interactive capture session) are persisted to a companion file.
/// </summary>
public sealed class AppSessionSnapshot
{
    public DateTime SavedAtUtc { get; set; }

    /// <summary>Page name to navigate to on restore. Matches the strings written by
    /// MainWindow.NavigateTo. Unknown values fall back to the wizard.</summary>
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
/// Drives the "save session on exit / silent restore on launch" feature. Wizard state still
/// lives in <see cref="WizardSessionStore"/>; this store wraps the rest so File→Delete
/// Session can wipe both in one click.
/// </summary>
public static class AppSessionStore
{
    private static readonly string Dir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DllSidecar");

    public static string FilePath => Path.Combine(Dir, "app_session.json");

    // Heavy results that cannot be re-derived from a path live in companion files so the
    // main app_session.json stays small and human-inspectable. Each file is loaded
    // independently — a corrupt/missing companion never blocks restoring the others.
    private static string EtwResultPath => Path.Combine(Dir, "etw_result.json");
    private static string ScanResultsPath => Path.Combine(Dir, "scan_results.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        // The TracedProcess tree shares nodes between RootProcess and ProcessTree; without
        // this, the cycle-detector trips on the same instance being seen twice. Preserve
        // round-trips by id refs so the deserialized tree matches the in-memory layout.
        ReferenceHandler = ReferenceHandler.Preserve,
    };

    public static bool HasSession() =>
        File.Exists(FilePath) || File.Exists(EtwResultPath) || WizardSessionStore.HasSession();

    public static void Save(AppSessionSnapshot snap)
    {
        // Throw on error so the caller (MainWindow.OnClosing) can log it.
        // Silent failure made the "Save then reopen → nothing" symptom indistinguishable
        // from "Save succeeded but restore code didn't pick up the data".
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
            // Silent return-null masked real load failures: a researcher who
            // saved on exit would see an empty app on next launch and assume
            // "save doesn't work" when the actual symptom is "load threw".
            Log.Warn("session.load", $"app_session.json deserialize failed: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    /// <summary>Persist the live trace result so a save-and-restart cycle resurrects the
    /// page exactly. Pass null to clear the on-disk copy (used when the user discards).</summary>
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

    /// <summary>Persist the in-memory ScanResults (existing + promoted phantoms) so a
    /// RuntimeTrace→Promote→Wizard→Craft chain survives a restart without forcing the
    /// user to redo Promote. Pass null to clear the on-disk copy.</summary>
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

    /// <summary>Deletes app-level snapshot AND every companion file AND the wizard snapshot.
    /// Used by File→Delete Session and by the "discard" branch of the exit prompt.</summary>
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
