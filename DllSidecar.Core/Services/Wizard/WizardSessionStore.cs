using System.Text.Json;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Wizard;

namespace DllSidecar.Core.Services.Wizard;

/// <summary>
/// Snapshot DTO that captures the user-typed / user-chosen state of a WizardSession so
/// it can survive app restarts. Heavy objects (ScanResults, CveDedup, full PeAnalysis)
/// are intentionally omitted — when the user resumes we re-run those, but we don't lose
/// their typed paths, combo selections and advisory draft text.
/// </summary>
public sealed class WizardSessionSnapshot
{
    public WizardStage CurrentStage { get; set; }
    public WizardInputKind InputKind { get; set; }
    public WizardEntryPoint EntryPoint { get; set; }
    public WizardHuntingGoal HuntingGoal { get; set; }
    public string? InputPath { get; set; }

    public string? SurveyRootDir { get; set; }

    public string? ProcmonCsvPath { get; set; }

    // Candidate choice recorded by name/path so Pick can rematch when the user resumes
    // and re-scans. If nothing matches anymore the user just picks again.
    public string? ChosenExistingFilename { get; set; }
    public string? ChosenExistingPath { get; set; }
    public string? ChosenPhantomName { get; set; }
    public string? ChosenPhantomDirectory { get; set; }

    public GenerationMode CraftMode { get; set; } = GenerationMode.Sideload;
    public string? TargetExport { get; set; }
    public string? GeneratedOutputDir { get; set; }
    public string? BuiltDllPath { get; set; }

    // Craft UI state
    public string? CraftHostExePath { get; set; }
    public string? Vendor { get; set; }
    public string? CraftArchOverride { get; set; }
    public int CraftPayloadIndex { get; set; }
    public string? CraftPayloadData { get; set; }
    public string? CraftSandboxTargets { get; set; }
    public int CraftThreadModeIndex { get; set; }
    public bool CraftDInvoke { get; set; }
    public bool CraftSyscalls { get; set; }
    public bool CraftEncryptStrings { get; set; }
    public int CraftEntryDelayMs { get; set; }
    public int CraftXorKeyIndex { get; set; }
    public bool CraftCloneMeta { get; set; }
    public bool CraftTimestampStomp { get; set; }
    public bool CraftAutoBuild { get; set; } = true;
    public bool CraftWriteProof { get; set; }
    public int CraftPreLaunchDelaySec { get; set; }
    public bool CraftWaitBlock { get; set; } = true;
    public int CraftFireTimeoutSec { get; set; } = 15;

    public string? AdvisoryMarkdown { get; set; }
    public string? AdvisoryPdfPath { get; set; }

    public DateTime SavedAtUtc { get; set; }
}

/// <summary>
/// Persists WizardSession to %LOCALAPPDATA%\DllSidecar\wizard_session.json so a user that
/// closes the app mid-wizard can resume where they left off.
/// </summary>
public static class WizardSessionStore
{
    private static readonly string Dir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DllSidecar");

    public static string FilePath => Path.Combine(Dir, "wizard_session.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static bool HasSession() => File.Exists(FilePath);

    public static void Save(WizardSession session)
    {
        try
        {
            Directory.CreateDirectory(Dir);
            var snap = new WizardSessionSnapshot
            {
                CurrentStage = session.CurrentStage,
                InputKind = session.InputKind,
                EntryPoint = session.EntryPoint,
                HuntingGoal = session.HuntingGoal,
                InputPath = session.InputPath,
                SurveyRootDir = session.SurveyRootDir,
                ProcmonCsvPath = session.ProcmonCsvPath,
                ChosenExistingFilename = session.ChosenExisting?.Dll.Filename,
                ChosenExistingPath = session.ChosenExisting?.Dll.Path,
                ChosenPhantomName = session.ChosenPhantom?.DllName,
                ChosenPhantomDirectory = session.ChosenPhantom?.DirectoryPath,
                CraftMode = session.CraftMode,
                TargetExport = session.TargetExport,
                GeneratedOutputDir = session.GeneratedOutputDir,
                BuiltDllPath = session.BuiltDllPath,
                CraftHostExePath = session.CraftHostExePath,
                Vendor = session.Vendor,
                CraftArchOverride = session.CraftArchOverride,
                CraftPayloadIndex = session.CraftPayloadIndex,
                CraftPayloadData = session.CraftPayloadData,
                CraftSandboxTargets = session.CraftSandboxTargets,
                CraftThreadModeIndex = session.CraftThreadModeIndex,
                CraftDInvoke = session.CraftDInvoke,
                CraftSyscalls = session.CraftSyscalls,
                CraftEncryptStrings = session.CraftEncryptStrings,
                CraftEntryDelayMs = session.CraftEntryDelayMs,
                CraftXorKeyIndex = session.CraftXorKeyIndex,
                CraftCloneMeta = session.CraftCloneMeta,
                CraftTimestampStomp = session.CraftTimestampStomp,
                CraftAutoBuild = session.CraftAutoBuild,
                CraftWriteProof = session.CraftWriteProof,
                CraftPreLaunchDelaySec = session.CraftPreLaunchDelaySec,
                CraftWaitBlock = session.CraftWaitBlock,
                CraftFireTimeoutSec = session.CraftFireTimeoutSec,
                AdvisoryMarkdown = session.AdvisoryMarkdown,
                AdvisoryPdfPath = session.AdvisoryPdfPath,
                SavedAtUtc = DateTime.UtcNow,
            };
            File.WriteAllText(FilePath, JsonSerializer.Serialize(snap, JsonOpts));
        }
        catch
        {
            // Non-fatal — persistence is best-effort. Losing the snapshot is the same as
            // closing without saving, which is the pre-existing behaviour.
        }
    }

    public static WizardSessionSnapshot? TryLoad()
    {
        try
        {
            if (!File.Exists(FilePath)) return null;
            var json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<WizardSessionSnapshot>(json, JsonOpts);
        }
        catch { return null; }
    }

    public static void Delete()
    {
        try { if (File.Exists(FilePath)) File.Delete(FilePath); } catch { /* ignore */ }
    }

    /// <summary>
    /// Apply a snapshot to a fresh WizardSession so stages see previously typed state.
    /// Heavy objects (ScanResults/CveDedup) stay null until the user re-runs survey/verify.
    /// </summary>
    public static void Apply(WizardSessionSnapshot snap, WizardSession target)
    {
        target.CurrentStage = snap.CurrentStage;
        target.InputKind = snap.InputKind;
        target.EntryPoint = snap.EntryPoint;
        target.HuntingGoal = snap.HuntingGoal;
        target.InputPath = snap.InputPath;
        target.SurveyRootDir = snap.SurveyRootDir;
        target.ProcmonCsvPath = snap.ProcmonCsvPath;
        target.CraftMode = snap.CraftMode;
        target.TargetExport = snap.TargetExport;
        target.GeneratedOutputDir = snap.GeneratedOutputDir;
        target.BuiltDllPath = snap.BuiltDllPath;
        target.CraftHostExePath = snap.CraftHostExePath;
        target.Vendor = snap.Vendor;
        target.CraftArchOverride = snap.CraftArchOverride;
        target.CraftPayloadIndex = snap.CraftPayloadIndex;
        target.CraftPayloadData = snap.CraftPayloadData;
        target.CraftSandboxTargets = snap.CraftSandboxTargets;
        target.CraftThreadModeIndex = snap.CraftThreadModeIndex;
        target.CraftDInvoke = snap.CraftDInvoke;
        target.CraftSyscalls = snap.CraftSyscalls;
        target.CraftEncryptStrings = snap.CraftEncryptStrings;
        target.CraftEntryDelayMs = snap.CraftEntryDelayMs;
        target.CraftXorKeyIndex = snap.CraftXorKeyIndex;
        target.CraftCloneMeta = snap.CraftCloneMeta;
        target.CraftTimestampStomp = snap.CraftTimestampStomp;
        target.CraftAutoBuild = snap.CraftAutoBuild;
        target.CraftWriteProof = snap.CraftWriteProof;
        target.CraftPreLaunchDelaySec = snap.CraftPreLaunchDelaySec;
        target.CraftWaitBlock = snap.CraftWaitBlock;
        target.CraftFireTimeoutSec = snap.CraftFireTimeoutSec;
        target.AdvisoryMarkdown = snap.AdvisoryMarkdown;
        target.AdvisoryPdfPath = snap.AdvisoryPdfPath;
        // Candidate objects left null — user re-scans in Survey to re-populate. The
        // filename/path snapshot fields stay available for a future "auto-rematch".
    }
}
