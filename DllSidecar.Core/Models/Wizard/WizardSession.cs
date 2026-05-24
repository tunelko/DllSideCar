using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Advisory;
using DllSidecar.Core.Models.Cve;
using DllSidecar.Core.Services;

namespace DllSidecar.Core.Models.Wizard;

public enum WizardStage
{
    Input = 0,
    Survey = 1,
    Verify = 2,
    Pick = 3,
    Craft = 4,
    Report = 5,
    Done = 6,
}

public enum WizardInputKind
{
    // Explicit numeric IDs preserve back-compat with persisted
    // wizard_session.json snapshots written before the Installer-extract
    // feature was removed. Value 0 used to be 'Installer'; keeping the
    // gap means an old snapshot with InputKind=1 still deserializes as
    // InstallDirectory, not SinglePe.
    InstallDirectory = 1, // a directory, scan it
    SinglePe = 2,         // skip scanning — go straight to Craft
}

/// <summary>
/// Which of the three entry points the user chose on the Input stage. Drives
/// the routing: ScanFolder → Survey, AnalyzeBinary → Pick (bypass scan),
/// RuntimeTrace → hand off to RuntimeTracePage (user returns via promotion).
/// </summary>
public enum WizardEntryPoint
{
    ScanFolder,
    AnalyzeBinary,
    RuntimeTrace,
}

/// <summary>
/// Research goal declared up-front. Used by SurveyStage to bias scoring emphasis
/// and default filters — e.g. LocalPrivesc prefers writable service/task paths
/// over user-only ACLs, Persistence favours COM hijack + Program Files writes.
/// </summary>
public enum WizardHuntingGoal
{
    ArbitraryCode,    // any user-context RCE — default
    LocalPrivesc,     // user → SYSTEM / elevated
    Persistence,      // survives reboot, COM hijack, writable Program Files
}

/// <summary>
/// All state accumulated as the user (or express automation) moves through the wizard.
/// Single instance per wizard session — passed to every stage. Lost on wizard close
/// unless the user confirms completion of Report stage.
/// </summary>
public class WizardSession
{
    public WizardStage CurrentStage { get; set; } = WizardStage.Input;

    // ---- Stage 1: Input ----
    public WizardInputKind InputKind { get; set; } = WizardInputKind.InstallDirectory;
    public WizardEntryPoint EntryPoint { get; set; } = WizardEntryPoint.ScanFolder;
    public WizardHuntingGoal HuntingGoal { get; set; } = WizardHuntingGoal.ArbitraryCode;
    public string? InputPath { get; set; }

    // ---- Stage 2: Survey ----
    public string? SurveyRootDir { get; set; }
    public ScanResults? ScanResults { get; set; }

    // ---- Stage 3: Verify ----
    public string? ProcmonCsvPath { get; set; }
    public CveQueryResult? CveDedup { get; set; }

    // ---- Stage 4: Pick ----
    public SideloadCandidate? ChosenExisting { get; set; }
    public PhantomCandidate? ChosenPhantom { get; set; }

    // ---- Stage 5: Craft ----
    public DllSidecar.Core.Models.GenerationMode CraftMode { get; set; } = DllSidecar.Core.Models.GenerationMode.Sideload;
    public string? TargetExport { get; set; }
    public string? GeneratedOutputDir { get; set; }
    public string? BuiltDllPath { get; set; }

    // Craft UI state — survives back/forward navigation within the wizard AND (when
    // snapshotted) across app restarts. Every user input in CraftStage writes here.
    public string? CraftHostExePath { get; set; }
    /// <summary>
    /// Vendor resolved from the Host EXE's PE version info (CompanyName) when CraftStage
    /// sees a valid host path. Feeds <see cref="ReportStage"/> and the Library so phantom
    /// advisories (no target PE) still end up under the correct vendor folder.
    /// </summary>
    public string? Vendor { get; set; }
    public string? CraftArchOverride { get; set; }               // "x86" / "x64"
    public int CraftPayloadIndex { get; set; }
    public string? CraftPayloadData { get; set; }
    public string? CraftSandboxTargets { get; set; }
    public int CraftThreadModeIndex { get; set; }
    public bool CraftDInvoke { get; set; }
    public bool CraftSyscalls { get; set; }
    public bool CraftIndirectSyscalls { get; set; }
    public bool CraftEncryptStrings { get; set; }
    public int CraftEntryDelayMs { get; set; }
    public bool CraftCloneMeta { get; set; }
    public bool CraftTimestampStomp { get; set; }
    public bool CraftAutoBuild { get; set; } = true;
    public bool CraftWriteProof { get; set; }
    public int CraftPreLaunchDelaySec { get; set; }
    public bool CraftWaitBlock { get; set; } = true;
    public int CraftFireTimeoutSec { get; set; } = 15;

    // ---- Stage 6: Report ----
    public AdvisoryContext? Advisory { get; set; }
    public string? AdvisoryMarkdown { get; set; }
    public string? AdvisoryPdfPath { get; set; }

    /// <summary>True when any stage beyond Input has produced state worth warning about on close.</summary>
    public bool HasProgress =>
        ScanResults != null ||
        ChosenExisting != null || ChosenPhantom != null ||
        BuiltDllPath != null ||
        AdvisoryMarkdown != null;

    /// <summary>What the user actually picked — convenience for later stages.</summary>
    public PeAnalysis? TargetPe =>
        ChosenExisting?.Dll ??
        (ChosenPhantom != null ? null : null); // phantoms have no PE; synthesized at Craft time

    /// <summary>Human-readable short label of what's chosen, for SessionSummary panel.</summary>
    public string ChosenLabel
    {
        get
        {
            if (ChosenExisting != null)
            {
                var s = ChosenExisting.Score;
                return $"{ChosenExisting.Dll.Filename} (existing · total {s.Total}/10 · E{s.Exploitability} I{s.Impact} C{s.Confidence})";
            }
            if (ChosenPhantom != null)
            {
                var s = ChosenPhantom.Score;
                return $"{ChosenPhantom.DllName} (phantom · total {s.Total}/10 · E{s.Exploitability} I{s.Impact} C{s.Confidence})";
            }
            return "—";
        }
    }
}
