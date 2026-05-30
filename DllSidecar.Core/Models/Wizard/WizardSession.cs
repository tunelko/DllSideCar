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
    // Explicit numeric IDs preserve back-compat with persisted wizard_session.json snapshots (value 0 was the removed 'Installer').
    InstallDirectory = 1,
    SinglePe = 2,
}

/// <summary>Entry point chosen on the Input stage; drives stage routing.</summary>
public enum WizardEntryPoint
{
    ScanFolder,
    AnalyzeBinary,
    RuntimeTrace,
}

/// <summary>Research goal declared up-front; biases SurveyStage scoring and defaults.</summary>
public enum WizardHuntingGoal
{
    ArbitraryCode,    // any user-context RCE — default
    LocalPrivesc,     // user → SYSTEM / elevated
    Persistence,      // survives reboot, COM hijack, writable Program Files
}

/// <summary>State accumulated as the user moves through wizard stages.</summary>
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

    // Craft UI state — persisted across navigation and (snapshotted) app restarts.
    public string? CraftHostExePath { get; set; }
    /// <summary>Vendor resolved from the Host EXE's CompanyName; used by ReportStage and the Library.</summary>
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
    public bool CraftUnhookNtdll { get; set; }
    public bool CraftPatchEtw { get; set; }
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
