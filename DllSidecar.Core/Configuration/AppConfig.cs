namespace DllSidecar.Core.Configuration;

public class AppConfig
{
    public MingwConfig Mingw { get; set; } = new();
    public PathsConfig Paths { get; set; } = new();
    public ToolsConfig Tools { get; set; } = new();
    public UiStateConfig UiState { get; set; } = new();
    public ResearcherConfig Researcher { get; set; } = new();
    public PayloadConfig Payload { get; set; } = new();

    // ScanPage runs CVE dedup against NVD after each scan; off by default.
    public bool AutoCveLookup { get; set; }

    // First-run onboarding flag; reset on every version transition by PostInstallReset.
    public bool WelcomeSeen { get; set; }
}

/// <summary>Default payload knobs reused across Generate runs.</summary>
public class PayloadConfig
{
    public string MessageBoxTitle { get; set; } = "DllSidecar PoC";
    public string MessageBoxBody { get; set; } = "DLL Sideloading PoC\nDllSidecar — BugAInters 2026";

    // Hostnames or dotted-quad IPv4; 4444 is the canonical msfvenom/nc default.
    public string ReverseShellHost { get; set; } = "127.0.0.1";
    public int ReverseShellPort { get; set; } = 4444;
}

/// <summary>Researcher identity reused across every AdvisoryContext default.</summary>
public class ResearcherConfig
{
    public string Name { get; set; } = "";
    public string Handle { get; set; } = "";
    public string Blog { get; set; } = "";
    public string Email { get; set; } = "";
    public string PgpFingerprint { get; set; } = "";  // e.g. "ECFE8F52A79544C4D5CEC31D816793CF3167C4D2"
    public string PgpKeyId { get; set; } = "";        // short id, e.g. "816793CF3167C4D2"
}

/// <summary>Per-page UI state persisted in %APPDATA%\DllSidecar\config.json.</summary>
public class UiStateConfig
{
    public GeneratePageState GeneratePage { get; set; } = new();
    public ScanPageState ScanPage { get; set; } = new();
    public ProcmonPageState ProcmonPage { get; set; } = new();

    public string? LastBuildDir { get; set; }
    public string? LastPrivescDir { get; set; }
    public string? LastRuntimeExePath { get; set; }
    public string? LastRuntimePid { get; set; }

    // 32 = collapsed (just the CONSOLE header strip).
    public double ConsoleHeight { get; set; } = 32;
}

public class GeneratePageState
{
    // Top-level target / deploy
    public string? DllPath { get; set; }
    public string? HostExePath { get; set; }
    public string? Arch { get; set; }                     // "x86" / "x64"

    // Payload
    public int PayloadIndex { get; set; }                 // 0=MessageBox 1=Command 2=Shellcode 3=SandboxEscape
    public string? PayloadData { get; set; }
    public string SandboxTargets { get; set; } = "AcroCEF.exe,AdobeCollabSync.exe";

    // Proxy-specific
    public string? TargetExport { get; set; }

    // Thread mode for payload (calling / std / native)
    public int ThreadModeIndex { get; set; }

    // Evasion
    public bool DInvoke { get; set; }
    public bool Syscalls { get; set; }
    public bool IndirectSyscalls { get; set; }
    public bool EncryptStrings { get; set; }
    public bool UnhookNtdll { get; set; }
    public bool PatchEtw { get; set; }
    public int EntryDelayMs { get; set; }

    // Metadata / build
    public bool CloneMeta { get; set; }
    public bool TimestampStomp { get; set; }
    public bool AutoBuild { get; set; } = true;

    // Execution
    public bool WriteProof { get; set; }
    public int PreLaunchDelaySec { get; set; }
    public bool WaitBlock { get; set; } = true;          // true = WaitBlock, false = WaitFire
    public int FireTimeoutSec { get; set; } = 15;
}

public class ScanPageState
{
    public bool RequireImporter { get; set; } = true;
    public bool OnlyWritable { get; set; }
    public bool OnlySignedExe { get; set; }
    public bool IncludePhantoms { get; set; } = true;

    public int MinExploit { get; set; }
    public int MinImpact { get; set; }
    public int MinConf { get; set; }
}

public class ProcmonPageState
{
    public string? LastCsvPath { get; set; }
    public bool OnlyUserSpace { get; set; }
    public bool OnlyHighRisk { get; set; }
    // KnownDlls always load from System32 regardless of sideload attempts.
    public bool HideKnownDlls { get; set; } = true;
    // Rows where every searched dir requires admin to write collapse the threat model.
    public bool HideLockedDirs { get; set; } = true;
}

public class MingwConfig
{
    public string Mingw32BinDir { get; set; } = @"C:\msys64\mingw32\bin";
    public string Mingw64BinDir { get; set; } = @"C:\msys64\mingw64\bin";
    public string MsysUsrBinDir { get; set; } = @"C:\msys64\usr\bin";

    public string[] GetSearchPaths(string arch) => arch switch
    {
        "x86" => [Mingw32BinDir, MsysUsrBinDir],
        "x64" => [Mingw64BinDir, MsysUsrBinDir],
        _ => [],
    };
}

public class PathsConfig
{
    public string? LastDllPath { get; set; }
    public string? LastScanPath { get; set; }
    public string? LastOutputRoot { get; set; }
}

public class ToolsConfig
{
    // ToolkitChecker probes these dirs first. SysinternalsDir auto-resolves Procmon, sigcheck, etc.
    public string? SysinternalsDir { get; set; }         // e.g. C:\Tools\Sysinternals
    public string? ToolsRootDir { get; set; }            // generic root, probed recursively 1 level

    // Individual tool paths — override or supplement bundle-directory resolution
    public string? ProcmonPath { get; set; }             // Procmon.exe or Procmon64.exe
    public string? SigcheckPath { get; set; }            // sigcheck.exe or sigcheck64.exe
    public string? DependenciesGuiPath { get; set; }     // lucasg Dependencies
    public string? X64DbgPath { get; set; }
    public string? X32DbgPath { get; set; }

    public string SysinternalsDownloadUrl { get; set; } = "https://download.sysinternals.com/files/SysinternalsSuite.zip";
    public string DependenciesDownloadUrl { get; set; } = "https://github.com/lucasg/Dependencies/releases";
    public string X64DbgDownloadUrl { get; set; } = "https://x64dbg.com/";

    // NVD API v2 key raises rate limit from 5 req/30s to 50 req/30s. https://nvd.nist.gov/developers/request-an-api-key
    public string? NvdApiKey { get; set; }
}
