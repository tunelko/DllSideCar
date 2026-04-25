namespace DllSidecar.Core.Configuration;

public class AppConfig
{
    public MingwConfig Mingw { get; set; } = new();
    public XorConfig Xor { get; set; } = new();
    public PathsConfig Paths { get; set; } = new();
    public ToolsConfig Tools { get; set; } = new();
    public UiStateConfig UiState { get; set; } = new();
    public ResearcherConfig Researcher { get; set; } = new();

    // When true, ScanPage automatically runs CVE dedup against NVD after each scan.
    // Off by default — researcher may want to avoid traffic on repeat local scans.
    public bool AutoCveLookup { get; set; }
}

/// <summary>
/// Identity of the researcher submitting advisories. Set once in Configuration and
/// reused across every AdvisoryContext default. PGP key stored here because it's
/// author-identity, not per-case.
/// </summary>
public class ResearcherConfig
{
    public string Name { get; set; } = "Pedro J. Nunez-Cacho Fuentes";
    public string Handle { get; set; } = "@tunelko";
    public string Blog { get; set; } = "https://blogs.tunelko.com";
    public string Email { get; set; } = "";
    public string PgpFingerprint { get; set; } = "";  // e.g. "ECFE8F52A79544C4D5CEC31D816793CF3167C4D2"
    public string PgpKeyId { get; set; } = "";        // short id, e.g. "816793CF3167C4D2"

    // INCIBE CVE ranking (see https://www.incibe.es/.../asignacion-publicacion-cve)
    public bool IncibeRankingOptIn { get; set; } = true;
    public string IncibePublicDisplayName { get; set; } = "";  // falls back to Name + Handle if empty
}

/// <summary>
/// Per-page UI state persisted across sessions so a researcher doesn't have to re-enter
/// paths/flags/combo selections every time. Written to %APPDATA%\DllSidecar\config.json
/// alongside the rest of AppConfig.
/// </summary>
public class UiStateConfig
{
    public GeneratePageState GeneratePage { get; set; } = new();
    public ScanPageState ScanPage { get; set; } = new();
    public ProcmonPageState ProcmonPage { get; set; } = new();

    public string? LastBuildDir { get; set; }
    public string? LastPrivescDir { get; set; }
    public string? LastRuntimeExePath { get; set; }
    public string? LastRuntimePid { get; set; }
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
    public bool EncryptStrings { get; set; }
    public int EntryDelayMs { get; set; }
    public int XorKeyIndex { get; set; }

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

public class XorConfig
{
    public byte DefaultKey { get; set; } = 0x5A;
    public List<byte> PresetKeys { get; set; } = [0x5A, 0xA5, 0xFF, 0x13, 0x37, 0x42, 0x69];
}

public class PathsConfig
{
    public string? LastDllPath { get; set; }
    public string? LastScanPath { get; set; }
    public string? LastOutputRoot { get; set; }
}

public class ToolsConfig
{
    // Tool-bundle directories — when set, ToolkitChecker probes these FIRST for known binaries.
    // Setting SysinternalsDir auto-resolves Procmon, sigcheck, and several other utilities.
    public string? SysinternalsDir { get; set; }         // e.g. C:\Tools\Sysinternals
    public string? ToolsRootDir { get; set; }            // generic root, probed recursively 1 level

    // Individual tool paths — override or supplement bundle-directory resolution
    public string? ProcmonPath { get; set; }             // Procmon.exe or Procmon64.exe
    public string? SigcheckPath { get; set; }            // sigcheck.exe or sigcheck64.exe
    public string? DependenciesGuiPath { get; set; }     // lucasg Dependencies
    public string? X64DbgPath { get; set; }
    public string? X32DbgPath { get; set; }
    public string? PythonPath { get; set; }
    public string? SevenZipPath { get; set; }            // 7z.exe — installer extraction
    public string? InnoUnpPath { get; set; }             // innounp.exe — Inno Setup extraction

    public string SysinternalsDownloadUrl { get; set; } = "https://download.sysinternals.com/files/SysinternalsSuite.zip";
    public string DependenciesDownloadUrl { get; set; } = "https://github.com/lucasg/Dependencies/releases";
    public string X64DbgDownloadUrl { get; set; } = "https://x64dbg.com/";
    public string SevenZipDownloadUrl { get; set; } = "https://www.7-zip.org/";
    public string InnoUnpDownloadUrl { get; set; } = "https://innounp.sourceforge.net/";

    // NVD API v2 — optional key raises rate limit from 5 req/30s to 50 req/30s
    // Register at https://nvd.nist.gov/developers/request-an-api-key
    // Stored LOCALLY in %APPDATA%\DllSidecar\config.json — never committed to source.
    public string? NvdApiKey { get; set; }
}
