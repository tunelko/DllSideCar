namespace DllSidecar.Core.Models;

/// <summary>
/// Describes a tool that can be downloaded and installed automatically. The URL must point
/// to a ZIP archive hosted on a whitelisted domain. Post-extract, extracted binaries matching
/// <see cref="BinariesToVerify"/> are verified via Authenticode — if ANY fails, the install
/// aborts.
/// </summary>
public class ToolDownloadDef
{
    public required string Id { get; set; }                // internal key — e.g. "sysinternals-suite"
    public required string DisplayName { get; set; }       // UI label
    public required string Url { get; set; }               // HTTPS-only
    public required long MaxSizeBytes { get; set; }        // hard limit before downloading
    public required string InstallSubdir { get; set; }     // under %LOCALAPPDATA%\DllSidecar\tools\
    public List<string> BinariesToVerify { get; set; } = []; // filenames that MUST be Authenticode-valid
    public Dictionary<string, string> ConfigUpdates { get; set; } = [];
        // Keys: "SysinternalsDir", "ProcmonPath", "SigcheckPath", etc
        // Values: relative path inside InstallSubdir (empty string = InstallSubdir itself for dir keys)
}
