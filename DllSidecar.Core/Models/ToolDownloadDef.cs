namespace DllSidecar.Core.Models;

/// <summary>Describes a tool downloadable from a whitelisted ZIP URL; extracted binaries are Authenticode-verified.</summary>
public class ToolDownloadDef
{
    public required string Id { get; set; }
    public required string DisplayName { get; set; }
    public required string Url { get; set; }               // HTTPS-only
    public required long MaxSizeBytes { get; set; }
    public required string InstallSubdir { get; set; }     // under %LOCALAPPDATA%\DllSidecar\tools\
    public List<string> BinariesToVerify { get; set; } = [];
    public Dictionary<string, string> ConfigUpdates { get; set; } = [];
}
