namespace DllSidecar.Core.Models;

public enum ExtractionMethod { None, SevenZip, MsiExec, InnoUnp }

public class InstallerExtractionResult
{
    public bool Success { get; set; }
    public string? OutputDir { get; set; }
    public ExtractionMethod MethodUsed { get; set; }
    public List<string> Logs { get; set; } = [];
    public string? ErrorMessage { get; set; }
    public int FilesExtracted { get; set; }
    public long TotalBytesExtracted { get; set; }
}
