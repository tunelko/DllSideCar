namespace DllSidecar.Core.Models;

public class PeAnalysis
{
    public required string Path { get; set; }
    public required string Filename { get; set; }
    public required string Arch { get; set; }
    public ushort Machine { get; set; }
    public bool IsDll { get; set; }
    public List<ExportEntry> Exports { get; set; } = [];
    public int NamedExports { get; set; }
    public int OrdinalOnlyExports { get; set; }
    public SecurityFlags Security { get; set; } = new();
    public long FileSize { get; set; }
    public ushort Subsystem { get; set; }
    public string OriginalFilename { get; set; } = "";
    public string FileVersion { get; set; } = "";
    public string ProductName { get; set; } = "";
    public string CompanyName { get; set; } = "";

    public List<ImportedDll> Imports { get; set; } = [];
}
