namespace DllSidecar.Core.Models;

public class ImportedDll
{
    public required string DllName { get; set; }
    public List<string> Functions { get; set; } = [];
    public bool IsDelayLoad { get; set; }
}
