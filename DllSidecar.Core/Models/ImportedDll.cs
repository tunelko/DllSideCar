namespace DllSidecar.Core.Models;

public class ImportedDll
{
    public required string DllName { get; set; }
    public List<string> Functions { get; set; } = [];
    public List<int> Ordinals { get; set; } = [];
    public bool SymbolsComplete { get; set; }
    public bool IsDelayLoad { get; set; }
}
