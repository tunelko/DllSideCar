namespace DllSidecar.Core.Models;

public class ExportEntry
{
    public int Ordinal { get; set; }
    public string? Name { get; set; }
    public uint Rva { get; set; }
    public string? ForwardedTo { get; set; }

    public string DisplayName => Name ?? $"ord_{Ordinal}";
    public bool IsForwarded => ForwardedTo is not null;
}
