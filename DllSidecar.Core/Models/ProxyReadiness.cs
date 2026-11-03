namespace DllSidecar.Core.Models;

public enum ProxyReadinessLevel { Unknown, Ready, Partial, Unsafe }

public sealed class ProxyReadiness
{
    public ProxyReadinessLevel Level { get; set; }
    public int Required { get; set; }
    public int Matched { get; set; }
    public int OrdinalImports { get; set; }
    public int Forwarded { get; set; }
    public int TotalExports { get; set; }
    public List<string> Missing { get; set; } = [];
    public string Reason { get; set; } = "Import/export coverage has not been evaluated";
    public string Label => Level.ToString().ToUpperInvariant();
    public string Summary => $"{Label}: {Matched}/{Required} required symbols; " +
        $"{OrdinalImports} ordinals, {Forwarded} forwarders, {TotalExports} total exports. {Reason}";
}
