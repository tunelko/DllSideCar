using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

public static class ProxyCompatibilityAnalyzer
{
    public static ProxyReadiness Evaluate(PeAnalysis importer, string dllName, PeAnalysis? target)
    {
        var requirements = importer.Imports.Where(i => i.DllName.Equals(dllName, StringComparison.OrdinalIgnoreCase)).ToList();
        var names = requirements.SelectMany(i => i.Functions).Distinct(StringComparer.Ordinal).ToList();
        var ordinals = requirements.SelectMany(i => i.Ordinals).Distinct().ToList();
        var result = new ProxyReadiness
        {
            Required = names.Count + ordinals.Count, OrdinalImports = ordinals.Count,
            TotalExports = target?.Exports.Count ?? 0,
        };
        if (target == null)
        {
            result.Reason = "No reference DLL available for comparison";
            return result;
        }
        if (!importer.Arch.Equals(target.Arch, StringComparison.OrdinalIgnoreCase))
        {
            result.Level = ProxyReadinessLevel.Unsafe;
            result.Reason = $"Architecture mismatch: {importer.Arch} importer / {target.Arch} DLL";
            return result;
        }
        foreach (var name in names)
            Check(name, target.Exports.FirstOrDefault(e => e.Name == name));
        foreach (var ordinal in ordinals)
            Check($"#{ordinal}", target.Exports.FirstOrDefault(e => e.Ordinal == ordinal));

        if (result.Missing.Count > 0)
        {
            result.Level = ProxyReadinessLevel.Unsafe;
            result.Reason = "Missing exports: " + string.Join(", ", result.Missing);
        }
        else if (requirements.Count == 0 || result.Required == 0 || requirements.Any(i => !i.SymbolsComplete))
        {
            result.Level = ProxyReadinessLevel.Partial;
            result.Reason = "Import requirements incomplete; runtime GetProcAddress requests remain unknown";
        }
        else if (result.Forwarded > 0)
        {
            result.Level = ProxyReadinessLevel.Partial;
            result.Reason = "Export entries exist; forwarded destinations have not been validated";
        }
        else
        {
            result.Level = ProxyReadinessLevel.Ready;
            result.Reason = "Static export coverage only; ABI, runtime lookups and application stability still require validation";
        }
        return result;

        void Check(string label, ExportEntry? export)
        {
            if (export == null || (export.Rva == 0 && !export.IsForwarded)) result.Missing.Add(label);
            else { result.Matched++; if (export.IsForwarded) result.Forwarded++; }
        }
    }
}
