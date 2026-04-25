using PeNet;
using PeNet.Header.Pe;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

public static class PeAnalyzer
{
    private const ushort DllCharDynamicBase = 0x0040;
    private const ushort DllCharHighEntropyVa = 0x0020;
    private const ushort DllCharNxCompat = 0x0100;
    private const ushort DllCharForceIntegrity = 0x0080;
    private const ushort DllCharGuardCf = 0x4000;

    public static PeAnalysis Analyze(string filepath)
    {
        var pe = new PeFile(filepath);
        var filename = Path.GetFileName(filepath);

        var machine = pe.ImageNtHeaders!.FileHeader.Machine;
        var arch = machine switch
        {
            MachineType.I386 => "x86",
            MachineType.Amd64 => "x64",
            MachineType.Arm64 => "arm64",
            _ => $"unknown_{(ushort)machine:x}"
        };

        var isDll = (pe.ImageNtHeaders.FileHeader.Characteristics & FileCharacteristicsType.Dll) != 0;

        var analysis = new PeAnalysis
        {
            Path = filepath,
            Filename = filename,
            Arch = arch,
            Machine = (ushort)machine,
            IsDll = isDll,
            FileSize = new FileInfo(filepath).Length,
            Subsystem = (ushort)pe.ImageNtHeaders.OptionalHeader.Subsystem,
        };

        // Security flags
        var dllChars = (ushort)pe.ImageNtHeaders.OptionalHeader.DllCharacteristics;
        analysis.Security.Aslr = (dllChars & DllCharDynamicBase) != 0;
        analysis.Security.HighEntropyAslr = (dllChars & DllCharHighEntropyVa) != 0;
        analysis.Security.Dep = (dllChars & DllCharNxCompat) != 0;
        analysis.Security.ForceIntegrity = (dllChars & DllCharForceIntegrity) != 0;
        analysis.Security.Cfg = (dllChars & DllCharGuardCf) != 0;

        // DependentLoadFlags from LoadConfig
        if (pe.ImageLoadConfigDirectory != null)
        {
            var lc = pe.ImageLoadConfigDirectory;
            // PeNet exposes DependentLoadFlags in newer versions
            // Fall back to 0 if not available
            analysis.Security.DependentLoadFlags = 0;
        }

        // Version info
        var resources = pe.Resources;
        if (resources?.VsVersionInfo != null)
        {
            var vi = resources.VsVersionInfo;
            if (vi.StringFileInfo?.StringTable is { Length: > 0 } tables)
            {
                var st = tables[0];
                analysis.OriginalFilename = st.OriginalFilename ?? "";
                analysis.FileVersion = st.FileVersion ?? "";
                analysis.ProductName = st.ProductName ?? "";
                analysis.CompanyName = st.CompanyName ?? "";
            }
        }

        // Exports
        if (pe.ExportedFunctions is { Length: > 0 })
        {
            foreach (var exp in pe.ExportedFunctions)
            {
                var entry = new ExportEntry
                {
                    Ordinal = (int)exp.Ordinal,
                    Name = exp.Name,
                    Rva = exp.Address,
                    ForwardedTo = exp.HasForward ? exp.ForwardName : null,
                };
                analysis.Exports.Add(entry);

                if (exp.Name != null)
                    analysis.NamedExports++;
                else
                    analysis.OrdinalOnlyExports++;
            }
        }

        // Imports (regular IAT)
        if (pe.ImportedFunctions is { Length: > 0 })
        {
            var grouped = pe.ImportedFunctions
                .Where(i => !string.IsNullOrEmpty(i.DLL))
                .GroupBy(i => i.DLL!, StringComparer.OrdinalIgnoreCase);

            foreach (var g in grouped)
            {
                var imp = new ImportedDll { DllName = g.Key };
                foreach (var fn in g)
                    if (!string.IsNullOrEmpty(fn.Name))
                        imp.Functions.Add(fn.Name);
                analysis.Imports.Add(imp);
            }
        }

        // Delay-load imports
        try
        {
            var delay = pe.ImageDelayImportDescriptors;
            if (delay is { Length: > 0 })
            {
                foreach (var d in delay)
                {
                    // PeNet 5.0: delay-load descriptor exposes name via SzName (raw field) — resolve via RVA
                    var name = ResolveDelayDllName(pe, d);
                    if (string.IsNullOrEmpty(name)) continue;
                    var existing = analysis.Imports.FirstOrDefault(
                        i => string.Equals(i.DllName, name, StringComparison.OrdinalIgnoreCase));
                    if (existing != null)
                    {
                        existing.IsDelayLoad = true;
                    }
                    else
                    {
                        analysis.Imports.Add(new ImportedDll { DllName = name, IsDelayLoad = true });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // Delay-load parsing varies across PeNet versions and is best-effort
            Log.Debug("pe.delay", $"Delay-load descriptor parsing failed for {filename}", ex);
        }

        return analysis;
    }

    private static string? ResolveDelayDllName(PeFile pe, object descriptor)
    {
        // PeNet 5.0 exposes SzName as an RVA (uint) in ImageDelayImportDescriptor.
        // Resolve RVA→file offset and read zero-terminated ASCII.
        try
        {
            var prop = descriptor.GetType().GetProperty("SzName");
            if (prop?.GetValue(descriptor) is not uint rva || rva == 0) return null;
            var sections = pe.ImageSectionHeaders;
            if (sections == null) return null;

            var offset = (long)((ulong)rva).RvaToOffset(sections);
            var raw = pe.RawFile;
            var total = raw.Length;
            int maxLen = 256;
            long available = total - offset;
            if (available <= 0) return null;
            int take = (int)Math.Min(available, maxLen);
            var bytes = raw.AsSpan(offset, take).ToArray();
            int end = 0;
            while (end < bytes.Length && bytes[end] != 0) end++;
            return System.Text.Encoding.ASCII.GetString(bytes, 0, end);
        }
        catch (Exception ex)
        {
            Log.Debug("pe.delay", "Failed to resolve delay DLL name from RVA", ex);
            return null;
        }
    }

    public static Dictionary<string, string> ExtractVersionInfo(string filepath)
    {
        var pe = new PeFile(filepath);
        var info = new Dictionary<string, string>();

        var resources = pe.Resources;
        if (resources?.VsVersionInfo != null)
        {
            var vi = resources.VsVersionInfo;

            // String table entries
            if (vi.StringFileInfo?.StringTable is { Length: > 0 } tables)
            {
                var st = tables[0];
                if (st.CompanyName != null) info["CompanyName"] = st.CompanyName;
                if (st.FileDescription != null) info["FileDescription"] = st.FileDescription;
                if (st.FileVersion != null) info["FileVersion"] = st.FileVersion;
                if (st.InternalName != null) info["InternalName"] = st.InternalName;
                if (st.LegalCopyright != null) info["LegalCopyright"] = st.LegalCopyright;
                if (st.OriginalFilename != null) info["OriginalFilename"] = st.OriginalFilename;
                if (st.ProductName != null) info["ProductName"] = st.ProductName;
                if (st.ProductVersion != null) info["ProductVersion"] = st.ProductVersion;
            }

            // Fixed file info
            if (vi.VsFixedFileInfo != null)
            {
                var ffi = vi.VsFixedFileInfo;
                info["_file_version"] = $"{(ffi.DwFileVersionMS >> 16) & 0xFFFF}," +
                    $"{ffi.DwFileVersionMS & 0xFFFF}," +
                    $"{(ffi.DwFileVersionLS >> 16) & 0xFFFF}," +
                    $"{ffi.DwFileVersionLS & 0xFFFF}";
                info["_product_version"] = $"{(ffi.DwProductVersionMS >> 16) & 0xFFFF}," +
                    $"{ffi.DwProductVersionMS & 0xFFFF}," +
                    $"{(ffi.DwProductVersionLS >> 16) & 0xFFFF}," +
                    $"{ffi.DwProductVersionLS & 0xFFFF}";
                info["_file_os"] = $"0x{ffi.DwFileOS:x}";
                info["_file_type"] = $"0x{ffi.DwFileType:x}";
            }
        }

        return info;
    }
}
