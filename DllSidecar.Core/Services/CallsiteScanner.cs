using Iced.Intel;
using PeNet;
using PeNet.Header.Pe;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Disassembles a PE's executable sections and reports every indirect call/jmp
/// that resolves through the Import Address Table to one of the dynamic-loading
/// APIs we care about (LoadLibrary*, LdrLoadDll, GetModuleHandle*).
///
/// Why: the static IAT view (PeAnalyzer) tells us a DLL *imports* LoadLibraryW,
/// but not *where* it's called or *what string* it loads. A callsite list lets
/// us follow the chain — and a hardcoded LoadLibraryW("amfrt64.dll") right next
/// to a sideload-able directory is a much stronger signal than "imports it".
///
/// Port-of-origin: SandboxEscaper, "Windows filesystem – Enumerating the attack
/// surface" (Patreon, 2026). Original was Python + capstone for CreateFile.
/// We swap capstone for Iced (native .NET disassembler) and the API list for
/// loader-targeting calls.
/// </summary>
public static class CallsiteScanner
{
    /// <summary>
    /// APIs whose callsites we want to flag. All resolve through the standard
    /// Win32/NT loader. NOT exhaustive — feel free to extend per investigation.
    /// </summary>
    public static readonly IReadOnlySet<string> DefaultLoaderApis = new HashSet<string>(
        StringComparer.OrdinalIgnoreCase)
    {
        "LoadLibraryA", "LoadLibraryW",
        "LoadLibraryExA", "LoadLibraryExW",
        "LdrLoadDll",
        "GetModuleHandleA", "GetModuleHandleW",
        "GetModuleHandleExA", "GetModuleHandleExW",
    };

    /// <summary>
    /// Scan <paramref name="pePath"/> and return every callsite to one of
    /// <paramref name="apiNames"/> (defaults to <see cref="DefaultLoaderApis"/>),
    /// plus the imports we tracked so callers can tell apart "no relevant
    /// imports" from "imports exist but no callsite found".
    ///
    /// arm64 returns empty (Iced is x86/x64 only). Caller should check
    /// PeAnalysis.Arch first if it wants to surface a friendly message.
    /// </summary>
    public static CallsiteScanResult Scan(string pePath, IReadOnlySet<string>? apiNames = null)
    {
        apiNames ??= DefaultLoaderApis;
        var pe = new PeFile(pePath);
        return Scan(pe, apiNames);
    }

    public static CallsiteScanResult Scan(PeFile pe, IReadOnlySet<string> apiNames)
    {
        var callsites = new List<Callsite>();
        var tracked = new Dictionary<string, int>();
        if (pe.ImageNtHeaders == null) return new CallsiteScanResult(callsites, tracked);

        var machine = pe.ImageNtHeaders.FileHeader.Machine;
        var bitness = machine switch
        {
            MachineType.I386 => 32,
            MachineType.Amd64 => 64,
            _ => 0, // arm64, ia64, etc. — Iced doesn't support them
        };
        if (bitness == 0) return new CallsiteScanResult(callsites, tracked);

        var imageBase = pe.ImageNtHeaders.OptionalHeader.ImageBase;

        // 1) Build a map: IAT slot virtual address (image_base + RVA) → (module, api).
        //    Also populate the diagnostic dict so the caller can render a
        //    "imports tracked: kernel32.dll!LoadLibraryW=1, ..." line.
        var iatTargets = BuildIatTargetMap(pe, apiNames, imageBase, tracked);
        if (iatTargets.Count == 0) return new CallsiteScanResult(callsites, tracked);

        // 2) Build an export map for caller-name resolution. Keyed by RVA;
        //    we use the export whose RVA is the largest <= the call RVA as a
        //    coarse "caller is somewhere inside this exported function" hint.
        //    No PDB → no precise function names — exports are the next-best signal.
        var exportsByRva = pe.ExportedFunctions == null
            ? new SortedDictionary<uint, string>()
            : BuildExportRvaMap(pe.ExportedFunctions);

        // 3) For each executable section, disassemble and collect call/jmp
        //    instructions whose memory operand resolves to a tracked IAT slot.
        var sections = pe.ImageSectionHeaders ?? [];
        foreach (var sec in sections)
        {
            if (!IsExecutable(sec)) continue;
            ScanSection(pe, sec, bitness, imageBase, iatTargets, exportsByRva, callsites);
        }

        return new CallsiteScanResult(callsites, tracked);
    }

    // ---------- IAT slot map ----------

    private static Dictionary<ulong, (string Module, string Api)> BuildIatTargetMap(
        PeFile pe, IReadOnlySet<string> apiNames, ulong imageBase,
        Dictionary<string, int> tracked)
    {
        var map = new Dictionary<ulong, (string, string)>();
        if (pe.ImportedFunctions == null) return map;

        foreach (var imp in pe.ImportedFunctions)
        {
            if (string.IsNullOrEmpty(imp.Name) || string.IsNullOrEmpty(imp.DLL)) continue;
            if (!apiNames.Contains(imp.Name)) continue;

            // PeNet 5: ImportedFunction.IATOffset is the RVA of the IAT slot
            // within the loaded image. Combined with imageBase this is the VA
            // the call instruction's memory operand will reference.
            var slotVa = imageBase + imp.IATOffset;
            map[slotVa] = (imp.DLL!, imp.Name!);

            // Populate the diagnostic dict — keyed "module!api" so the same
            // API imported from two different forwarders (kernel32 + api-ms-...)
            // shows up as two distinct lines.
            var key = $"{imp.DLL}!{imp.Name}";
            tracked.TryGetValue(key, out var n);
            tracked[key] = n + 1;
        }
        return map;
    }

    // ---------- Export RVA map ----------

    private static SortedDictionary<uint, string> BuildExportRvaMap(ExportFunction[] exports)
    {
        var map = new SortedDictionary<uint, string>();
        foreach (var exp in exports)
        {
            if (exp.Name == null) continue;
            if (exp.HasForward) continue;
            // Multiple ordinals can alias the same RVA — first one wins, that's
            // fine for a "nearest export" hint.
            if (!map.ContainsKey(exp.Address))
                map[exp.Address] = exp.Name;
        }
        return map;
    }

    private static string ResolveCallerHint(SortedDictionary<uint, string> exportsByRva, uint callRva)
    {
        if (exportsByRva.Count == 0) return "<no exports>";
        // Largest export RVA that is <= call RVA. SortedDictionary doesn't
        // expose floor lookup, so linear scan from largest down. Export tables
        // rarely exceed a few thousand entries — well within budget.
        string? best = null;
        uint bestRva = 0;
        foreach (var kv in exportsByRva)
        {
            if (kv.Key > callRva) break;
            best = kv.Value;
            bestRva = kv.Key;
        }
        if (best == null) return "<before first export>";
        return $"{best}+0x{callRva - bestRva:X}";
    }

    // ---------- Section disassembly ----------

    private static bool IsExecutable(ImageSectionHeader sec) =>
        (sec.Characteristics & ScnCharacteristicsType.MemExecute) != 0;

    private static void ScanSection(
        PeFile pe,
        ImageSectionHeader sec,
        int bitness,
        ulong imageBase,
        Dictionary<ulong, (string Module, string Api)> iatTargets,
        SortedDictionary<uint, string> exportsByRva,
        List<Callsite> result)
    {
        // VirtualSize can be > SizeOfRawData when the section has uninitialized
        // tail; we can only disassemble the bytes we have.
        var rawSize = (int)Math.Min(sec.SizeOfRawData, sec.VirtualSize == 0 ? sec.SizeOfRawData : sec.VirtualSize);
        if (rawSize <= 0) return;

        var fileOffset = (int)sec.PointerToRawData;
        var rawBytes = pe.RawFile.AsSpan(fileOffset, rawSize).ToArray();

        var startIp = imageBase + sec.VirtualAddress;
        var reader = new ByteArrayCodeReader(rawBytes);
        var decoder = Decoder.Create(bitness, reader, startIp, DecoderOptions.None);
        var formatter = new NasmFormatter();
        var output = new StringOutput();

        var endIp = startIp + (ulong)rawBytes.Length;
        while (decoder.IP < endIp)
        {
            decoder.Decode(out var inst);
            if (inst.IsInvalid) continue;
            if (inst.Mnemonic != Mnemonic.Call && inst.Mnemonic != Mnemonic.Jmp) continue;
            if (inst.OpCount != 1 || inst.Op0Kind != OpKind.Memory) continue;

            // Resolve the absolute VA the memory operand points to. For x64 this
            // is RIP-relative (Iced gives us the absolute VA via
            // IPRelativeMemoryAddress when the decoder IP was set correctly).
            // For x86 it's an absolute [imm32]. Indexed/scaled addressing is
            // ignored — IAT thunks are always plain absolute or RIP-relative.
            ulong target;
            if (inst.IsIPRelativeMemoryOperand)
            {
                target = inst.IPRelativeMemoryAddress;
            }
            else if (bitness == 32
                     && inst.MemoryBase == Register.None
                     && inst.MemoryIndex == Register.None)
            {
                target = inst.MemoryDisplacement32;
            }
            else continue;

            if (!iatTargets.TryGetValue(target, out var hit)) continue;

            // Format the instruction for display in the results grid.
            output.Reset();
            formatter.Format(inst, output);
            var disasm = output.ToStringAndReset();

            var callRva = (uint)(inst.IP - imageBase);
            result.Add(new Callsite(
                CallRva: callRva,
                Mnemonic: inst.Mnemonic == Mnemonic.Call ? "call" : "jmp",
                TargetModule: hit.Module,
                TargetApi: hit.Api,
                CallerHint: ResolveCallerHint(exportsByRva, callRva),
                Disasm: disasm));
        }
    }
}
