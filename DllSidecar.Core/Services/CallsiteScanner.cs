using System.Text;
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
        // FQN avoids the System.Text.Decoder vs Iced.Intel.Decoder ambiguity
        // we get from importing System.Text for the StringBuilder below.
        var decoder = Iced.Intel.Decoder.Create(bitness, reader, startIp, DecoderOptions.None);
        var formatter = new NasmFormatter();
        var output = new StringOutput();

        // Sliding window of recent decoded instructions, used by ExtractArgs to
        // walk back from each callsite and resolve the LoadLibrary first-arg
        // string. 16 slots is more than enough — typical arg-load → call
        // distance is 1-3 instructions; 16 covers register saves, NOP padding,
        // and short setup sequences.
        const int WindowSize = 16;
        var ring = new Instruction[WindowSize];
        var ringHead = 0;
        var ringCount = 0;

        var endIp = startIp + (ulong)rawBytes.Length;
        while (decoder.IP < endIp)
        {
            decoder.Decode(out var inst);
            if (inst.IsInvalid)
            {
                // Mid-instruction garbage poisons the window — reset.
                ringCount = 0;
                continue;
            }

            var isCallOrJmp = inst.Mnemonic == Mnemonic.Call || inst.Mnemonic == Mnemonic.Jmp;
            if (isCallOrJmp && inst.OpCount == 1 && inst.Op0Kind == OpKind.Memory)
            {
                // Resolve the absolute VA the memory operand points to. For x64
                // this is RIP-relative (Iced gives us the absolute VA via
                // IPRelativeMemoryAddress when the decoder IP was set correctly).
                // For x86 it's an absolute [imm32]. Indexed/scaled addressing is
                // ignored — IAT thunks are always plain absolute or RIP-relative.
                ulong target = 0;
                bool resolved = false;
                if (inst.IsIPRelativeMemoryOperand)
                {
                    target = inst.IPRelativeMemoryAddress;
                    resolved = true;
                }
                else if (bitness == 32
                         && inst.MemoryBase == Register.None
                         && inst.MemoryIndex == Register.None)
                {
                    target = inst.MemoryDisplacement32;
                    resolved = true;
                }

                if (resolved && iatTargets.TryGetValue(target, out var hit))
                {
                    output.Reset();
                    formatter.Format(inst, output);
                    var disasm = output.ToStringAndReset();
                    var callRva = (uint)(inst.IP - imageBase);

                    // Arg extraction is only meaningful for direct calls. A jmp
                    // through the IAT is a tail-call thunk — the caller of the
                    // thunk holds the args, not the thunk body itself.
                    string? loadedName = null;
                    uint? loadFlags = null;
                    if (inst.Mnemonic == Mnemonic.Call)
                    {
                        (loadedName, loadFlags) = ExtractArgs(
                            ring, ringHead, ringCount, hit.Api, bitness, pe, imageBase);
                    }

                    result.Add(new Callsite(
                        CallRva: callRva,
                        Mnemonic: inst.Mnemonic == Mnemonic.Call ? "call" : "jmp",
                        TargetModule: hit.Module,
                        TargetApi: hit.Api,
                        CallerHint: ResolveCallerHint(exportsByRva, callRva),
                        Disasm: disasm,
                        LoadedName: loadedName,
                        LoadFlags: loadFlags));
                }
            }

            // Push the instruction into the ring AFTER the callsite check, so
            // ExtractArgs only sees instructions BEFORE the current one.
            ring[ringHead] = inst;
            ringHead = (ringHead + 1) % WindowSize;
            if (ringCount < WindowSize) ringCount++;
        }
    }

    // ---------- Arg extraction ----------

    /// <summary>
    /// Walk the ring buffer in reverse (most recent first) looking for the
    /// instruction(s) that loaded the LoadLibrary first arg. Returns
    /// (loadedName, loadFlags) — either may be null when the arg was computed,
    /// loaded indirectly, or built on the stack (we don't simulate execution).
    ///
    /// LdrLoadDll has 4 args including a UNICODE_STRING* — we don't unpack that
    /// structure in v1 and return (null, null) for it.
    /// </summary>
    private static (string? Name, uint? Flags) ExtractArgs(
        Instruction[] ring, int head, int count,
        string apiName, int bitness, PeFile pe, ulong imageBase)
    {
        if (apiName.Equals("LdrLoadDll", StringComparison.OrdinalIgnoreCase))
            return (null, null);

        var isWide = apiName.EndsWith("W", StringComparison.Ordinal);
        var isLoadEx = apiName.StartsWith("LoadLibraryEx", StringComparison.OrdinalIgnoreCase);

        if (bitness == 64)
            return ExtractArgsX64(ring, head, count, isWide, isLoadEx, pe, imageBase);
        return ExtractArgsX86(ring, head, count, isWide, pe, imageBase);
    }

    /// <summary>
    /// x64 calling convention: arg1 in RCX (string ptr), arg3 in R8 (flags for
    /// LoadLibraryEx). We look for the most recent write to each. The string
    /// usually comes via 'lea rcx, [rip+disp]' (string is in .rdata) or
    /// 'mov rcx, imm64'. The flags usually come via 'mov r8d, imm32' or
    /// 'xor r8d, r8d' (= 0).
    /// </summary>
    private static (string? Name, uint? Flags) ExtractArgsX64(
        Instruction[] ring, int head, int count, bool isWide, bool isLoadEx,
        PeFile pe, ulong imageBase)
    {
        string? name = null;
        uint? flags = null;
        var rcxResolved = false;
        var r8Resolved = !isLoadEx; // skip R8 chase for non-Ex APIs

        for (var i = 1; i <= count; i++)
        {
            // i-th most-recent slot. ring is a circular buffer with head =
            // index of the next *empty* slot, so the most recent valid entry is
            // at (head - 1).
            var idx = (head - i + ring.Length) % ring.Length;
            ref readonly var prior = ref ring[idx];

            if (!rcxResolved && WritesRegisterFamily(prior, Register.RCX))
            {
                name = TryReadStringArg(prior, pe, imageBase, isWide);
                rcxResolved = true;
            }
            if (!r8Resolved && WritesRegisterFamily(prior, Register.R8))
            {
                flags = TryReadImmediateArg(prior);
                r8Resolved = true;
            }
            if (rcxResolved && r8Resolved) break;
        }

        return (name, flags);
    }

    /// <summary>
    /// x86 stdcall: args pushed right-to-left, so the push immediately before
    /// the call is arg1. We walk back to the closest push imm32 and read the
    /// pointed-to string. Skipping x86 flags extraction in v1 — would need to
    /// count pushes through reserved-arg=0 etc.
    /// </summary>
    private static (string? Name, uint? Flags) ExtractArgsX86(
        Instruction[] ring, int head, int count, bool isWide,
        PeFile pe, ulong imageBase)
    {
        for (var i = 1; i <= count; i++)
        {
            var idx = (head - i + ring.Length) % ring.Length;
            ref readonly var prior = ref ring[idx];

            // Stop at any control transfer — arguments don't survive across them.
            if (prior.FlowControl != FlowControl.Next) return (null, null);

            if (prior.Mnemonic == Mnemonic.Push && IsImmediateOpKind(prior.Op0Kind))
            {
                var stringVa = prior.GetImmediate(0);
                if (stringVa < imageBase) return (null, null);
                var rva = (uint)(stringVa - imageBase);
                return (ReadStringFromRva(pe, rva, isWide), null);
            }
        }
        return (null, null);
    }

    /// <summary>
    /// True when the instruction's destination register is in the same family
    /// as <paramref name="canonical"/> — i.e. RCX/ECX/CX/CL all count as a
    /// write to RCX. Iced's GetInfo()/UsedRegisters has full info but this
    /// covers our patterns without the extra allocations.
    /// </summary>
    private static bool WritesRegisterFamily(in Instruction inst, Register canonical)
    {
        if (inst.OpCount == 0 || inst.Op0Kind != OpKind.Register) return false;
        return RegisterCanonical(inst.Op0Register) == canonical;
    }

    private static Register RegisterCanonical(Register r) => r switch
    {
        Register.ECX or Register.CX or Register.CL or Register.CH => Register.RCX,
        Register.R8D or Register.R8W or Register.R8L => Register.R8,
        Register.EAX or Register.AX or Register.AL or Register.AH => Register.RAX,
        Register.EDX or Register.DX or Register.DL or Register.DH => Register.RDX,
        _ => r,
    };

    private static string? TryReadStringArg(in Instruction prior, PeFile pe, ulong imageBase, bool isWide)
    {
        // 'lea reg, [rip+disp]' — the canonical "string lives in .rdata" pattern.
        if (prior.Mnemonic == Mnemonic.Lea && prior.Op1Kind == OpKind.Memory && prior.IsIPRelativeMemoryOperand)
        {
            var stringVa = prior.IPRelativeMemoryAddress;
            if (stringVa < imageBase) return null;
            return ReadStringFromRva(pe, (uint)(stringVa - imageBase), isWide);
        }
        // 'mov reg, imm' — direct address. Less common for strings, more common
        // for handles, but cheap to check.
        if (prior.Mnemonic == Mnemonic.Mov && IsImmediateOpKind(prior.Op1Kind))
        {
            var stringVa = prior.GetImmediate(1);
            if (stringVa < imageBase) return null;
            return ReadStringFromRva(pe, (uint)(stringVa - imageBase), isWide);
        }
        return null;
    }

    private static uint? TryReadImmediateArg(in Instruction prior)
    {
        // 'mov r8d, imm32' — flags constant.
        if (prior.Mnemonic == Mnemonic.Mov && IsImmediateOpKind(prior.Op1Kind))
            return (uint)prior.GetImmediate(1);
        // 'xor r8d, r8d' — flags = 0 (the dangerous default for LoadLibraryEx,
        // means "behave like LoadLibrary" → search-order resolution).
        if (prior.Mnemonic == Mnemonic.Xor
            && prior.Op1Kind == OpKind.Register
            && RegisterCanonical(prior.Op1Register) == RegisterCanonical(prior.Op0Register))
            return 0;
        return null;
    }

    private static bool IsImmediateOpKind(OpKind k) => k
        is OpKind.Immediate8 or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64
        or OpKind.Immediate8to16 or OpKind.Immediate8to32 or OpKind.Immediate8to64
        or OpKind.Immediate32to64;

    /// <summary>
    /// Resolve an RVA to a file offset (via section table) and read a
    /// null-terminated string. Wide → UTF-16 LE. Returns null when the RVA
    /// falls outside any section, the string is empty, or the bytes don't
    /// look like printable ASCII (good enough for DLL names; rejects garbage).
    /// </summary>
    private static string? ReadStringFromRva(PeFile pe, uint rva, bool isWide)
    {
        if (pe.ImageSectionHeaders == null) return null;
        long offset = -1;
        long sectionLimit = 0;
        foreach (var s in pe.ImageSectionHeaders)
        {
            var virtualEnd = s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= s.VirtualAddress && rva < virtualEnd)
            {
                offset = s.PointerToRawData + (rva - s.VirtualAddress);
                sectionLimit = s.PointerToRawData + s.SizeOfRawData;
                break;
            }
        }
        if (offset < 0) return null;

        // PeNet 5 exposes the file as an IRawFile (no direct indexer); read a
        // bounded chunk and walk the byte buffer instead. MaxLen*2 covers wide
        // chars plus the terminator slop.
        const int MaxLen = 260;
        var maxBytes = (long)(MaxLen * (isWide ? 2 : 1) + 2);
        var available = Math.Min(maxBytes, sectionLimit - offset);
        if (available <= 0) return null;

        byte[] data;
        try { data = pe.RawFile.AsSpan(offset, (int)available).ToArray(); }
        catch { return null; }

        var sb = new StringBuilder(32);
        if (isWide)
        {
            for (var i = 0; i + 1 < data.Length; i += 2)
            {
                var cu = (ushort)(data[i] | (data[i + 1] << 8));
                if (cu == 0) break;
                if (cu < 0x20 || cu > 0x7E) return null;
                sb.Append((char)cu);
            }
        }
        else
        {
            for (var i = 0; i < data.Length; i++)
            {
                var b = data[i];
                if (b == 0) break;
                if (b < 0x20 || b > 0x7E) return null;
                sb.Append((char)b);
            }
        }
        return sb.Length > 0 ? sb.ToString() : null;
    }
}
