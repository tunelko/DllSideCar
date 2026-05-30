using System.Text;
using Iced.Intel;
using PeNet;
using PeNet.Header.Pe;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Disassembles a PE and reports every indirect call/jmp through the IAT to LoadLibrary*, LdrLoadDll, or GetModuleHandle*.
/// </summary>
public static class CallsiteScanner
{
    /// <summary>
    /// Loader APIs whose callsites are flagged.
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
    /// Scan <paramref name="pePath"/> for callsites to the given APIs (Iced is x86/x64 only; arm64 returns empty).
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

        // 1) Map IAT slot VA -> (module, api); also populate diagnostic counts.
        var iatTargets = BuildIatTargetMap(pe, apiNames, imageBase, bitness, tracked);
        if (iatTargets.Count == 0) return new CallsiteScanResult(callsites, tracked);

        // 2) Export RVA map for nearest-export caller-name hints (no PDB).
        var exportsByRva = pe.ExportedFunctions == null
            ? new SortedDictionary<uint, string>()
            : BuildExportRvaMap(pe.ExportedFunctions);

        // 3) Disassemble each executable section, collecting call/jmp through tracked IAT slots.
        var sections = pe.ImageSectionHeaders ?? [];
        foreach (var sec in sections)
        {
            if (!IsExecutable(sec)) continue;
            ScanSection(pe, sec, bitness, imageBase, iatTargets, exportsByRva, callsites);
        }

        return new CallsiteScanResult(callsites, tracked);
    }

    // ---------- IAT slot map ----------

    /// <summary>
    /// Walk import descriptors directly so slot VAs match what Iced reads from call operands.
    /// </summary>
    private static Dictionary<ulong, (string Module, string Api)> BuildIatTargetMap(
        PeFile pe, IReadOnlySet<string> apiNames, ulong imageBase, int bitness,
        Dictionary<string, int> tracked)
    {
        var map = new Dictionary<ulong, (string, string)>();
        var descs = pe.ImageImportDescriptors;
        if (descs == null || descs.Length == 0) return map;

        var thunkSize = (uint)(bitness == 64 ? 8 : 4);
        var ordinalFlag = bitness == 64 ? 0x8000000000000000UL : 0x80000000UL;

        foreach (var desc in descs)
        {
            if (desc.FirstThunk == 0) continue;

            var dllName = ReadAsciiAtRva(pe, desc.Name);
            if (string.IsNullOrEmpty(dllName)) continue;

            // Prefer OriginalFirstThunk (INT); fall back to FirstThunk on-disk.
            var nameTableRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;

            for (uint i = 0; i < 65536; i++)
            {
                var thunk = ReadThunkAtRva(pe, nameTableRva + i * thunkSize, bitness);
                if (thunk == null || thunk.Value == 0) break;

                // Ordinal-only imports have no name to match — skip.
                if ((thunk.Value & ordinalFlag) != 0) continue;

                // Named import: low bits -> IMAGE_IMPORT_BY_NAME; skip 2-byte Hint.
                var fnName = ReadAsciiAtRva(pe, (uint)thunk.Value + 2);
                if (string.IsNullOrEmpty(fnName)) continue;
                if (!apiNames.Contains(fnName)) continue;

                var slotVa = imageBase + desc.FirstThunk + i * thunkSize;
                map[slotVa] = (dllName, fnName);

                var key = $"{dllName}!{fnName}";
                tracked.TryGetValue(key, out var n);
                tracked[key] = n + 1;
            }
        }
        return map;
    }

    /// <summary>Read a null-terminated printable-ASCII string at the given RVA.</summary>
    private static string? ReadAsciiAtRva(PeFile pe, uint rva, int maxLen = 512)
    {
        var off = RvaToFileOffsetUnchecked(pe, rva);
        if (off < 0) return null;
        try
        {
            var available = (int)Math.Min(maxLen, pe.RawFile.Length - off);
            if (available <= 0) return null;
            var data = pe.RawFile.AsSpan(off, available).ToArray();
            var sb = new StringBuilder(32);
            for (var i = 0; i < data.Length; i++)
            {
                var b = data[i];
                if (b == 0) break;
                if (b < 0x20 || b > 0x7E) return null;
                sb.Append((char)b);
            }
            return sb.Length > 0 ? sb.ToString() : null;
        }
        catch { return null; }
    }

    /// <summary>Read one IAT/INT thunk (4 or 8 bytes); null on OOB.</summary>
    private static ulong? ReadThunkAtRva(PeFile pe, uint rva, int bitness)
    {
        var off = RvaToFileOffsetUnchecked(pe, rva);
        if (off < 0) return null;
        var size = bitness == 64 ? 8 : 4;
        try
        {
            if (off + size > pe.RawFile.Length) return null;
            var data = pe.RawFile.AsSpan(off, size).ToArray();
            return bitness == 64 ? BitConverter.ToUInt64(data, 0) : BitConverter.ToUInt32(data, 0);
        }
        catch { return null; }
    }

    private static long RvaToFileOffsetUnchecked(PeFile pe, uint rva)
    {
        if (pe.ImageSectionHeaders == null) return -1;
        foreach (var s in pe.ImageSectionHeaders)
        {
            var virtualEnd = s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= s.VirtualAddress && rva < virtualEnd)
                return s.PointerToRawData + (rva - s.VirtualAddress);
        }
        return -1;
    }

    // ---------- Export RVA map ----------

    private static SortedDictionary<uint, string> BuildExportRvaMap(ExportFunction[] exports)
    {
        var map = new SortedDictionary<uint, string>();
        foreach (var exp in exports)
        {
            if (exp.Name == null) continue;
            if (exp.HasForward) continue;
            // First export at an RVA wins for the nearest-export hint.
            if (!map.ContainsKey(exp.Address))
                map[exp.Address] = exp.Name;
        }
        return map;
    }

    private static string ResolveCallerHint(SortedDictionary<uint, string> exportsByRva, uint callRva)
    {
        if (exportsByRva.Count == 0) return "<no exports>";
        // Find largest export RVA <= call RVA (no floor-lookup on SortedDictionary).
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
        // Disassemble only the raw bytes present on disk.
        var rawSize = (int)Math.Min(sec.SizeOfRawData, sec.VirtualSize == 0 ? sec.SizeOfRawData : sec.VirtualSize);
        if (rawSize <= 0) return;

        var fileOffset = (int)sec.PointerToRawData;
        var rawBytes = pe.RawFile.AsSpan(fileOffset, rawSize).ToArray();

        var startIp = imageBase + sec.VirtualAddress;
        var reader = new ByteArrayCodeReader(rawBytes);
        // FQN: avoids System.Text.Decoder vs Iced.Intel.Decoder ambiguity.
        var decoder = Iced.Intel.Decoder.Create(bitness, reader, startIp, DecoderOptions.None);
        var formatter = new NasmFormatter();
        var output = new StringOutput();

        // Ring of recent decoded instructions for ExtractArgs back-walk.
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
                // Resolve operand VA: x64 RIP-relative or x86 absolute [imm32].
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

                    // Arg extraction only for direct calls (IAT jmp is a tail-call thunk).
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

            // Push after the callsite check so ExtractArgs only sees prior insts.
            ring[ringHead] = inst;
            ringHead = (ringHead + 1) % WindowSize;
            if (ringCount < WindowSize) ringCount++;
        }
    }

    // ---------- Arg extraction ----------

    /// <summary>
    /// Back-walk the ring for the instruction that loaded the first arg. LdrLoadDll returns (null, null).
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
    /// x64: arg1 in RCX (string ptr), arg3 in R8 (LoadLibraryEx flags). Look for most-recent writes.
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
            // i-th most-recent slot in the circular ring.
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
    /// x86 stdcall: walk back to the nearest push imm32 (arg1).
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
    /// True when the destination register is in <paramref name="canonical"/>'s family (RCX includes ECX/CX/CL).
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
        // 'lea reg, [rip+disp]' — string in .rdata.
        if (prior.Mnemonic == Mnemonic.Lea && prior.Op1Kind == OpKind.Memory && prior.IsIPRelativeMemoryOperand)
        {
            var stringVa = prior.IPRelativeMemoryAddress;
            if (stringVa < imageBase) return null;
            return ReadStringFromRva(pe, (uint)(stringVa - imageBase), isWide);
        }
        // 'mov reg, imm' — direct address.
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
        // 'xor r8d, r8d' — flags = 0 (search-order resolution).
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
    /// Read a null-terminated printable string at <paramref name="rva"/> (UTF-16 LE when wide).
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

        // Read a bounded chunk; MaxLen*2 covers wide chars + terminator.
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
