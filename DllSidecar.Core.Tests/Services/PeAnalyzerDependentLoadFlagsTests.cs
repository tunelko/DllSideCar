using System.Buffers.Binary;
using DllSidecar.Core.Services;

namespace DllSidecar.Core.Tests.Services;

public class PeAnalyzerDependentLoadFlagsTests
{
    [Theory]
    [InlineData(false, "x86")]
    [InlineData(true, "x64")]
    public void Analyze_ReadsDependentLoadFlagsFromLoadConfig(bool pe32Plus, string expectedArch)
    {
        var path = Path.Combine(Path.GetTempPath(), $"dllsidecar-loadcfg-{Guid.NewGuid():N}.dll");
        try
        {
            File.WriteAllBytes(path, BuildPeWithLoadConfig(pe32Plus, dependentLoadFlags: 0x0800));

            var analysis = PeAnalyzer.Analyze(path);

            Assert.Equal(expectedArch, analysis.Arch);
            Assert.Equal(0x0800u, analysis.Security.DependentLoadFlags);
            Assert.True(analysis.Security.ForcesSystem32Only);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    private static byte[] BuildPeWithLoadConfig(bool pe32Plus, ushort dependentLoadFlags)
    {
        const int peOffset = 0x80;
        const int optionalHeaderOffset = peOffset + 4 + 20;
        const int sectionRawOffset = 0x200;
        const uint sectionRva = 0x1000;

        var optionalHeaderSize = pe32Plus ? 0xF0 : 0xE0;
        var dataDirectoryOffset = optionalHeaderOffset + (pe32Plus ? 112 : 96);
        var sectionHeaderOffset = optionalHeaderOffset + optionalHeaderSize;
        var image = new byte[0x400];

        WriteUInt16(image, 0x00, 0x5A4D); // MZ
        WriteUInt32(image, 0x3C, peOffset);
        WriteUInt32(image, peOffset, 0x00004550); // PE\0\0

        var coff = peOffset + 4;
        WriteUInt16(image, coff, pe32Plus ? (ushort)0x8664 : (ushort)0x014C);
        WriteUInt16(image, coff + 2, 1); // NumberOfSections
        WriteUInt16(image, coff + 16, (ushort)optionalHeaderSize);
        WriteUInt16(image, coff + 18, pe32Plus ? (ushort)0x2022 : (ushort)0x2102);

        WriteUInt16(image, optionalHeaderOffset, pe32Plus ? (ushort)0x020B : (ushort)0x010B);
        WriteUInt32(image, optionalHeaderOffset + 20, sectionRva); // BaseOfCode
        if (pe32Plus)
            WriteUInt64(image, optionalHeaderOffset + 24, 0x0000000140000000);
        else
        {
            WriteUInt32(image, optionalHeaderOffset + 24, sectionRva); // BaseOfData
            WriteUInt32(image, optionalHeaderOffset + 28, 0x00400000); // ImageBase
        }

        WriteUInt32(image, optionalHeaderOffset + 32, 0x1000); // SectionAlignment
        WriteUInt32(image, optionalHeaderOffset + 36, 0x0200); // FileAlignment
        WriteUInt16(image, optionalHeaderOffset + 40, 6);      // MajorOperatingSystemVersion
        WriteUInt16(image, optionalHeaderOffset + 48, 6);      // MajorSubsystemVersion
        WriteUInt32(image, optionalHeaderOffset + 56, 0x2000); // SizeOfImage
        WriteUInt32(image, optionalHeaderOffset + 60, 0x0200); // SizeOfHeaders
        WriteUInt16(image, optionalHeaderOffset + 68, 3);      // Windows CUI
        WriteUInt16(image, optionalHeaderOffset + 70, 0x0140); // DYNAMIC_BASE | NX_COMPAT
        WriteUInt32(image, optionalHeaderOffset + (pe32Plus ? 108 : 92), 16);

        var loadConfigDirectory = dataDirectoryOffset + (10 * 8);
        WriteUInt32(image, loadConfigDirectory, sectionRva);
        WriteUInt32(image, loadConfigDirectory + 4, pe32Plus ? 0x70u : 0x40u);

        image[sectionHeaderOffset + 0] = (byte)'.';
        image[sectionHeaderOffset + 1] = (byte)'r';
        image[sectionHeaderOffset + 2] = (byte)'d';
        image[sectionHeaderOffset + 3] = (byte)'a';
        image[sectionHeaderOffset + 4] = (byte)'t';
        image[sectionHeaderOffset + 5] = (byte)'a';
        WriteUInt32(image, sectionHeaderOffset + 8, 0x0200);  // VirtualSize
        WriteUInt32(image, sectionHeaderOffset + 12, sectionRva);
        WriteUInt32(image, sectionHeaderOffset + 16, 0x0200); // SizeOfRawData
        WriteUInt32(image, sectionHeaderOffset + 20, sectionRawOffset);
        WriteUInt32(image, sectionHeaderOffset + 36, 0x40000040); // initialized, readable

        WriteUInt32(image, sectionRawOffset, pe32Plus ? 0x70u : 0x40u);
        var dependentLoadFlagsOffset = sectionRawOffset + (pe32Plus ? 0x4E : 0x36);
        WriteUInt16(image, dependentLoadFlagsOffset, dependentLoadFlags);

        return image;
    }

    private static void WriteUInt16(byte[] image, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(offset), value);

    private static void WriteUInt32(byte[] image, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(offset), value);

    private static void WriteUInt64(byte[] image, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(offset), value);
}
