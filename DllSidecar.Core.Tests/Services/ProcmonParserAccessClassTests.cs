using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.Core.Tests.Services;

public class ProcmonParserAccessClassTests
{
    [Fact]
    public void Parse_TaggsEachEventWithAccessClass()
    {
        // Two synthetic rows: one loader-like, one metadata-probe.
        var tmp = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tmp,
                "\"Time of Day\",\"Process Name\",\"PID\",\"Operation\",\"Path\",\"Result\",\"Detail\"\n" +
                "\"10:00:00,1\",\"foo.exe\",\"1234\",\"CreateFile\",\"C:\\\\x\\\\foo.dll\",\"NAME NOT FOUND\"," +
                "\"Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, " +
                "Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a\"\n" +
                "\"10:00:00,2\",\"foo.exe\",\"1234\",\"CreateFile\",\"C:\\\\x\\\\bar.dll\",\"NAME NOT FOUND\"," +
                "\"Desired Access: Read Data/List Directory, Read Attributes, Synchronize, " +
                "Disposition: Open, Options: Synchronous IO Non-Alert, Non-Directory File, " +
                "Attributes: n/a, ShareMode: Read, Delete, AllocationSize: n/a\"\n");

            var result = ProcmonParser.Parse(tmp);

            Assert.Equal(2, result.FilteredRows);
            var fooEvt = result.Events.Single(e => e.DllName == "foo.dll");
            var barEvt = result.Events.Single(e => e.DllName == "bar.dll");
            Assert.Equal(AccessClass.MetadataProbe, fooEvt.Access);
            Assert.Equal(AccessClass.LoaderLike,   barEvt.Access);

            var fooAgg = result.ByDll.Single(a => a.DllName == "foo.dll");
            Assert.Equal(0, fooAgg.LoaderLikeCount);
            Assert.Equal(1, fooAgg.MetadataProbeCount);
            Assert.True(fooAgg.IsProbeOnly);

            var barAgg = result.ByDll.Single(a => a.DllName == "bar.dll");
            Assert.Equal(1, barAgg.LoaderLikeCount);
            Assert.Equal(0, barAgg.MetadataProbeCount);
            Assert.False(barAgg.IsProbeOnly);
        }
        finally { File.Delete(tmp); }
    }

    /// <summary>Live validation against the MobaXterm 26.4 retest CSV; skips when absent.</summary>
    [Fact]
    public void Parse_MobaXterm26_4_AllProbeNoLoad()
    {
        const string csvPath =
            @"D:\COMPARTIDO\CLAUDE\BugAInters\poc\mobaxterm\26_4_REVISION_RETEST\CYGWIN.CSV";
        if (!File.Exists(csvPath))
            return; // skip — corpus not on this machine

        var result = ProcmonParser.Parse(csvPath);

        Assert.Null(result.Error);
        Assert.True(result.FilteredRows > 0, "Expected NAME-NOT-FOUND rows in MobaXterm CSV");

        var cygwin = result.ByDll.SingleOrDefault(a =>
            string.Equals(a.DllName, "cygwin1.dll", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(cygwin);

        // Retest CSV is all GetFileAttributes-class probes.
        Assert.Equal(0, cygwin!.LoaderLikeCount);
        Assert.True(cygwin.MetadataProbeCount > 0, "Expected at least one probe event");
        Assert.True(cygwin.IsProbeOnly);
    }
}
