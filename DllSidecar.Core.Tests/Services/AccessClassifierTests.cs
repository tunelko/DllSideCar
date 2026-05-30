using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.Core.Tests.Services;

public class AccessClassifierTests
{
    // ── ProcMon Detail strings ──────────────────────────────────────────────

    [Fact]
    public void Classify_Detail_MobaXtermProbe_ReturnsMetadataProbe()
    {
        // Real Detail from MobaXterm 26.4 Preview1 trace (cygwin1.dll probe).
        const string detail =
            "Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, " +
            "Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a";

        Assert.Equal(AccessClass.MetadataProbe, AccessClassifier.Classify(detail));
    }

    [Fact]
    public void Classify_Detail_LoaderImageOpen_ReturnsLoaderLike()
    {
        // Canonical loader image-map CreateFile shape.
        const string detail =
            "Desired Access: Read Data/List Directory, Read Attributes, Synchronize, " +
            "Disposition: Open, Options: Synchronous IO Non-Alert, Non-Directory File, " +
            "Attributes: n/a, ShareMode: Read, Delete, AllocationSize: n/a";

        Assert.Equal(AccessClass.LoaderLike, AccessClassifier.Classify(detail));
    }

    [Fact]
    public void Classify_Detail_GenericReadInDesiredAccess_ReturnsLoaderLike()
    {
        const string detail =
            "Desired Access: Generic Read, Disposition: Open, " +
            "Options: Sequential Access, Synchronous IO Non-Alert, Non-Directory File, " +
            "Attributes: N, ShareMode: Read, Delete, AllocationSize: n/a";

        Assert.Equal(AccessClass.LoaderLike, AccessClassifier.Classify(detail));
    }

    [Fact]
    public void Classify_Detail_ExecuteInDesiredAccess_ReturnsLoaderLike()
    {
        // Some loader variants request Execute explicitly.
        const string detail =
            "Desired Access: Read Attributes, Execute/Traverse, Synchronize, " +
            "Disposition: Open, Options: Non-Directory File, " +
            "Attributes: n/a, ShareMode: Read, AllocationSize: n/a";

        Assert.Equal(AccessClass.LoaderLike, AccessClassifier.Classify(detail));
    }

    [Fact]
    public void Classify_Detail_LoadOptionsAlone_ReturnsLoaderLike()
    {
        // Loader's image-map Options shape classifies as LoaderLike.
        const string detail =
            "Desired Access: Read Attributes, Disposition: Open, " +
            "Options: Synchronous IO Non-Alert, Non-Directory File, " +
            "Attributes: n/a, ShareMode: Read, AllocationSize: n/a";

        Assert.Equal(AccessClass.LoaderLike, AccessClassifier.Classify(detail));
    }

    [Fact]
    public void Classify_Detail_Null_ReturnsUnknown()
    {
        Assert.Equal(AccessClass.Unknown, AccessClassifier.Classify((string?)null));
    }

    [Fact]
    public void Classify_Detail_Empty_ReturnsUnknown()
    {
        Assert.Equal(AccessClass.Unknown, AccessClassifier.Classify(""));
    }

    [Fact]
    public void Classify_Detail_NoFingerprintFields_ReturnsUnknown()
    {
        // Some legacy ProcMon exports omit Detail entirely or carry only "n/a".
        Assert.Equal(AccessClass.Unknown, AccessClassifier.Classify("Attributes: n/a"));
    }

    // ── ParseDetail field splitter ──────────────────────────────────────────

    [Fact]
    public void ParseDetail_HandlesCommasInsideShareMode()
    {
        // ShareMode commas must NOT split fields; AllocationSize is the boundary.
        const string detail =
            "Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, " +
            "Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a";

        var fields = AccessClassifier.ParseDetail(detail);

        Assert.Equal("Read Attributes", fields["Desired Access"]);
        Assert.Equal("Open", fields["Disposition"]);
        Assert.Equal("Open Reparse Point", fields["Options"]);
        Assert.Equal("Read, Write, Delete", fields["ShareMode"]);
        Assert.Equal("n/a", fields["AllocationSize"]);
    }

    // ── NT CreateOptions (ETW) ──────────────────────────────────────────────

    [Fact]
    public void Classify_CreateOptions_LoaderShape_ReturnsLoaderLike()
    {
        uint opts = AccessClassifier.FILE_NON_DIRECTORY_FILE
                  | AccessClassifier.FILE_SYNCHRONOUS_IO_NONALERT;
        Assert.Equal(AccessClass.LoaderLike, AccessClassifier.Classify(opts));
    }

    [Fact]
    public void Classify_CreateOptions_ReparsePointOnly_ReturnsMetadataProbe()
    {
        uint opts = AccessClassifier.FILE_OPEN_REPARSE_POINT;
        Assert.Equal(AccessClass.MetadataProbe, AccessClassifier.Classify(opts));
    }

    [Fact]
    public void Classify_CreateOptions_LoaderShapeWithReparsePoint_NotProbe()
    {
        // Load flags + reparse-point together demote to Unknown (not probe).
        uint opts = AccessClassifier.FILE_NON_DIRECTORY_FILE
                  | AccessClassifier.FILE_SYNCHRONOUS_IO_NONALERT
                  | AccessClassifier.FILE_OPEN_REPARSE_POINT;
        Assert.NotEqual(AccessClass.MetadataProbe, AccessClassifier.Classify(opts));
    }

    [Fact]
    public void Classify_CreateOptions_Zero_ReturnsUnknown()
    {
        Assert.Equal(AccessClass.Unknown, AccessClassifier.Classify(0u));
    }

    [Fact]
    public void Classify_CreateOptions_OnlyDirectoryFlag_ReturnsUnknown()
    {
        Assert.Equal(AccessClass.Unknown, AccessClassifier.Classify(AccessClassifier.FILE_DIRECTORY_FILE));
    }

    // ── UI labels ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData(AccessClass.LoaderLike,    "FILE_NON_DIRECTORY_FILE")]
    [InlineData(AccessClass.MetadataProbe, "FILE_OPEN_REPARSE_POINT")]
    [InlineData(AccessClass.Unknown,       "")]
    public void Label_MatchesProcmonNomenclature(AccessClass cls, string expected)
    {
        Assert.Equal(expected, AccessClassifier.Label(cls));
    }
}
