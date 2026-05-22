using DllSidecar.Core.Helpers;

namespace DllSidecar.Core.Tests.Helpers;

public class ServiceImagePathParserTests
{
    [Fact]
    public void ExtractPath_Empty_ReturnsEmpty()
    {
        Assert.Equal("", ServiceImagePathParser.ExtractPath(""));
        Assert.Equal("", ServiceImagePathParser.ExtractPath("   "));
        Assert.Equal("", ServiceImagePathParser.ExtractPath(null));
    }

    [Fact]
    public void ExtractPath_QuotedPath_StripsQuotesAndArgs()
    {
        var s = "\"C:\\Windows\\System32\\svchost.exe\" -k netsvcs -p";
        Assert.Equal(@"C:\Windows\System32\svchost.exe", ServiceImagePathParser.ExtractPath(s));
    }

    [Fact]
    public void ExtractPath_QuotedPathWithSpaces_Survives()
    {
        var s = "\"C:\\Program Files\\Vendor\\svc.exe\" --listen 8080";
        Assert.Equal(@"C:\Program Files\Vendor\svc.exe", ServiceImagePathParser.ExtractPath(s));
    }

    [Fact]
    public void ExtractPath_UnquotedNoSpacesInPath_SplitsAtFirstSpace()
    {
        var s = @"C:\Windows\System32\svchost.exe -k netsvcs";
        Assert.Equal(@"C:\Windows\System32\svchost.exe", ServiceImagePathParser.ExtractPath(s));
    }

    [Fact]
    public void ExtractPath_UnquotedWithSpacesInPath_DetectsExeBoundary()
    {
        // The bug this helper exists to fix: a naive first-space split would have
        // returned "C:\Program" here. The .exe-terminator heuristic keeps the
        // full path intact.
        var s = @"C:\Program Files\Vendor\svc.exe -k group";
        Assert.Equal(@"C:\Program Files\Vendor\svc.exe", ServiceImagePathParser.ExtractPath(s));
    }

    [Fact]
    public void ExtractPath_UnquotedWithSpacesInPath_NoArgs()
    {
        var s = @"C:\Program Files\Vendor\svc.exe";
        Assert.Equal(@"C:\Program Files\Vendor\svc.exe", ServiceImagePathParser.ExtractPath(s));
    }

    [Fact]
    public void ExtractPath_UnquotedCaseInsensitiveExtension_DetectsBoundary()
    {
        var s = @"C:\Program Files\Vendor\SVC.EXE -arg";
        Assert.Equal(@"C:\Program Files\Vendor\SVC.EXE", ServiceImagePathParser.ExtractPath(s));
    }

    [Fact]
    public void ExtractPath_DriverPathWithSysExtension_DetectsBoundary()
    {
        var s = @"\??\C:\Windows\System32\drivers\my driver.sys";
        Assert.Equal(@"\??\C:\Windows\System32\drivers\my driver.sys", ServiceImagePathParser.ExtractPath(s));
    }

    [Fact]
    public void ExtractPath_NoRecognizedExtension_FallsBackToFirstSpace()
    {
        // Preserves the legacy fallback so unusual registrations (no extension at all)
        // still return *something* useful — same as the old behaviour.
        var s = "scriptrunner -arg1 -arg2";
        Assert.Equal("scriptrunner", ServiceImagePathParser.ExtractPath(s));
    }

    [Fact]
    public void ExtractPath_ArgsContainAnotherExePath_PicksEarliestBoundary()
    {
        // Defends against an argument that itself contains an executable extension:
        // the earliest valid boundary wins, so the actual binary is captured even
        // when args look like another path.
        var s = @"C:\Program Files\Vendor\svc.exe --plugin=C:\Other\helper.exe";
        Assert.Equal(@"C:\Program Files\Vendor\svc.exe", ServiceImagePathParser.ExtractPath(s));
    }

    [Fact]
    public void ExtractPath_UnclosedQuote_TrimsRemainingQuote()
    {
        var s = "\"C:\\bad path\\svc.exe";
        // No matching closing quote — falls back to trimming surrounding quotes.
        Assert.Equal(@"C:\bad path\svc.exe", ServiceImagePathParser.ExtractPath(s));
    }
}
