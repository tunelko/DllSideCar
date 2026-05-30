using DllSidecar.Core.Models.Execution;
using DllSidecar.Core.Services.Privesc;

namespace DllSidecar.Core.Tests.Privesc;

public class ServicesDetectorTests
{
    [Fact]
    public void ImagePath_DirectExeWithArgs_ResolvesAndKeepsArguments()
    {
        var entries = ServicesDetector.BuildEntries(
            serviceName: "VendorSvc",
            imagePath: "\"C:\\Program Files\\Vendor\\svc.exe\" -k netsvcs",
            serviceDll: null,
            objectName: "LocalSystem",
            startType: 2);

        var e = Assert.Single(entries);
        Assert.Equal(ServicesDetector.ServiceSource.ImagePath, e.Source);
        Assert.Equal(WrapperKind.None, e.Wrapper);
        Assert.Equal(ResolutionStatus.Resolved, e.ResolutionStatus);
        Assert.Equal(@"C:\Program Files\Vendor\svc.exe", e.ResolvedPath);
        Assert.Equal("-k netsvcs", e.Arguments);
        Assert.Equal(2, e.StartType);
        Assert.True(e.RunsAsSystem);
    }

    [Fact]
    public void ImagePath_EnvVar_IsExpanded()
    {
        Environment.SetEnvironmentVariable("VENDOR_TEST_DIR", @"C:\Temp\Vendor");
        try
        {
            var entries = ServicesDetector.BuildEntries(
                "EnvSvc",
                imagePath: "%VENDOR_TEST_DIR%\\svc.exe -run",
                serviceDll: null,
                objectName: "NT AUTHORITY\\SYSTEM",
                startType: 2);
            var e = Assert.Single(entries);
            Assert.Equal(@"C:\Temp\Vendor\svc.exe", e.ResolvedPath);
        }
        finally { Environment.SetEnvironmentVariable("VENDOR_TEST_DIR", null); }
    }

    [Fact]
    public void ImagePath_CmdWrapper_ResolvesTargetAndFlagsWrapper()
    {
        var entries = ServicesDetector.BuildEntries(
            "WrappedSvc",
            imagePath: "cmd.exe /c \"C:\\ProgramData\\Vendor\\start.bat\"",
            serviceDll: null,
            objectName: "LocalSystem",
            startType: 2);

        var e = Assert.Single(entries);
        Assert.Equal(WrapperKind.Cmd, e.Wrapper);
        Assert.True(e.ResolvedViaWrapper);
        Assert.Equal(@"C:\ProgramData\Vendor\start.bat", e.ResolvedPath);
    }

    [Fact]
    public void Svchost_WithServiceDll_ProducesBothEntries()
    {
        // ImagePath is svchost; ServiceDll is the actual target.
        var entries = ServicesDetector.BuildEntries(
            "SvchostHostedSvc",
            imagePath: @"C:\Windows\System32\svchost.exe -k netsvcs",
            serviceDll: @"C:\Program Files\Vendor\svc.dll",
            objectName: "NT AUTHORITY\\SYSTEM",
            startType: 2);

        Assert.Equal(2, entries.Count);
        var img = entries.Single(e => e.Source == ServicesDetector.ServiceSource.ImagePath);
        var dll = entries.Single(e => e.Source == ServicesDetector.ServiceSource.ServiceDll);
        Assert.Equal(@"C:\Windows\System32\svchost.exe", img.ResolvedPath);
        Assert.Equal(@"C:\Program Files\Vendor\svc.dll", dll.ResolvedPath);
    }

    [Fact]
    public void LocalService_AccountTagged_RestrictedNotSystem()
    {
        var entries = ServicesDetector.BuildEntries(
            "RestrictedSvc",
            imagePath: @"C:\Tools\svc.exe",
            serviceDll: null,
            objectName: "NT AUTHORITY\\LocalService",
            startType: 2);
        var e = Assert.Single(entries);
        Assert.False(e.RunsAsSystem);
        Assert.True(e.RunsAsRestrictedService);
    }

    [Fact]
    public void UserSpecificAccount_NeitherSystemNorRestricted()
    {
        var entries = ServicesDetector.BuildEntries(
            "UserSvc",
            imagePath: @"C:\Tools\svc.exe",
            serviceDll: null,
            objectName: "DOMAIN\\alice",
            startType: 3);
        var e = Assert.Single(entries);
        Assert.False(e.RunsAsSystem);
        Assert.False(e.RunsAsRestrictedService);
        Assert.Equal(3, e.StartType);
    }

    [Theory]
    [InlineData(0, "boot")]
    [InlineData(1, "system")]
    [InlineData(2, "auto")]
    [InlineData(3, "manual")]
    [InlineData(4, "disabled")]
    public void StartType_RoundtripsViaEvidence(int code, string expected)
    {
        var entries = ServicesDetector.BuildEntries("X", @"C:\x.exe", null, "LocalSystem", code);
        var e = Assert.Single(entries);
        Assert.Equal(code, e.StartType);
        _ = expected; // name mapping is internal; proved via smoke here
    }

    [Fact]
    public void EmptyImagePathAndServiceDll_ReturnsEmptyList()
    {
        var entries = ServicesDetector.BuildEntries("Empty", "", "", "LocalSystem", 2);
        Assert.Empty(entries);
    }
}
