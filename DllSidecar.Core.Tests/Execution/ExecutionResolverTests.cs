using DllSidecar.Core.Models.Execution;
using DllSidecar.Core.Services.Execution;

namespace DllSidecar.Core.Tests.Execution;

public class ExecutionResolverTests
{
    // ─────────── Direct invocation ───────────

    [Fact]
    public void Direct_ExeWithSeparateArgs_ResolvesHead()
    {
        var r = ExecutionResolver.Resolve(@"C:\Program Files\Vendor\app.exe", "-start", @"C:\Program Files\Vendor");
        Assert.Equal(WrapperKind.None, r.Wrapper);
        Assert.Equal(ResolutionStatus.Resolved, r.Status);
        Assert.Equal(@"C:\Program Files\Vendor\app.exe", r.ResolvedPath);
        Assert.Equal("-start", r.Arguments);
        Assert.Equal(@"C:\Program Files\Vendor", r.WorkingDirectory);
        Assert.False(r.ResolvedViaWrapper);
    }

    [Fact]
    public void Direct_QuotedImagePathWithArgs_SplitsCorrectly()
    {
        // Service ImagePath style — everything in one field
        var r = ExecutionResolver.Resolve("\"C:\\Program Files\\Vendor\\svc.exe\" -k netsvcs");
        Assert.Equal(WrapperKind.None, r.Wrapper);
        Assert.Equal(@"C:\Program Files\Vendor\svc.exe", r.ResolvedPath);
        Assert.Equal("-k netsvcs", r.Arguments);
    }

    // ─────────── cmd /c ───────────

    [Fact]
    public void Cmd_SlashC_WithQuotedBat_Resolves()
    {
        var r = ExecutionResolver.Resolve("cmd.exe", "/c \"C:\\ProgramData\\Adobe\\updater.bat\"");
        Assert.Equal(WrapperKind.Cmd, r.Wrapper);
        Assert.Equal(ResolutionStatus.Resolved, r.Status);
        Assert.Equal(@"C:\ProgramData\Adobe\updater.bat", r.ResolvedPath);
        Assert.True(r.ResolvedViaWrapper);
    }

    [Fact]
    public void Cmd_SlashK_AlsoSupported()
    {
        var r = ExecutionResolver.Resolve("cmd.exe /k C:\\tools\\setup.bat");
        Assert.Equal(WrapperKind.Cmd, r.Wrapper);
        Assert.Equal(@"C:\tools\setup.bat", r.ResolvedPath);
    }

    [Fact]
    public void Cmd_EnvVar_IsExpanded()
    {
        // Set a predictable env var for the test
        Environment.SetEnvironmentVariable("TEST_UPDATER_DIR", @"C:\Temp\Vendor");
        try
        {
            var r = ExecutionResolver.Resolve("cmd.exe /c \"%TEST_UPDATER_DIR%\\updater.bat\"");
            Assert.Equal(WrapperKind.Cmd, r.Wrapper);
            Assert.Equal(@"C:\Temp\Vendor\updater.bat", r.ResolvedPath);
        }
        finally { Environment.SetEnvironmentVariable("TEST_UPDATER_DIR", null); }
    }

    [Fact]
    public void Cmd_WithoutSlashC_IsPartial()
    {
        var r = ExecutionResolver.Resolve("cmd.exe \"some-inline\"");
        Assert.Equal(WrapperKind.Cmd, r.Wrapper);
        Assert.Equal(ResolutionStatus.Partial, r.Status);
    }

    // ─────────── powershell ───────────

    [Fact]
    public void PowerShell_DashFile_Resolves()
    {
        var r = ExecutionResolver.Resolve("powershell.exe", "-NoProfile -File C:\\Tools\\run.ps1");
        Assert.Equal(WrapperKind.PowerShell, r.Wrapper);
        Assert.Equal(ResolutionStatus.Resolved, r.Status);
        Assert.Equal(@"C:\Tools\run.ps1", r.ResolvedPath);
    }

    [Fact]
    public void PowerShell_Pwsh_IsRecognized()
    {
        var r = ExecutionResolver.Resolve("pwsh.exe -File C:\\Tools\\run.ps1");
        Assert.Equal(WrapperKind.PowerShell, r.Wrapper);
        Assert.Equal(@"C:\Tools\run.ps1", r.ResolvedPath);
    }

    [Fact]
    public void PowerShell_EncodedCommand_ExtractsPathIfPresent()
    {
        // Base64-UTF16LE of: iex "C:\evil\x.ps1"
        var inner = "iex \"C:\\evil\\x.ps1\"";
        var b64 = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(inner));
        var r = ExecutionResolver.Resolve($"powershell.exe -EncodedCommand {b64}");
        Assert.Equal(WrapperKind.PowerShell, r.Wrapper);
        Assert.Equal(ResolutionStatus.Partial, r.Status); // Heuristic: partial even if path found
        Assert.Equal(@"C:\evil\x.ps1", r.ResolvedPath);
    }

    [Fact]
    public void PowerShell_EncodedCommand_WithoutPath_IsPartialNoPath()
    {
        var b64 = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Get-Process"));
        var r = ExecutionResolver.Resolve($"powershell.exe -enc {b64}");
        Assert.Equal(WrapperKind.PowerShell, r.Wrapper);
        Assert.Equal(ResolutionStatus.Partial, r.Status);
        Assert.Null(r.ResolvedPath);
    }

    [Fact]
    public void PowerShell_InvalidBase64_DoesNotThrow()
    {
        var r = ExecutionResolver.Resolve("powershell.exe -EncodedCommand !!!not-base64!!!");
        Assert.Equal(WrapperKind.PowerShell, r.Wrapper);
        Assert.Equal(ResolutionStatus.Partial, r.Status);
    }

    // ─────────── rundll32 ───────────

    [Fact]
    public void RunDll32_PathCommaEntry_ResolvesToDll()
    {
        // Unquoted path without spaces — the bare case
        var r = ExecutionResolver.Resolve("rundll32.exe", @"C:\Tools\helper.dll,Entry");
        Assert.Equal(WrapperKind.RunDll32, r.Wrapper);
        Assert.Equal(ResolutionStatus.Resolved, r.Status);
        Assert.Equal(@"C:\Tools\helper.dll", r.ResolvedPath);
    }

    [Fact]
    public void RunDll32_QuotedPath_Works()
    {
        var r = ExecutionResolver.Resolve("rundll32.exe \"C:\\Program Files\\Vendor\\helper.dll\",Entry");
        Assert.Equal(WrapperKind.RunDll32, r.Wrapper);
        Assert.Equal(@"C:\Program Files\Vendor\helper.dll", r.ResolvedPath);
    }

    // ─────────── msiexec ───────────

    [Fact]
    public void MsiExec_SlashI_Resolves()
    {
        var r = ExecutionResolver.Resolve("msiexec.exe /i C:\\pkg.msi /quiet");
        Assert.Equal(WrapperKind.MsiExec, r.Wrapper);
        Assert.Equal(ResolutionStatus.Resolved, r.Status);
        Assert.Equal(@"C:\pkg.msi", r.ResolvedPath);
    }

    [Theory]
    [InlineData("/x")]
    [InlineData("/a")]
    [InlineData("/package")]
    public void MsiExec_OtherFlags_AlsoResolved(string flag)
    {
        var r = ExecutionResolver.Resolve($"msiexec.exe {flag} C:\\pkg.msi");
        Assert.Equal(WrapperKind.MsiExec, r.Wrapper);
        Assert.Equal(@"C:\pkg.msi", r.ResolvedPath);
    }

    // ─────────── Edge cases ───────────

    [Fact]
    public void EmptyCommand_IsUnresolved()
    {
        var r = ExecutionResolver.Resolve("");
        Assert.Equal(ResolutionStatus.Unresolved, r.Status);
    }

    [Fact]
    public void OriginalCommand_IsPreserved()
    {
        var r = ExecutionResolver.Resolve("cmd.exe", "/c foo.bat");
        Assert.Equal("cmd.exe /c foo.bat", r.OriginalCommand);
    }
}
