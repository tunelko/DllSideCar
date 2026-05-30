using DllSidecar.Core.Models.Execution;
using DllSidecar.Core.Services.Privesc;

namespace DllSidecar.Core.Tests.Privesc;

public class ScheduledTaskDetectorTests
{
    // Task Scheduler v1.0 namespace.
    private const string TaskNs = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    private static string BuildTaskXml(
        string command,
        string? arguments = null,
        string? workingDir = null,
        string userId = "S-1-5-18",
        string runLevel = "HighestAvailable",
        IEnumerable<(string cmd, string? args)>? extraExecs = null)
    {
        var extra = string.Concat((extraExecs ?? []).Select(e =>
            $"    <Exec><Command>{e.cmd}</Command>" +
            (e.args != null ? $"<Arguments>{e.args}</Arguments>" : "") +
            "</Exec>\n"));
        return $"""
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="{TaskNs}">
  <Principals>
    <Principal id="Author">
      <UserId>{userId}</UserId>
      <RunLevel>{runLevel}</RunLevel>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>{command}</Command>
      {(arguments != null ? $"<Arguments>{arguments}</Arguments>" : "")}
      {(workingDir != null ? $"<WorkingDirectory>{workingDir}</WorkingDirectory>" : "")}
    </Exec>
{extra}  </Actions>
</Task>
""";
    }

    [Fact]
    public void DirectExe_ProducesResolvedEntry()
    {
        var xml = BuildTaskXml(@"C:\Program Files\Vendor\Updater.exe", arguments: "-run");
        var entries = ScheduledTaskDetector.ParseTaskXml(xml, "Vendor\\Updater");

        var e = Assert.Single(entries);
        Assert.Equal("Vendor\\Updater", e.TaskName);
        Assert.Equal(WrapperKind.None, e.Wrapper);
        Assert.Equal(ResolutionStatus.Resolved, e.ResolutionStatus);
        Assert.Equal(@"C:\Program Files\Vendor\Updater.exe", e.ResolvedPath);
        Assert.Equal("-run", e.Arguments);
        Assert.Equal("HighestAvailable", e.RunLevel);
        Assert.Equal("S-1-5-18", e.UserId);
        Assert.True(e.RunsAsSystem);
        Assert.True(e.RunsElevated);
    }

    [Fact]
    public void WrappedCmdSlashC_ResolvesBat()
    {
        var xml = BuildTaskXml("cmd.exe", arguments: "/c \"C:\\ProgramData\\Adobe\\updater.bat\"");
        var entries = ScheduledTaskDetector.ParseTaskXml(xml, "Adobe\\Updater");

        var e = Assert.Single(entries);
        Assert.Equal(WrapperKind.Cmd, e.Wrapper);
        Assert.True(e.ResolvedViaWrapper);
        Assert.Equal(ResolutionStatus.Resolved, e.ResolutionStatus);
        Assert.Equal(@"C:\ProgramData\Adobe\updater.bat", e.ResolvedPath);
    }

    [Fact]
    public void PowerShellDashFile_Resolves()
    {
        var xml = BuildTaskXml("powershell.exe", arguments: "-NoProfile -File C:\\Tools\\run.ps1");
        var entries = ScheduledTaskDetector.ParseTaskXml(xml, "Vendor\\PS");

        var e = Assert.Single(entries);
        Assert.Equal(WrapperKind.PowerShell, e.Wrapper);
        Assert.Equal(@"C:\Tools\run.ps1", e.ResolvedPath);
    }

    [Fact]
    public void RunDll32_ResolvesDllTarget()
    {
        var xml = BuildTaskXml("rundll32.exe", arguments: @"C:\Tools\helper.dll,Entry");
        var entries = ScheduledTaskDetector.ParseTaskXml(xml, "Vendor\\Helper");

        var e = Assert.Single(entries);
        Assert.Equal(WrapperKind.RunDll32, e.Wrapper);
        Assert.Equal(@"C:\Tools\helper.dll", e.ResolvedPath);
    }

    [Fact]
    public void MultipleExecActions_AllParsed()
    {
        var xml = BuildTaskXml(
            @"C:\first.exe", arguments: "-a",
            extraExecs: new[]
            {
                ((string cmd, string? args))( @"C:\second.exe", "-b" ),
                ((string cmd, string? args))( @"C:\third.exe", null ),
            });
        var entries = ScheduledTaskDetector.ParseTaskXml(xml, "Chain");

        Assert.Equal(3, entries.Count);
        Assert.Equal(@"C:\first.exe", entries[0].ResolvedPath);
        Assert.Equal(@"C:\second.exe", entries[1].ResolvedPath);
        Assert.Equal(@"C:\third.exe", entries[2].ResolvedPath);
    }

    [Fact]
    public void XmlWithoutNamespace_StillParses()
    {
        // Some legacy exports drop the xmlns — we must still find Exec/Command
        var xml = """
<Task version="1.2">
  <Principals>
    <Principal id="Author">
      <UserId>LocalSystem</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>C:\Tools\vendor.exe</Command>
      <Arguments>-silent</Arguments>
    </Exec>
  </Actions>
</Task>
""";
        var entries = ScheduledTaskDetector.ParseTaskXml(xml, "Legacy");
        var e = Assert.Single(entries);
        Assert.Equal(@"C:\Tools\vendor.exe", e.ResolvedPath);
        Assert.True(e.RunsAsSystem);
    }

    [Fact]
    public void WorkingDirectory_IsCaptured()
    {
        var xml = BuildTaskXml(@"C:\vendor.exe", arguments: "-x", workingDir: @"C:\ProgramData\Vendor");
        var e = Assert.Single(ScheduledTaskDetector.ParseTaskXml(xml, "T"));
        Assert.Equal(@"C:\ProgramData\Vendor", e.WorkingDirectory);
    }

    [Fact]
    public void LeastPrivilege_RunLevel_IsNotElevated()
    {
        var xml = BuildTaskXml(@"C:\user-app.exe", userId: "domain\\alice", runLevel: "LeastPrivilege");
        var e = Assert.Single(ScheduledTaskDetector.ParseTaskXml(xml, "T"));
        Assert.False(e.RunsElevated);
        Assert.False(e.RunsAsSystem);
    }
}
