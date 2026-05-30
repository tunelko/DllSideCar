namespace DllSidecar.Core.Models;

public class DirectoryPermissions
{
    public required string Path { get; set; }

    // Well-known SIDs with write access (CreateFiles / WriteData / AppendData / WriteAttributes / Modify / FullControl)
    public bool UsersWrite { get; set; }            // S-1-5-32-545 BUILTIN\Users
    public bool EveryoneWrite { get; set; }         // S-1-1-0
    public bool AuthenticatedUsersWrite { get; set; } // S-1-5-11
    public bool CurrentUserWrite { get; set; }      // effective check by current principal

    public List<string> WritableBy { get; set; } = [];
    public string? Error { get; set; }

    /// <summary>
    /// Effective writability for the targeted user. When the host process is elevated, the
    /// CurrentUserWrite probe overstates (admin can write to System32) — drop that signal and
    /// fall back to DACL-explicit grants plus any non-admin SID listed in <see cref="WritableBy"/>
    /// (which covers owner-only grants like portable installs in the user profile).
    /// </summary>
    public bool IsUserWritable
    {
        get
        {
            if (UsersWrite || EveryoneWrite || AuthenticatedUsersWrite) return true;
            if (WritableBy.Count > 0) return true;
            if (CurrentUserWrite && !ProcessElevation.IsElevated) return true;
            return false;
        }
    }

    public bool IsLowPrivWritable =>
        UsersWrite || EveryoneWrite || AuthenticatedUsersWrite;
}

internal static class ProcessElevation
{
    public static bool IsElevated { get; } = ComputeElevated();
    private static bool ComputeElevated()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(id);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
