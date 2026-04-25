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

    public bool IsUserWritable =>
        UsersWrite || EveryoneWrite || AuthenticatedUsersWrite || CurrentUserWrite;

    public bool IsLowPrivWritable =>
        UsersWrite || EveryoneWrite || AuthenticatedUsersWrite;
}
