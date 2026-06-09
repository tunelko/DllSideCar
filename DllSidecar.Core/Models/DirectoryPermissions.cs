namespace DllSidecar.Core.Models;

public class DirectoryPermissions
{
    public required string Path { get; set; }

    // Well-known SIDs with write access (CreateFiles / WriteData / AppendData / WriteAttributes / Modify / FullControl)
    public bool UsersWrite { get; set; }            // S-1-5-32-545 BUILTIN\Users
    public bool EveryoneWrite { get; set; }         // S-1-1-0
    public bool AuthenticatedUsersWrite { get; set; } // S-1-5-11

    // Live write-probe by the DllSidecar process. Informational only — contaminated by the
    // process token (an elevated DllSidecar writes everywhere). NOT used for writability decisions.
    public bool CurrentUserWrite { get; set; }

    // The directory's owner SID has an explicit DACL Allow-write rule and is NOT an
    // administrative principal. Decoupled from the DllSidecar process: same answer whether
    // DllSidecar runs elevated or not, and whether the running user is the owner or not.
    // Captures per-user portable installs (HKCU profile dirs) without falsely flagging
    // Program Files / System32 (owned by TrustedInstaller, filtered as administrative).
    public bool OwnerHasWrite { get; set; }

    public List<string> WritableBy { get; set; } = [];
    public string? Error { get; set; }

    /// <summary>
    /// Three-tier classification of "who can plant a DLL here". Single source of truth for
    /// every UI label, scorer factor, and filter. Decoupled from the DllSidecar process —
    /// the answer is the same whether DllSidecar runs elevated or not.
    /// <list type="bullet">
    ///   <item><c>Open</c> — DACL grants write to BUILTIN\Users, Everyone, or Authenticated Users.</item>
    ///   <item><c>OwnerOnly</c> — only the directory's non-admin owner can write (e.g. per-user portable installs).</item>
    ///   <item><c>AdminOnly</c> — only administrative principals (Administrators, SYSTEM, TrustedInstaller, AppContainer) can write.</item>
    /// </list>
    /// </summary>
    public WriteTier Tier
    {
        get
        {
            if (UsersWrite || EveryoneWrite || AuthenticatedUsersWrite) return WriteTier.Open;
            if (OwnerHasWrite) return WriteTier.OwnerOnly;
            return WriteTier.AdminOnly;
        }
    }

    /// <summary>Strict: any standard non-elevated user can plant here.</summary>
    public bool IsLowPrivWritable => Tier == WriteTier.Open;

    /// <summary>Only the directory's non-admin owner can plant here.</summary>
    public bool IsOwnerOnlyWritable => Tier == WriteTier.OwnerOnly;

    /// <summary>
    /// "Writable by a user" for sideloading purposes. TRUE iff Open or OwnerOnly. FALSE means
    /// the only path requires administrative privilege — no standard user can plant a DLL.
    /// </summary>
    public bool IsUserWritable => Tier != WriteTier.AdminOnly;
}

public enum WriteTier
{
    AdminOnly,
    OwnerOnly,
    Open,
}
