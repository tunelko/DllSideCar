using System.Security.AccessControl;
using System.Security.Principal;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

public static class DirectoryAclChecker
{
    // Well-known SIDs
    private static readonly SecurityIdentifier SidUsers             = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier SidEveryone          = new(WellKnownSidType.WorldSid, null);
    private static readonly SecurityIdentifier SidAuthenticatedUsers = new(WellKnownSidType.AuthenticatedUserSid, null);

    // Bits that grant write OR the ability to grant oneself write. Strictly write-only —
    // NEVER include FullControl/Modify/Read/Execute aggregates here: their value masks
    // also contain read bits (ReadData, ReadAttributes, Synchronize, ...) so AND-ing
    // against them would flag READ-only ACEs as "writable" (the FortiClient false
    // positive: BUILTIN\Users:(RX) matched FullControl=0x1F01FF because RX shares bits).
    // GenericAll / GenericWrite raw-bit constants from winnt.h (not in the .NET enum).
    private const FileSystemRights WriteRights =
        FileSystemRights.WriteData |                    // 0x02 = CreateFiles
        FileSystemRights.AppendData |                   // 0x04 = CreateDirectories
        FileSystemRights.WriteExtendedAttributes |      // 0x10
        FileSystemRights.WriteAttributes |              // 0x100
        FileSystemRights.Delete |                       // 0x10000
        FileSystemRights.DeleteSubdirectoriesAndFiles | // 0x40
        FileSystemRights.ChangePermissions |            // 0x40000 — can grant self write
        FileSystemRights.TakeOwnership |                // 0x80000 — can take ownership
        (FileSystemRights)0x10000000 |                  // GENERIC_ALL
        (FileSystemRights)0x40000000;                   // GENERIC_WRITE

    public static DirectoryPermissions Check(string directory)
    {
        var perms = new DirectoryPermissions { Path = directory };
        if (!Directory.Exists(directory))
        {
            perms.Error = "Directory not found";
            return perms;
        }

        try
        {
            var di = new DirectoryInfo(directory);
            var sec = di.GetAccessControl();
            var rules = sec.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier));

            SecurityIdentifier? ownerSid = null;
            try { ownerSid = (SecurityIdentifier?)sec.GetOwner(typeof(SecurityIdentifier)); }
            catch (Exception ex) { Log.Debug("acl", $"GetOwner failed for {directory}", ex); }

            foreach (AuthorizationRule rule in rules)
            {
                if (rule is not FileSystemAccessRule fsRule) continue;
                if (fsRule.AccessControlType != AccessControlType.Allow) continue;
                if ((fsRule.FileSystemRights & WriteRights) == 0) continue;

                var sid = (SecurityIdentifier)fsRule.IdentityReference;
                var name = SafeTranslate(sid);

                if (sid == SidUsers)
                {
                    perms.UsersWrite = true;
                    if (!perms.WritableBy.Contains(name)) perms.WritableBy.Add(name);
                }
                else if (sid == SidEveryone)
                {
                    perms.EveryoneWrite = true;
                    if (!perms.WritableBy.Contains(name)) perms.WritableBy.Add(name);
                }
                else if (sid == SidAuthenticatedUsers)
                {
                    perms.AuthenticatedUsersWrite = true;
                    if (!perms.WritableBy.Contains(name)) perms.WritableBy.Add(name);
                }
                else
                {
                    if (!IsAdministrative(sid))
                    {
                        if (!perms.WritableBy.Contains(name)) perms.WritableBy.Add(name);
                    }
                }

                // Owner-of-dir explicit write grant (non-administrative). Decoupled from the
                // DllSidecar process: matches the directory's owner SID, not the running user.
                if (ownerSid != null && sid == ownerSid && !IsAdministrative(sid))
                    perms.OwnerHasWrite = true;
            }

            perms.CurrentUserWrite = TestCurrentUserWritable(directory);
        }
        catch (Exception ex)
        {
            perms.Error = ex.Message;
        }

        return perms;
    }

    // SIDs that grant write but a regular interactive user cannot freely assume.
    // Filtering them prevents Program Files / System32 from being mis-classified as
    // user-writable via WritableBy when the only write grant is TrustedInstaller,
    // an AppContainer SID, or CREATOR OWNER.
    private static bool IsAdministrative(SecurityIdentifier sid)
    {
        try
        {
            if (sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
                sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
                sid.IsWellKnown(WellKnownSidType.LocalServiceSid) ||
                sid.IsWellKnown(WellKnownSidType.NetworkServiceSid) ||
                sid.IsWellKnown(WellKnownSidType.AccountDomainAdminsSid) ||
                sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid) ||
                sid.IsWellKnown(WellKnownSidType.CreatorGroupSid))
                return true;

            // NT SERVICE\* (S-1-5-80-...) — TrustedInstaller and other service-virtual SIDs.
            // APPLICATION PACKAGE AUTHORITY (S-1-15-...) — ALL APPLICATION PACKAGES etc.
            var v = sid.Value;
            return v.StartsWith("S-1-5-80-", StringComparison.Ordinal) ||
                   v.StartsWith("S-1-15-",   StringComparison.Ordinal);
        }
        catch (Exception ex)
        {
            Log.Debug("acl", $"IsWellKnown probe failed for SID {sid.Value}", ex);
            return false;
        }
    }

    private static string SafeTranslate(SecurityIdentifier sid)
    {
        try { return sid.Translate(typeof(NTAccount)).Value; }
        catch (IdentityNotMappedException)
        {
            // Orphan SID — fall back to raw SID string
            return sid.Value;
        }
        catch (Exception ex)
        {
            Log.Debug("acl", $"SID translation failed for {sid.Value}", ex);
            return sid.Value;
        }
    }

    private static bool TestCurrentUserWritable(string directory)
    {
        var probe = Path.Combine(directory, $".dllsidecar_probe_{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(probe, "x");
            return true;
        }
        catch (UnauthorizedAccessException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
        catch (IOException) { return false; }
        finally
        {
            try { if (File.Exists(probe)) File.Delete(probe); }
            catch (Exception ex) { Log.Warn("acl", $"Failed to remove write probe {probe}", ex); }
        }
    }
}
