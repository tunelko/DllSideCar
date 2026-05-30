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

    private const FileSystemRights WriteRights =
        FileSystemRights.WriteData |
        FileSystemRights.AppendData |
        FileSystemRights.CreateFiles |
        FileSystemRights.CreateDirectories |
        FileSystemRights.Modify |
        FileSystemRights.FullControl |
        FileSystemRights.Write;

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
            }

            perms.CurrentUserWrite = TestCurrentUserWritable(directory);
        }
        catch (Exception ex)
        {
            perms.Error = ex.Message;
        }

        return perms;
    }

    private static bool IsAdministrative(SecurityIdentifier sid)
    {
        try
        {
            return sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
                   sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
                   sid.IsWellKnown(WellKnownSidType.LocalServiceSid) ||
                   sid.IsWellKnown(WellKnownSidType.NetworkServiceSid) ||
                   sid.IsWellKnown(WellKnownSidType.AccountDomainAdminsSid);
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
