using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Aggregate writability verdict over a row's <c>SearchedDirs</c> set (CWE-427).
/// </summary>
public enum ProcmonDirWritability
{
    /// <summary>Every searched dir is low-priv writable.</summary>
    AllLowPrivWritable,
    /// <summary>Some writable, some locked.</summary>
    Mixed,
    /// <summary>Every searched dir requires admin.</summary>
    AllLocked,
    /// <summary>No usable dirs or every probe errored.</summary>
    Unknown,
}

public static class ProcmonRowWritabilityClassifier
{
    /// <summary>
    /// Reduce per-dir ACL probes into a single tier; errored probes are ignored.
    /// </summary>
    public static ProcmonDirWritability Classify(IEnumerable<string> searchedDirs, DirAclCache cache)
    {
        int writable = 0;
        int locked = 0;
        foreach (var dir in searchedDirs)
        {
            var perms = cache.Get(dir);
            if (!string.IsNullOrEmpty(perms.Error)) continue;   // skip errored probes
            if (perms.IsUserWritable) writable++;
            else locked++;
        }
        var total = writable + locked;
        if (total == 0) return ProcmonDirWritability.Unknown;
        if (writable == total) return ProcmonDirWritability.AllLowPrivWritable;
        if (writable == 0) return ProcmonDirWritability.AllLocked;
        return ProcmonDirWritability.Mixed;
    }
}
