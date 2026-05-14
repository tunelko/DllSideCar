using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Aggregate writability verdict over a row's <c>SearchedDirs</c> set. The
/// exploitability gate for CWE-427 sideloading is whether ANY of the
/// NAME-NOT-FOUND directories can be written by a low-priv user — that's the
/// slot where the planted DLL would live. The four-state tier surfaces the
/// distinctions ProcmonPage needs to color the Dir badge and decide whether
/// Promote should warn before handing off to DLL Techniques.
/// </summary>
public enum ProcmonDirWritability
{
    /// <summary>Every searched dir lets a low-priv user create files. Best-case sideload slot.</summary>
    AllLowPrivWritable,
    /// <summary>Some searched dirs are low-priv writable, others aren't. Still actionable — pick the writable one.</summary>
    Mixed,
    /// <summary>Every searched dir requires admin. Sideload would only fire from an already-elevated context.</summary>
    AllLocked,
    /// <summary>Row had no usable dirs or every probe errored (path gone, denied, malformed).</summary>
    Unknown,
}

public static class ProcmonRowWritabilityClassifier
{
    /// <summary>
    /// Cross every directory in <paramref name="searchedDirs"/> with the ACL
    /// cache and reduce to a single tier. Errors / missing dirs don't count
    /// against the tier (they fall through to <see cref="ProcmonDirWritability.Unknown"/>
    /// when there's no usable signal); when at least one dir resolved, the
    /// tier is decided by the ratio of low-priv-writable hits.
    /// </summary>
    public static ProcmonDirWritability Classify(IEnumerable<string> searchedDirs, DirAclCache cache)
    {
        int writable = 0;
        int locked = 0;
        foreach (var dir in searchedDirs)
        {
            var perms = cache.Get(dir);
            if (!string.IsNullOrEmpty(perms.Error)) continue;   // skip errored probes
            if (perms.IsLowPrivWritable) writable++;
            else locked++;
        }
        var total = writable + locked;
        if (total == 0) return ProcmonDirWritability.Unknown;
        if (writable == total) return ProcmonDirWritability.AllLowPrivWritable;
        if (writable == 0) return ProcmonDirWritability.AllLocked;
        return ProcmonDirWritability.Mixed;
    }
}
