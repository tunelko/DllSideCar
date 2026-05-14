using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Per-session memoization wrapper around <see cref="DirectoryAclChecker.Check"/>.
/// A single ProcMon CSV can list thousands of NAME-NOT-FOUND rows referencing a
/// few hundred distinct directories — without caching, ProcmonPage's writability
/// gate would re-probe each dir hundreds of times (each probe writes + deletes a
/// temp file). One probe per unique path keeps the parse-completion stall under
/// a second on typical CSVs.
///
/// Case-insensitive on the path key because Windows treats paths that way and
/// ProcMon export quotes are not normalized. Instance-based so the cache dies
/// with the owning page — no stale ACLs lingering after the user closes the
/// session and reinstalls the target.
/// </summary>
public sealed class DirAclCache
{
    private readonly Dictionary<string, DirectoryPermissions> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    public DirectoryPermissions Get(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
            return new DirectoryPermissions { Path = "", Error = "Empty path" };
        if (_cache.TryGetValue(directory, out var cached)) return cached;
        var perms = DirectoryAclChecker.Check(directory);
        _cache[directory] = perms;
        return perms;
    }

    public int Count => _cache.Count;
    public void Clear() => _cache.Clear();
}
