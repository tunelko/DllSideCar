using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Per-session, case-insensitive memoization wrapper around <see cref="DirectoryAclChecker.Check"/>.
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

    /// <summary>
    /// Pre-seed a permissions entry; intended for tests.
    /// </summary>
    public void Seed(string directory, DirectoryPermissions perms) => _cache[directory] = perms;
}
