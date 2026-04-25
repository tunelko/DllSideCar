using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models.Cve;

namespace DllSidecar.Core.Services.Cve;

/// <summary>
/// Disk cache for NVD responses. 24h TTL — NVD updates roughly daily, and we want to be
/// a well-behaved API consumer. Keyed by SHA256 of the query string to keep filenames
/// filesystem-safe.
/// </summary>
public static class CveCache
{
    public static TimeSpan DefaultTtl { get; set; } = TimeSpan.FromHours(24);

    private static readonly string CacheDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DllSidecar", "cve-cache");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static CveQueryResult? TryGet(string query)
    {
        try
        {
            var path = PathFor(query);
            if (!File.Exists(path)) return null;
            var info = new FileInfo(path);
            if (DateTime.UtcNow - info.LastWriteTimeUtc > DefaultTtl) return null;

            var json = File.ReadAllText(path);
            var result = JsonSerializer.Deserialize<CveQueryResult>(json, JsonOptions);
            if (result == null) return null;
            result.FromCache = true;
            return result;
        }
        catch (IOException ex) { Log.Debug("cve.cache", $"Read error for '{query}'", ex); }
        catch (JsonException ex) { Log.Debug("cve.cache", $"Parse error for '{query}'", ex); }
        return null;
    }

    public static void Save(string query, CveQueryResult result)
    {
        try
        {
            Directory.CreateDirectory(CacheDir);
            var path = PathFor(query);
            var json = JsonSerializer.Serialize(result, JsonOptions);
            File.WriteAllText(path, json);
        }
        catch (IOException ex) { Log.Warn("cve.cache", $"Save failed for '{query}'", ex); }
        catch (UnauthorizedAccessException ex) { Log.Warn("cve.cache", $"Access denied saving '{query}'", ex); }
    }

    public static void Clear()
    {
        try
        {
            if (Directory.Exists(CacheDir))
                Directory.Delete(CacheDir, recursive: true);
        }
        catch (IOException ex) { Log.Warn("cve.cache", "Clear failed", ex); }
    }

    private static string PathFor(string query)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(query.ToLowerInvariant())));
        return Path.Combine(CacheDir, $"{hash[..16]}.json");
    }
}
