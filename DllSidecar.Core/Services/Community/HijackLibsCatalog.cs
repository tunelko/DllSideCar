using System.Security.Cryptography;
using System.Text.Json;
using DllSidecar.Core.Models;
using DllSidecar.Core.Logging;

namespace DllSidecar.Core.Services.Community;

public sealed class HijackLibsCatalog
{
    public const string FeedUrl = "https://hijacklibs.net/api/hijacklibs.json";
    private const int MaxBytes = 16 * 1024 * 1024;
    private static readonly HttpClient Client = new() { Timeout = TimeSpan.FromSeconds(30) };
    private static readonly SemaphoreSlim UpdateGate = new(1, 1);
    private readonly Dictionary<string, List<Entry>> _byDll;
    public string Sha256 { get; }
    public DateTime RetrievedAtUtc { get; }
    public int Count => _byDll.Values.Sum(v => v.Count);
    public static string CachePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DllSidecar", "community", "hijacklibs.json");

    private HijackLibsCatalog(List<Entry> entries, string hash, DateTime retrieved)
    {
        _byDll = entries.GroupBy(e => e.Name!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
        Sha256 = hash;
        RetrievedAtUtc = retrieved;
    }

    public static HijackLibsCatalog Parse(byte[] json, DateTime retrieved)
    {
        if (json.Length > MaxBytes) throw new InvalidDataException("Community dataset exceeds size limit");
        var entries = JsonSerializer.Deserialize<List<Entry>>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true, MaxDepth = 32 })
            ?? throw new InvalidDataException("Empty community dataset");
        entries = entries.Where(e => e != null && !string.IsNullOrWhiteSpace(e.Name)
            && e.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            && e.Name == Path.GetFileName(e.Name)
            && Uri.TryCreate(e.Url, UriKind.Absolute, out var url) && url.Scheme == "https"
            && url.Host.Equals("hijacklibs.net", StringComparison.OrdinalIgnoreCase)).ToList();
        if (entries.Count == 0) throw new InvalidDataException("No usable entries in community dataset");
        return new(entries, Convert.ToHexString(SHA256.HashData(json)), retrieved);
    }

    public static HijackLibsCatalog? LoadCache()
    {
        try
        {
            if (!File.Exists(CachePath)) return null;
            if (new FileInfo(CachePath).Length > MaxBytes) return null;
            return Parse(File.ReadAllBytes(CachePath), File.GetLastWriteTimeUtc(CachePath));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        { Log.Warn("community", "Cannot read HijackLibs cache", ex); return null; }
    }

    public static async Task<HijackLibsCatalog> UpdateAsync(CancellationToken ct = default)
    {
        await UpdateGate.WaitAsync(ct);
        string? temp = null;
        try
        {
            using var response = await Client.GetAsync(FeedUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength > MaxBytes) throw new InvalidDataException("Dataset too large");
            await using var input = await response.Content.ReadAsStreamAsync(ct);
            using var output = new MemoryStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = await input.ReadAsync(buffer, ct)) > 0)
            {
                if (output.Length + count > MaxBytes) throw new InvalidDataException("Dataset too large");
                output.Write(buffer, 0, count);
            }
            var bytes = output.ToArray();
            var catalog = Parse(bytes, DateTime.UtcNow);
            Directory.CreateDirectory(Path.GetDirectoryName(CachePath)!);
            temp = CachePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            await File.WriteAllBytesAsync(temp, bytes, ct);
            File.Move(temp, CachePath, true);
            return catalog;
        }
        finally
        {
            try { if (temp != null && File.Exists(temp)) File.Delete(temp); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { Log.Warn("community", "Cannot remove temporary dataset", ex); }
            finally { UpdateGate.Release(); }
        }
    }

    public List<CommunityEvidence> Match(string dllName, IEnumerable<ImporterRef> importers)
    {
        if (!_byDll.TryGetValue(dllName, out var entries)) return [];
        var hosts = importers.Where(i => i.ExeFilename.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            && i.ResolutionKind is ImportResolutionKind.ResolvedLocal or ImportResolutionKind.ResolvedSystem or ImportResolutionKind.Unresolved).ToList();
        var results = new List<CommunityEvidence>();
        foreach (var entry in entries)
        {
            var pairs = (entry.VulnerableExecutables ?? []).Where(exe => exe != null).SelectMany(exe => hosts
                .Where(host => host.ExeFilename.Equals(Path.GetFileName(exe.Path?.Replace('/', '\\') ?? ""), StringComparison.OrdinalIgnoreCase))
                .Select(host => (host, exe))).ToList();
            if (pairs.Count == 0) results.Add(Evidence(entry, null, "", CommunityMatch.DllName));
            else foreach (var (host, exe) in pairs)
                results.Add(Evidence(entry, host.ExePath, exe.Type ?? "", CommunityMatch.ExeDllNames));
        }
        return results;
    }

    private CommunityEvidence Evidence(Entry entry, string? host, string type, CommunityMatch match) => new()
    {
        DllName = entry.Name!, Vendor = entry.Vendor ?? "", ImporterPath = host, Type = type, Match = match,
        SourceUrl = entry.Url!, DatasetSha256 = Sha256, RetrievedAtUtc = RetrievedAtUtc,
    };

    public void Enrich(ScanResults scan)
    {
        foreach (var c in scan.Existing) c.Community = Match(c.Dll.Filename, c.Importers);
        foreach (var p in scan.Phantoms) p.Community = Match(p.DllName, p.Importers);
    }

    public sealed class Entry
    {
        public string? Name { get; set; }
        public string? Vendor { get; set; }
        public string? Url { get; set; }
        public List<Executable>? VulnerableExecutables { get; set; }
    }
    public sealed class Executable
    {
        public string? Path { get; set; }
        public string? Type { get; set; }
    }
}
