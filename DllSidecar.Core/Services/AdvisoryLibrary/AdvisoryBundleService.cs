using System.IO.Compression;
using System.Text.Json;
using DllSidecar.Core.Models.AdvisoryLibrary;

namespace DllSidecar.Core.Services.AdvisoryLibrary;

/// <summary>Export / import a single advisory as a self-contained <c>.dsa</c> ZIP bundle.</summary>
public sealed class AdvisoryBundleService
{
    private const string BundleSchemaVersion = "1";
    private readonly AdvisoryRepository _repo;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public AdvisoryBundleService(AdvisoryRepository repo) { _repo = repo; }

    public async Task ExportAsync(string advisoryId, string destZipPath)
    {
        var record = await _repo.GetAsync(advisoryId)
            ?? throw new InvalidOperationException($"Advisory {advisoryId} not found.");
        // GetAsync doesn't populate Artifacts; pull them separately.
        var index = await _repo.GetArtifactsIndexAsync();
        if (index.TryGetValue(advisoryId, out var arts))
            record.Artifacts = arts;

        var advisoryJson = JsonSerializer.Serialize(record, JsonOpts);
        var manifest = new BundleManifest
        {
            SchemaVersion = BundleSchemaVersion,
            AdvisoryId = advisoryId,
            ExportedAtUtc = DateTime.UtcNow,
            AdvisoryJsonSha256 = Sha256Hex(advisoryJson),
            ArtifactCount = record.Artifacts.Count,
        };
        var manifestJson = JsonSerializer.Serialize(manifest, JsonOpts);

        if (File.Exists(destZipPath)) File.Delete(destZipPath);
        using var zip = ZipFile.Open(destZipPath, ZipArchiveMode.Create);

        AddEntry(zip, "manifest.json", manifestJson);
        AddEntry(zip, "advisory.json", advisoryJson);

        // Bundle by template_id + filename so import can rebuild paths against the local vendor folder.
        foreach (var a in record.Artifacts)
        {
            if (string.IsNullOrEmpty(a.Path) || !File.Exists(a.Path)) continue;
            var template = a.TemplateId ?? "_attachment";
            var filename = Path.GetFileName(a.Path);
            var entryName = $"attachments/{template}/{filename}";
            zip.CreateEntryFromFile(a.Path, entryName, CompressionLevel.Optimal);
        }
    }

    /// <summary>Import a bundle; reassigns id on collision. Returns the imported id.</summary>
    public async Task<string> ImportAsync(string srcZipPath)
    {
        if (!File.Exists(srcZipPath)) throw new FileNotFoundException(srcZipPath);

        using var zip = ZipFile.OpenRead(srcZipPath);
        var manifestEntry = zip.GetEntry("manifest.json") ?? throw new InvalidDataException("manifest.json missing — not a DllSidecar bundle.");
        var advisoryEntry = zip.GetEntry("advisory.json") ?? throw new InvalidDataException("advisory.json missing.");

        var manifest = ReadJson<BundleManifest>(manifestEntry)
            ?? throw new InvalidDataException("manifest.json unreadable.");
        if (manifest.SchemaVersion != BundleSchemaVersion)
            throw new InvalidDataException($"Bundle schema {manifest.SchemaVersion} is not supported by this build (expected {BundleSchemaVersion}).");

        var advisory = ReadJson<AdvisoryRecord>(advisoryEntry)
            ?? throw new InvalidDataException("advisory.json unreadable.");

        // Hash check — detects truncation or tampering.
        string advJsonText;
        using (var s = advisoryEntry.Open())
        using (var sr = new StreamReader(s)) advJsonText = sr.ReadToEnd();
        if (!string.IsNullOrEmpty(manifest.AdvisoryJsonSha256)
            && !string.Equals(manifest.AdvisoryJsonSha256, Sha256Hex(advJsonText), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("advisory.json SHA-256 doesn't match manifest — bundle corrupted or tampered.");
        }

        // If the id already exists locally, assign a new one to avoid collision.
        var existing = await _repo.GetAsync(advisory.Id);
        if (existing != null)
        {
            var newId = Guid.NewGuid().ToString("N")[..10];
            RemapAdvisoryId(advisory, newId);
        }

        // Drop the source librarian's sequence; allocate a fresh one in the local vendor namespace.
        advisory.SequenceNumber = null;

        await _repo.InsertFullAsync(advisory);

        var seq = await _repo.EnsureSequenceAsync(advisory.Id);
        var vulnType = string.IsNullOrWhiteSpace(advisory.VulnerabilityType)
            ? "DLL Sideloading" : advisory.VulnerabilityType;

        foreach (var a in advisory.Artifacts)
        {
            var template = a.TemplateId ?? "";
            var filename = Path.GetFileName(a.Path);
            var entryName = $"attachments/{(string.IsNullOrEmpty(template) ? "_attachment" : template)}/{filename}";
            var entry = zip.GetEntry(entryName);
            if (entry == null) continue;

            string newPath;
            if (string.IsNullOrEmpty(template))
            {
                // User-uploaded attachment: keep original filename under vendor's _attachment folder.
                newPath = Path.Combine(AdvisoryRepository.GetVendorDir(advisory.Vendor), "_attachment", filename);
            }
            else
            {
                var ext = Path.GetExtension(filename);
                if (string.IsNullOrEmpty(ext)) ext = ".txt";
                newPath = AdvisoryRepository.BuildArtifactPath(advisory.Vendor, template, vulnType, seq, ext);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(newPath)!);
            entry.ExtractToFile(newPath, overwrite: true);
            await _repo.UpdateArtifactPathAsync(a.Id, newPath);
        }

        return advisory.Id;
    }

    private static void RemapAdvisoryId(AdvisoryRecord advisory, string newId)
    {
        advisory.Id = newId;
        foreach (var t in advisory.Timeline) t.AdvisoryId = newId;
        foreach (var a in advisory.Artifacts) a.AdvisoryId = newId;
        foreach (var l in advisory.Links) l.AdvisoryId = newId;
    }

    private static void AddEntry(ZipArchive zip, string name, string content)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        using var w = new StreamWriter(entry.Open(), new System.Text.UTF8Encoding(false));
        w.Write(content);
    }

    private static T? ReadJson<T>(ZipArchiveEntry entry)
    {
        using var s = entry.Open();
        return JsonSerializer.Deserialize<T>(s, JsonOpts);
    }

    private static string Sha256Hex(string text)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    }

    public sealed class BundleManifest
    {
        public string SchemaVersion { get; set; } = "";
        public string AdvisoryId { get; set; } = "";
        public DateTime ExportedAtUtc { get; set; }
        public string? AdvisoryJsonSha256 { get; set; }
        public int ArtifactCount { get; set; }
    }
}
