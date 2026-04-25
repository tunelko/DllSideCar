using System.IO.Compression;
using System.Text.Json;
using DllSidecar.Core.Models.AdvisoryLibrary;

namespace DllSidecar.Core.Services.AdvisoryLibrary;

/// <summary>
/// Export / import a single advisory as a self-contained <c>.dsa</c> bundle:
/// a ZIP containing <c>advisory.json</c> (record + timeline + links),
/// <c>manifest.json</c> (schema version + SHA-256 of advisory.json), and a
/// mirror of the advisory's <c>attachments\&lt;id&gt;\</c> directory with all
/// rendered files and user attachments.
///
/// Designed for: backup before reinstalling, transferring cases between
/// investigators, archiving closed CVEs in immutable form. Portable across
/// DllSidecar versions via a schema-version check on import.
/// </summary>
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
        // Pull full artifact list (GetAsync doesn't populate Artifacts today).
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

        // Bundle each artifact by template_id + filename so the import can re-derive a fresh
        // path against the local vendor folder (which may be different on the importer side).
        // The on-disk layout is now <vendor>/<template>/PREFIX_NNNN.ext — files for one
        // advisory don't share a parent dir, so we iterate the artifact list, not a folder tree.
        foreach (var a in record.Artifacts)
        {
            if (string.IsNullOrEmpty(a.Path) || !File.Exists(a.Path)) continue;
            var template = a.TemplateId ?? "_attachment";
            var filename = Path.GetFileName(a.Path);
            var entryName = $"attachments/{template}/{filename}";
            zip.CreateEntryFromFile(a.Path, entryName, CompressionLevel.Optimal);
        }
    }

    /// <summary>
    /// Import a bundle and insert it into the library. If an advisory with the same id
    /// exists already, a fresh id is generated so the import doesn't clobber live data.
    /// Returns the id of the imported record (may differ from the one in the bundle).
    /// </summary>
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

        // The bundle ships the original librarian's per-vendor sequence number, which is
        // meaningless on the importer's side (their vendor namespace might already have
        // advisories with overlapping numbers). Drop it so a fresh seq gets allocated below.
        advisory.SequenceNumber = null;

        // Insert record + timeline + links first so FK-cascading cleanup works if later stages fail.
        await _repo.InsertFullAsync(advisory);

        // Allocate a new sequence number under the local vendor namespace, then materialize
        // each artifact under the new vendor/template path layout.
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
                // User-uploaded attachment with no template id — keep the original filename
                // under the vendor's _attachment subfolder.
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
