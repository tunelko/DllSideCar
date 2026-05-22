using Microsoft.Data.Sqlite;
using DllSidecar.Core.Models.Advisory;
using DllSidecar.Core.Models.AdvisoryLibrary;

namespace DllSidecar.Core.Services.AdvisoryLibrary;

/// <summary>
/// SQLite-backed repository for the Advisory Library (Fase 7c.1).
/// DB lives at %LOCALAPPDATA%\DllSidecar\advisories\library.db and is created on first use.
/// Schema defined in spec ADVISORY_LIBRARY_SPEC.md; schema_info table carries version "1".
/// </summary>
public sealed class AdvisoryRepository
{
    private const string SchemaVersion = "8";

    private static readonly string BaseDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DllSidecar", "advisories");

    public static string DbPath => Path.Combine(BaseDir, "library.db");

    private readonly string _connectionString;

    public AdvisoryRepository()
    {
        Directory.CreateDirectory(BaseDir);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
        }.ToString();
    }

    public async Task InitializeAsync()
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();

        await using (var pragma = conn.CreateCommand())
        {
            pragma.CommandText = "PRAGMA foreign_keys = ON;";
            await pragma.ExecuteNonQueryAsync();
        }

        await ExecNonQueryAsync(conn, SchemaSql);

        // Stamp or migrate schema version
        await using var check = conn.CreateCommand();
        check.CommandText = "SELECT value FROM schema_info WHERE key='version';";
        var existing = await check.ExecuteScalarAsync() as string;
        if (existing == null)
        {
            await using var ins = conn.CreateCommand();
            ins.CommandText = "INSERT INTO schema_info(key,value) VALUES('version',$v);";
            ins.Parameters.AddWithValue("$v", SchemaVersion);
            await ins.ExecuteNonQueryAsync();
        }
        else if (existing != SchemaVersion)
        {
            // v1 → v2: add template_id to advisory_artifacts
            if (existing == "1")
            {
                try { await ExecNonQueryAsync(conn, "ALTER TABLE advisory_artifacts ADD COLUMN template_id TEXT;"); }
                catch { /* column may already exist from a previous partial migration — ignore */ }
                existing = "2";
            }
            // v2 → v3: soft-delete columns on advisory_records
            if (existing == "2")
            {
                try { await ExecNonQueryAsync(conn, "ALTER TABLE advisory_records ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;"); }
                catch { /* idempotent */ }
                try { await ExecNonQueryAsync(conn, "ALTER TABLE advisory_records ADD COLUMN deleted_at_utc TEXT;"); }
                catch { /* idempotent */ }
                existing = "3";
            }
            // v3 → v4: Template Fields persistence — classification, vendor PoC, affected
            // components/requirements/solution, CVSS v4, researcher PGP overrides.
            if (existing == "3")
            {
                foreach (var col in V4NewColumns)
                {
                    try { await ExecNonQueryAsync(conn, $"ALTER TABLE advisory_records ADD COLUMN {col};"); }
                    catch { /* idempotent — column may already exist from a partial migration */ }
                }
                existing = "4";
            }
            // v4 → v5: persist the active template per advisory so reopen restores the renderer
            // (previously every reopen reverted to Markdown and could overwrite non-Markdown bodies).
            if (existing == "4")
            {
                try { await ExecNonQueryAsync(conn, "ALTER TABLE advisory_records ADD COLUMN last_template_id TEXT;"); }
                catch { /* idempotent */ }
                existing = "5";
            }
            // v5 → v6: per-vendor sequence number (used to build human-readable filenames like
            // DLL_SIDELOADING_ADVISORY_0001.txt). Allocated lazily on first write that needs it,
            // never reused — soft-deleted rows still hold their slot to keep numbers stable.
            if (existing == "5")
            {
                try { await ExecNonQueryAsync(conn, "ALTER TABLE advisory_records ADD COLUMN sequence_number INTEGER;"); }
                catch { /* idempotent */ }
                existing = "6";
            }
            // v6 → v7: per-artifact workflow status. Each format tracks its own state because
            // submission lifecycles differ (markdown → blog, ghsa → GitHub). Backfill from the
            // parent record so existing rows keep visible status.
            if (existing == "6")
            {
                try { await ExecNonQueryAsync(conn, "ALTER TABLE advisory_artifacts ADD COLUMN status INTEGER NOT NULL DEFAULT 0;"); }
                catch { /* idempotent */ }
                try { await ExecNonQueryAsync(conn, @"
                    UPDATE advisory_artifacts SET status = (
                        SELECT r.status FROM advisory_records r WHERE r.id = advisory_artifacts.advisory_id
                    ) WHERE status = 0;"); }
                catch { /* best effort */ }
                existing = "7";
            }
            // v7 → v8: drop the four classification / external-ranking columns that backed a
            // template renderer pruned from the registry, plus a sweep of any artifact rows
            // (and their backing files on disk) produced by that renderer. Best-effort — the
            // ALTER TABLE DROP COLUMN form requires SQLite >= 3.35 (March 2021); on older
            // engines the columns are simply ignored by the rest of the code path.
            if (existing == "7")
            {
                // First unlink the physical artifact files so we don't orphan them once the
                // DB rows go. Snapshot paths in a list — iterating the reader while issuing
                // another command on the same connection deadlocks SQLite.
                var orphanPaths = new List<string>();
                try
                {
                    await using var sel = conn.CreateCommand();
                    sel.CommandText = "SELECT path FROM advisory_artifacts WHERE template_id = 'incibe';";
                    await using var rdr = await sel.ExecuteReaderAsync();
                    while (await rdr.ReadAsync())
                        if (!rdr.IsDBNull(0)) orphanPaths.Add(rdr.GetString(0));
                }
                catch { /* artifact table might not exist yet on a freshly-created v8 schema */ }

                foreach (var p in orphanPaths)
                {
                    try { if (File.Exists(p)) File.Delete(p); } catch { /* best effort */ }
                }

                try { await ExecNonQueryAsync(conn, "DELETE FROM advisory_artifacts WHERE template_id = 'incibe';"); }
                catch { /* idempotent */ }

                foreach (var col in new[] { "attack_type", "impact_category", "incibe_ranking_opt_in", "incibe_public_display_name" })
                {
                    try { await ExecNonQueryAsync(conn, $"ALTER TABLE advisory_records DROP COLUMN {col};"); }
                    catch { /* idempotent / unsupported on legacy SQLite — column becomes dead weight */ }
                }
                existing = "8";
            }
            await using var updVersion = conn.CreateCommand();
            updVersion.CommandText = "UPDATE schema_info SET value=$v WHERE key='version';";
            updVersion.Parameters.AddWithValue("$v", SchemaVersion);
            await updVersion.ExecuteNonQueryAsync();
        }
    }

    public async Task<AdvisoryRecord> CreateFromContextAsync(AdvisoryContext ctx, string markdownBody,
        AdvisoryCreateOptions? options = null)
    {
        var now = DateTime.UtcNow;
        var record = new AdvisoryRecord
        {
            Id = Guid.NewGuid().ToString("N")[..10],
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
            Status = AdvisoryStatus.Draft,
            Title = InterpolateTitle(ctx),
            Vendor = ctx.Vendor,
            Product = ctx.Product,
            ProductVersion = ctx.Version,
            Architecture = ctx.Architecture,
            PePath = ctx.PePath,
            PeFilename = ctx.PeFilename,
            InstallDirectory = ctx.InstallDirectory,
            VulnerabilityType = ctx.VulnType,
            CweId = ctx.Cwe,
            CweName = ctx.CweName,
            ResearcherName = ctx.ResearcherName,
            ResearcherHandle = ctx.ResearcherHandle,
            ResearcherBlog = ctx.ResearcherBlog,
            ResearcherEmail = ctx.ResearcherEmail,
            PayloadDescription = ctx.PayloadDescription,
            ImporterExe = ctx.ImporterExe,
            GeneratedDllPath = ctx.GeneratedDllPath,
            DirectoryLowPrivWritable = ctx.DirectoryLowPrivWritable,
            WritableByPrincipals = ctx.WritableByPrincipals,
            CvssVector = ctx.Cvss?.VectorString,
            CvssScore = ctx.CvssScore > 0 ? ctx.CvssScore : null,
            CvssSeverity = ctx.CvssSeverity,
            DisclosurePolicy = ctx.DisclosurePolicy,
            DiscoveredOn = ctx.DiscoveredOn == default ? null : ctx.DiscoveredOn,
            ReportedOn = ctx.ReportedOn,
            DisclosedOn = ctx.DisclosedOn,
            MarkdownBody = markdownBody,
            SourceScanDir = options?.SourceScanDir,
            SourceCandidateKind = options?.SourceCandidateKind,
            SourceCandidateKey = options?.SourceCandidateKey,
            // Template Fields (schema v4) — copy verbatim from ctx; reload uses ConfigManager
            // fallback for the researcher-identity fields when these come back null.
            VulnerabilityTypeText = NullIfBlank(ctx.VulnerabilityTypeText),
            VendorUrl = NullIfBlank(ctx.VendorUrl),
            VendorPocName = NullIfBlank(ctx.VendorPocName),
            VendorPocEmail = NullIfBlank(ctx.VendorPocEmail),
            DeviceUrlReference = NullIfBlank(ctx.DeviceUrlReference),
            DeviceBriefSummary = NullIfBlank(ctx.DeviceBriefSummary),
            AffectedComponents = NullIfBlank(ctx.AffectedComponents),
            PreviousRequirements = NullIfBlank(ctx.PreviousRequirements),
            ProposedSolution = NullIfBlank(ctx.ProposedSolution),
            HasContactedVendorNote = NullIfBlank(ctx.HasContactedVendorNote),
            CvssV4Vector = NullIfBlank(ctx.CvssV4?.VectorString),
            CvssV4Score = ctx.CvssV4Score > 0 ? ctx.CvssV4Score : null,
            CvssV4Severity = NullIfBlank(ctx.CvssV4Severity),
            ResearcherPgpFingerprint = NullIfBlank(ctx.ResearcherPgpFingerprint),
            ResearcherPgpKeyId = NullIfBlank(ctx.ResearcherPgpKeyId),
            LastTemplateId = options?.LastTemplateId,
        };

        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        await InsertRecordAsync(conn, tx, record);
        await InsertTimelineAsync(conn, tx, record.Id, TimelineEventKind.Created, "Created from AdvisoryPage", null, null, null);

        await tx.CommitAsync();
        return record;
    }

    /// <summary>
    /// Insert a fully-formed advisory (record + timeline + artifacts + links) in one transaction.
    /// Used by the .dsa import path. Caller is responsible for ensuring the id doesn't collide.
    /// </summary>
    public async Task InsertFullAsync(AdvisoryRecord record)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        await InsertRecordAsync(conn, tx, record);

        foreach (var t in record.Timeline)
        {
            await using var tlc = conn.CreateCommand();
            tlc.Transaction = tx;
            tlc.CommandText = @"INSERT INTO advisory_timeline_events
                (advisory_id, event_kind, event_at_utc, title, note, old_status, new_status)
                VALUES ($aid, $kind, $at, $title, $note, $old, $new);";
            tlc.Parameters.AddWithValue("$aid", record.Id);
            tlc.Parameters.AddWithValue("$kind", (int)t.EventKind);
            tlc.Parameters.AddWithValue("$at", FormatUtc(t.EventAtUtc));
            tlc.Parameters.AddWithValue("$title", t.Title);
            tlc.Parameters.AddWithValue("$note", (object?)t.Note ?? DBNull.Value);
            tlc.Parameters.AddWithValue("$old", t.OldStatus.HasValue ? (object)(int)t.OldStatus.Value : DBNull.Value);
            tlc.Parameters.AddWithValue("$new", t.NewStatus.HasValue ? (object)(int)t.NewStatus.Value : DBNull.Value);
            await tlc.ExecuteNonQueryAsync();
        }

        await InsertTimelineAsync(conn, tx, record.Id, TimelineEventKind.Imported, "Imported from .dsa bundle", null, null, null);

        foreach (var a in record.Artifacts)
        {
            await using var ac = conn.CreateCommand();
            ac.Transaction = tx;
            ac.CommandText = @"INSERT INTO advisory_artifacts
                (advisory_id, artifact_kind, path, label, sha256, created_at_utc, template_id, status)
                VALUES ($aid, $kind, $path, $label, $sha, $at, $tpl, $status);";
            ac.Parameters.AddWithValue("$aid", record.Id);
            ac.Parameters.AddWithValue("$kind", (int)a.ArtifactKind);
            ac.Parameters.AddWithValue("$path", a.Path);
            ac.Parameters.AddWithValue("$label", (object?)a.Label ?? DBNull.Value);
            ac.Parameters.AddWithValue("$sha", (object?)a.Sha256 ?? DBNull.Value);
            ac.Parameters.AddWithValue("$at", FormatUtc(a.CreatedAtUtc));
            ac.Parameters.AddWithValue("$tpl", (object?)a.TemplateId ?? DBNull.Value);
            ac.Parameters.AddWithValue("$status", (int)a.Status);
            await ac.ExecuteNonQueryAsync();
        }

        foreach (var l in record.Links)
        {
            await using var lc = conn.CreateCommand();
            lc.Transaction = tx;
            lc.CommandText = @"INSERT INTO advisory_links
                (advisory_id, link_kind, value, label)
                VALUES ($aid, $kind, $value, $label);";
            lc.Parameters.AddWithValue("$aid", record.Id);
            lc.Parameters.AddWithValue("$kind", (int)l.LinkKind);
            lc.Parameters.AddWithValue("$value", l.Value);
            lc.Parameters.AddWithValue("$label", (object?)l.Label ?? DBNull.Value);
            await lc.ExecuteNonQueryAsync();
        }

        await tx.CommitAsync();
    }

    /// <summary>Patch the on-disk path of an existing artifact row (used after bundle import remaps files).</summary>
    public async Task UpdateArtifactPathAsync(long artifactId, string newPath)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE advisory_artifacts SET path=$p WHERE id=$id;";
        cmd.Parameters.AddWithValue("$p", newPath);
        cmd.Parameters.AddWithValue("$id", artifactId);
        await cmd.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Allocate the per-vendor sequence number for the given advisory if it doesn't yet
    /// have one, and return the current value. Used by bundle import (where artifacts
    /// arrive without going through WriteArtifactAsync) and by the file migration script.
    /// </summary>
    public async Task<int> EnsureSequenceAsync(string advisoryId)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        string? vendor = null;
        int? seq = null;
        await using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = "SELECT vendor, sequence_number FROM advisory_records WHERE id=$id;";
            sel.Parameters.AddWithValue("$id", advisoryId);
            await using var r = await sel.ExecuteReaderAsync();
            if (!await r.ReadAsync())
                throw new InvalidOperationException($"Advisory {advisoryId} not found");
            vendor = r.IsDBNull(0) ? null : r.GetString(0);
            seq = r.IsDBNull(1) ? null : r.GetInt32(1);
        }

        if (seq is null)
        {
            seq = await AllocateSequenceForVendorAsync(conn, tx, vendor);
            await using var upd = conn.CreateCommand();
            upd.Transaction = tx;
            upd.CommandText = "UPDATE advisory_records SET sequence_number=$s WHERE id=$id;";
            upd.Parameters.AddWithValue("$s", seq.Value);
            upd.Parameters.AddWithValue("$id", advisoryId);
            await upd.ExecuteNonQueryAsync();
        }

        await tx.CommitAsync();
        return seq.Value;
    }

    public async Task<AdvisoryRecord?> GetAsync(string id)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = SelectRecordSql + " WHERE id = $id;";
        cmd.Parameters.AddWithValue("$id", id);

        AdvisoryRecord? record = null;
        await using (var r = await cmd.ExecuteReaderAsync())
        {
            if (await r.ReadAsync()) record = ReadRecord(r);
        }
        if (record == null) return null;

        await using (var tl = conn.CreateCommand())
        {
            tl.CommandText = @"SELECT id, advisory_id, event_kind, event_at_utc, title, note, old_status, new_status
                               FROM advisory_timeline_events WHERE advisory_id=$id
                               ORDER BY event_at_utc ASC, id ASC;";
            tl.Parameters.AddWithValue("$id", id);
            await using var r = await tl.ExecuteReaderAsync();
            while (await r.ReadAsync())
            {
                record.Timeline.Add(new AdvisoryTimelineEvent
                {
                    Id = r.GetInt64(0),
                    AdvisoryId = r.GetString(1),
                    EventKind = (TimelineEventKind)r.GetInt32(2),
                    EventAtUtc = ParseUtc(r.GetString(3)),
                    Title = r.GetString(4),
                    Note = r.IsDBNull(5) ? null : r.GetString(5),
                    OldStatus = r.IsDBNull(6) ? null : (AdvisoryStatus)r.GetInt32(6),
                    NewStatus = r.IsDBNull(7) ? null : (AdvisoryStatus)r.GetInt32(7),
                });
            }
        }
        return record;
    }

    public async Task<IReadOnlyList<AdvisoryRecordListItem>> ListAsync(AdvisoryQuery query)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();

        var sql = @"SELECT r.id, r.status, r.title, r.vendor, r.product, r.product_version,
                           r.updated_at_utc,
                           (SELECT COUNT(1) FROM advisory_timeline_events t WHERE t.advisory_id=r.id) AS tlc
                    FROM advisory_records r
                    WHERE r.is_deleted = 0";
        var args = new List<(string, object)>();
        if (query.Status.HasValue)
        {
            sql += " AND r.status = $status";
            args.Add(("$status", (int)query.Status.Value));
        }
        if (!string.IsNullOrWhiteSpace(query.Vendor))
        {
            sql += " AND LOWER(r.vendor) = LOWER($vendor)";
            args.Add(("$vendor", query.Vendor));
        }
        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            sql += @" AND (LOWER(r.title) LIKE $s
                     OR LOWER(r.vendor) LIKE $s
                     OR LOWER(r.product) LIKE $s
                     OR LOWER(r.pe_filename) LIKE $s)";
            args.Add(("$s", $"%{query.Search.ToLowerInvariant()}%"));
        }
        sql += " ORDER BY r.updated_at_utc DESC LIMIT $lim;";
        args.Add(("$lim", query.Limit));

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (k, v) in args) cmd.Parameters.AddWithValue(k, v);

        var list = new List<AdvisoryRecordListItem>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(new AdvisoryRecordListItem
            {
                Id = reader.GetString(0),
                Status = (AdvisoryStatus)reader.GetInt32(1),
                Title = reader.GetString(2),
                Vendor = reader.IsDBNull(3) ? null : reader.GetString(3),
                Product = reader.IsDBNull(4) ? null : reader.GetString(4),
                ProductVersion = reader.IsDBNull(5) ? null : reader.GetString(5),
                UpdatedAtUtc = ParseUtc(reader.GetString(6)),
                TimelineCount = reader.GetInt32(7),
            });
        }
        return list;
    }

    public async Task SaveDraftAsync(AdvisoryRecord record)
    {
        record.UpdatedAtUtc = DateTime.UtcNow;
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        await using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = UpdateRecordSql;
            BindRecordParameters(cmd, record, includeId: true);
            await cmd.ExecuteNonQueryAsync();
        }
        await InsertTimelineAsync(conn, tx, record.Id, TimelineEventKind.Edited, "Draft saved", null, null, null);
        await tx.CommitAsync();
    }

    /// <summary>
    /// Update the workflow status of a single artifact (per-format independence). Used when
    /// the user changes status from a FileLeaf in the Library tree — only that artifact's
    /// pill flips, sibling artifacts of the same advisory keep their own state. Emits a
    /// timeline event scoped with the template id so history is auditable per-format.
    /// </summary>
    public async Task UpdateArtifactStatusAsync(long artifactId, AdvisoryStatus newStatus, string? note = null)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        string advisoryId = "";
        string? templateId = null;
        AdvisoryStatus? oldStatus = null;
        await using (var cur = conn.CreateCommand())
        {
            cur.Transaction = tx;
            cur.CommandText = "SELECT advisory_id, template_id, status FROM advisory_artifacts WHERE id=$id;";
            cur.Parameters.AddWithValue("$id", artifactId);
            await using var r = await cur.ExecuteReaderAsync();
            if (!await r.ReadAsync())
            {
                await tx.RollbackAsync();
                throw new InvalidOperationException($"Artifact {artifactId} not found");
            }
            advisoryId = r.GetString(0);
            templateId = r.IsDBNull(1) ? null : r.GetString(1);
            oldStatus = (AdvisoryStatus)r.GetInt32(2);
        }

        await using (var upd = conn.CreateCommand())
        {
            upd.Transaction = tx;
            upd.CommandText = "UPDATE advisory_artifacts SET status=$s WHERE id=$id;";
            upd.Parameters.AddWithValue("$s", (int)newStatus);
            upd.Parameters.AddWithValue("$id", artifactId);
            await upd.ExecuteNonQueryAsync();
        }

        var label = templateId is null ? "attachment" : templateId.ToUpperInvariant();
        var title = $"[{label}] Status → {newStatus}";
        await InsertTimelineAsync(conn, tx, advisoryId, TimelineEventKind.StatusChanged, title, note, oldStatus, newStatus);

        // Touch the parent advisory's updated_at so it bubbles to the top of recent lists.
        await using (var touch = conn.CreateCommand())
        {
            touch.Transaction = tx;
            touch.CommandText = "UPDATE advisory_records SET updated_at_utc=$u WHERE id=$id;";
            touch.Parameters.AddWithValue("$u", FormatUtc(DateTime.UtcNow));
            touch.Parameters.AddWithValue("$id", advisoryId);
            await touch.ExecuteNonQueryAsync();
        }

        await tx.CommitAsync();
    }

    public async Task UpdateStatusAsync(string id, AdvisoryStatus newStatus, string? note = null)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        AdvisoryStatus? oldStatus = null;
        await using (var cur = conn.CreateCommand())
        {
            cur.Transaction = tx;
            cur.CommandText = "SELECT status FROM advisory_records WHERE id=$id;";
            cur.Parameters.AddWithValue("$id", id);
            var v = await cur.ExecuteScalarAsync();
            if (v is long l) oldStatus = (AdvisoryStatus)(int)l;
        }
        if (oldStatus == null)
        {
            await tx.RollbackAsync();
            throw new InvalidOperationException($"Advisory {id} not found");
        }

        await using (var upd = conn.CreateCommand())
        {
            upd.Transaction = tx;
            upd.CommandText = "UPDATE advisory_records SET status=$s, updated_at_utc=$u WHERE id=$id;";
            upd.Parameters.AddWithValue("$s", (int)newStatus);
            upd.Parameters.AddWithValue("$u", FormatUtc(DateTime.UtcNow));
            upd.Parameters.AddWithValue("$id", id);
            await upd.ExecuteNonQueryAsync();
        }

        var title = $"Status → {newStatus}";
        await InsertTimelineAsync(conn, tx, id, TimelineEventKind.StatusChanged, title, note, oldStatus, newStatus);
        await tx.CommitAsync();
    }

    public async Task AddTimelineEventAsync(string id, TimelineEventKind kind, string title, string? note = null)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();
        await InsertTimelineAsync(conn, tx, id, kind, title, note, null, null);
        await using (var touch = conn.CreateCommand())
        {
            touch.Transaction = tx;
            touch.CommandText = "UPDATE advisory_records SET updated_at_utc=$u WHERE id=$id;";
            touch.Parameters.AddWithValue("$u", FormatUtc(DateTime.UtcNow));
            touch.Parameters.AddWithValue("$id", id);
            await touch.ExecuteNonQueryAsync();
        }
        await tx.CommitAsync();
    }

    /// <summary>
    /// Soft-delete: flips the record's is_deleted flag so it disappears from the main list
    /// but stays in the DB and lands in the Trash group, recoverable via <see cref="RestoreAsync"/>.
    /// Preferred over <see cref="PermanentDeleteAsync"/> for the UI's default delete action.
    /// </summary>
    public async Task DeleteAsync(string id) => await SoftDeleteAsync(id);

    public async Task SoftDeleteAsync(string id)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        await using (var upd = conn.CreateCommand())
        {
            upd.Transaction = tx;
            upd.CommandText = @"UPDATE advisory_records
                                SET is_deleted = 1, deleted_at_utc = $at, updated_at_utc = $at
                                WHERE id = $id;";
            upd.Parameters.AddWithValue("$at", FormatUtc(DateTime.UtcNow));
            upd.Parameters.AddWithValue("$id", id);
            await upd.ExecuteNonQueryAsync();
        }
        await InsertTimelineAsync(conn, tx, id, TimelineEventKind.Note, "Moved to Trash", null, null, null);
        await tx.CommitAsync();
    }

    public async Task RestoreAsync(string id)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        await using (var upd = conn.CreateCommand())
        {
            upd.Transaction = tx;
            upd.CommandText = @"UPDATE advisory_records
                                SET is_deleted = 0, deleted_at_utc = NULL, updated_at_utc = $at
                                WHERE id = $id;";
            upd.Parameters.AddWithValue("$at", FormatUtc(DateTime.UtcNow));
            upd.Parameters.AddWithValue("$id", id);
            await upd.ExecuteNonQueryAsync();
        }
        await InsertTimelineAsync(conn, tx, id, TimelineEventKind.Note, "Restored from Trash", null, null, null);
        await tx.CommitAsync();
    }

    /// <summary>
    /// Permanent removal: enumerate the advisory's artifact files (now scattered under
    /// <c>vendor/template/PREFIX_NNNN.ext</c>), unlink each, then DELETE the row (cascades
    /// timeline/artifacts/links via FK). Irreversible. Only exposed in the Trash view.
    /// </summary>
    public async Task PermanentDeleteAsync(string id)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();

        // Collect artifact paths first so we can unlink them after the cascade delete.
        var paths = new List<string>();
        await using (var sel = conn.CreateCommand())
        {
            sel.CommandText = "SELECT path FROM advisory_artifacts WHERE advisory_id=$id;";
            sel.Parameters.AddWithValue("$id", id);
            await using var r = await sel.ExecuteReaderAsync();
            while (await r.ReadAsync()) paths.Add(r.GetString(0));
        }

        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "PRAGMA foreign_keys=ON; DELETE FROM advisory_records WHERE id=$id;";
            cmd.Parameters.AddWithValue("$id", id);
            await cmd.ExecuteNonQueryAsync();
        }

        foreach (var p in paths)
        {
            try { if (File.Exists(p)) File.Delete(p); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// Return a dictionary keyed by SourceCandidateKey (set at CreateFromContext time, e.g.
    /// "existing|C:\Foo\bar.dll") with a compact reference to the advisory behind it. Used
    /// by ScanPage to stamp a REPORTED badge on rows that already have a Library entry.
    /// </summary>
    public async Task<Dictionary<string, ReportedRef>> GetReportedBySourceKeyAsync()
    {
        var map = new Dictionary<string, ReportedRef>(StringComparer.OrdinalIgnoreCase);
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT id, title, status, source_candidate_key, updated_at_utc
                            FROM advisory_records
                            WHERE is_deleted = 0 AND source_candidate_key IS NOT NULL AND source_candidate_key <> '';";
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var key = r.GetString(3);
            map[key] = new ReportedRef
            {
                AdvisoryId = r.GetString(0),
                Title = r.GetString(1),
                Status = (AdvisoryStatus)r.GetInt32(2),
                UpdatedAtUtc = ParseUtc(r.GetString(4)),
            };
        }
        return map;
    }

    /// <summary>Lightweight ScanPage-facing reference.</summary>
    public sealed class ReportedRef
    {
        public string AdvisoryId { get; set; } = "";
        public string Title { get; set; } = "";
        public AdvisoryStatus Status { get; set; }
        public DateTime UpdatedAtUtc { get; set; }
    }

    /// <summary>Fetch the list of soft-deleted records for the Trash group in the library tree.</summary>
    public async Task<IReadOnlyList<AdvisoryRecordListItem>> ListDeletedAsync()
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT r.id, r.status, r.title, r.vendor, r.product, r.product_version,
                                   COALESCE(r.deleted_at_utc, r.updated_at_utc) AS du,
                                   (SELECT COUNT(1) FROM advisory_timeline_events t WHERE t.advisory_id=r.id)
                            FROM advisory_records r
                            WHERE r.is_deleted = 1
                            ORDER BY du DESC;";
        var list = new List<AdvisoryRecordListItem>();
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            list.Add(new AdvisoryRecordListItem
            {
                Id = r.GetString(0),
                Status = (AdvisoryStatus)r.GetInt32(1),
                Title = r.GetString(2),
                Vendor = r.IsDBNull(3) ? null : r.GetString(3),
                Product = r.IsDBNull(4) ? null : r.GetString(4),
                ProductVersion = r.IsDBNull(5) ? null : r.GetString(5),
                UpdatedAtUtc = ParseUtc(r.GetString(6)),
                TimelineCount = r.GetInt32(7),
            });
        }
        return list;
    }

    /// <summary>
    /// Reassign a single advisory to a different vendor (drag-and-drop between folders).
    /// Re-allocates the sequence_number under the new vendor (the old number stays in the
    /// source vendor's history as a hole — no shifting / renumbering of siblings) and
    /// physically moves the artifact files from the old vendor folder to the new one.
    /// All artifact paths in the DB are rewritten to match.
    /// </summary>
    public async Task MoveAdvisoryToVendorAsync(string advisoryId, string newVendor)
    {
        if (string.IsNullOrWhiteSpace(newVendor)) throw new ArgumentException("vendor name cannot be empty", nameof(newVendor));
        newVendor = newVendor.Trim();

        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        // Snapshot current state inside the tx so the rest of the operation is consistent.
        string? oldVendor = null;
        string vulnType = "DLL Sideloading";
        await using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = "SELECT vendor, vulnerability_type FROM advisory_records WHERE id=$id;";
            sel.Parameters.AddWithValue("$id", advisoryId);
            await using var r = await sel.ExecuteReaderAsync();
            if (!await r.ReadAsync())
                throw new InvalidOperationException($"Advisory {advisoryId} not found");
            oldVendor = r.IsDBNull(0) ? null : r.GetString(0);
            if (!r.IsDBNull(1) && !string.IsNullOrWhiteSpace(r.GetString(1))) vulnType = r.GetString(1);
        }

        // Allocate fresh sequence under the destination vendor (NULL out the old one
        // so AllocateSequence sees a clean slot to assign).
        var newSeq = await AllocateSequenceForVendorAsync(conn, tx, newVendor);

        await using (var upd = conn.CreateCommand())
        {
            upd.Transaction = tx;
            upd.CommandText = @"UPDATE advisory_records
                                SET vendor=$v, sequence_number=$s, updated_at_utc=$u
                                WHERE id=$id;";
            upd.Parameters.AddWithValue("$v", newVendor);
            upd.Parameters.AddWithValue("$s", newSeq);
            upd.Parameters.AddWithValue("$u", FormatUtc(DateTime.UtcNow));
            upd.Parameters.AddWithValue("$id", advisoryId);
            await upd.ExecuteNonQueryAsync();
        }

        // Compute new path per artifact, move file, persist new path. We snapshot the
        // current rows first to avoid iterating live results.
        var artifactUpdates = new List<(long Id, string OldPath, string NewPath)>();
        await using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = "SELECT id, template_id, path FROM advisory_artifacts WHERE advisory_id=$id;";
            sel.Parameters.AddWithValue("$id", advisoryId);
            await using var r = await sel.ExecuteReaderAsync();
            while (await r.ReadAsync())
            {
                var aid = r.GetInt64(0);
                var template = r.IsDBNull(1) ? null : r.GetString(1);
                var oldPath = r.GetString(2);
                if (string.IsNullOrEmpty(template)) continue; // attachments not handled here yet
                var ext = Path.GetExtension(oldPath);
                if (string.IsNullOrEmpty(ext)) ext = ExtensionForTemplate(template);
                var newPath = BuildArtifactPath(newVendor, template, vulnType, newSeq, ext);
                artifactUpdates.Add((aid, oldPath, newPath));
            }
        }

        foreach (var (aid, oldPath, newPath) in artifactUpdates)
        {
            await using var updPath = conn.CreateCommand();
            updPath.Transaction = tx;
            updPath.CommandText = "UPDATE advisory_artifacts SET path=$p WHERE id=$id;";
            updPath.Parameters.AddWithValue("$p", newPath);
            updPath.Parameters.AddWithValue("$id", aid);
            await updPath.ExecuteNonQueryAsync();
        }

        await tx.CommitAsync();

        // File system moves happen after the commit — best-effort, since the DB now has the
        // canonical path. If a move fails the next Save will recreate the file at the new
        // location anyway.
        foreach (var (_, oldPath, newPath) in artifactUpdates)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(newPath)!);
                if (File.Exists(oldPath) && !File.Exists(newPath))
                    File.Move(oldPath, newPath);
            }
            catch { /* best effort */ }
        }
    }

    /// <summary>
    /// Rename a vendor across every advisory that currently carries the <paramref name="oldVendor"/>
    /// label. Null/empty <paramref name="oldVendor"/> matches records with a NULL or blank vendor
    /// column (the "(no vendor)" group in the Library tree) so the user can classify them by typing
    /// a real vendor in. Also renames the on-disk vendor folder and rewrites every artifact path
    /// for the affected rows so DB and disk stay in sync.
    /// </summary>
    public async Task<int> RenameVendorAsync(string? oldVendor, string newVendor)
    {
        if (string.IsNullOrWhiteSpace(newVendor)) throw new ArgumentException("vendor name cannot be empty", nameof(newVendor));
        newVendor = newVendor.Trim();

        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        // Snapshot affected artifact paths so we can rewrite them in lockstep with the rename.
        var pathUpdates = new List<(long Id, string OldPath, string NewPath)>();
        await using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = string.IsNullOrWhiteSpace(oldVendor)
                ? @"SELECT a.id, a.path FROM advisory_artifacts a
                    JOIN advisory_records r ON r.id = a.advisory_id
                    WHERE r.vendor IS NULL OR TRIM(r.vendor) = '';"
                : @"SELECT a.id, a.path FROM advisory_artifacts a
                    JOIN advisory_records r ON r.id = a.advisory_id
                    WHERE LOWER(TRIM(r.vendor)) = LOWER(TRIM($old));";
            if (!string.IsNullOrWhiteSpace(oldVendor))
                sel.Parameters.AddWithValue("$old", oldVendor);
            await using var r = await sel.ExecuteReaderAsync();
            var oldVendorDir = GetVendorDir(oldVendor);
            var newVendorDir = GetVendorDir(newVendor);
            while (await r.ReadAsync())
            {
                var aid = r.GetInt64(0);
                var oldPath = r.GetString(1);
                // Replace the vendor folder portion of the path. Use OrdinalIgnoreCase since
                // NTFS is case-insensitive and the slugifier preserves casing.
                var newPath = oldPath.StartsWith(oldVendorDir, StringComparison.OrdinalIgnoreCase)
                    ? newVendorDir + oldPath.Substring(oldVendorDir.Length)
                    : oldPath;
                if (!ReferenceEquals(newPath, oldPath))
                    pathUpdates.Add((aid, oldPath, newPath));
            }
        }

        await using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            if (string.IsNullOrWhiteSpace(oldVendor))
            {
                cmd.CommandText = @"UPDATE advisory_records
                                    SET vendor = $new, updated_at_utc = $u
                                    WHERE vendor IS NULL OR TRIM(vendor) = '';";
            }
            else
            {
                cmd.CommandText = @"UPDATE advisory_records
                                    SET vendor = $new, updated_at_utc = $u
                                    WHERE LOWER(TRIM(vendor)) = LOWER(TRIM($old));";
                cmd.Parameters.AddWithValue("$old", oldVendor);
            }
            cmd.Parameters.AddWithValue("$new", newVendor);
            cmd.Parameters.AddWithValue("$u", FormatUtc(DateTime.UtcNow));
            var rowsAffected = await cmd.ExecuteNonQueryAsync();

            foreach (var (aid, _, np) in pathUpdates)
            {
                await using var updPath = conn.CreateCommand();
                updPath.Transaction = tx;
                updPath.CommandText = "UPDATE advisory_artifacts SET path=$p WHERE id=$id;";
                updPath.Parameters.AddWithValue("$p", np);
                updPath.Parameters.AddWithValue("$id", aid);
                await updPath.ExecuteNonQueryAsync();
            }

            await tx.CommitAsync();

            // Move the vendor directory on disk. Best-effort — DB is authoritative.
            try
            {
                var oldDir = GetVendorDir(oldVendor);
                var newDir = GetVendorDir(newVendor);
                if (!string.Equals(oldDir, newDir, StringComparison.OrdinalIgnoreCase)
                    && Directory.Exists(oldDir) && !Directory.Exists(newDir))
                {
                    Directory.Move(oldDir, newDir);
                }
            }
            catch { /* best effort */ }

            return rowsAffected;
        }
    }

    // ---- Artifacts (Fase 7c.2) --------------------------------------------

    /// <summary>Root directory for advisory artifacts (one folder per vendor under here).</summary>
    public static string AttachmentsBase => Path.Combine(BaseDir, "attachments");

    /// <summary>Folder for a vendor's artifacts. Sanitized to avoid NTFS-forbidden chars.</summary>
    public static string GetVendorDir(string? vendor) =>
        Path.Combine(AttachmentsBase, SlugifyVendor(vendor));

    /// <summary>Per-vendor / per-template subfolder. Created on demand by writers.</summary>
    public static string GetTemplateDir(string? vendor, string templateId) =>
        Path.Combine(GetVendorDir(vendor), templateId);

    /// <summary>
    /// Build the filesystem path for an advisory's rendered artifact under the
    /// vendor → template → PREFIX_NNNN.ext layout. Caller is responsible for ensuring
    /// the advisory has a SequenceNumber allocated for the given vendor.
    /// </summary>
    public static string BuildArtifactPath(string? vendor, string templateId, string vulnerabilityType,
        int sequenceNumber, string extension)
    {
        var prefix = SlugifyVulnerabilityType(vulnerabilityType);
        var ext = extension.StartsWith(".") ? extension : "." + extension;
        var name = $"{prefix}_ADVISORY_{sequenceNumber:0000}{ext}";
        return Path.Combine(GetTemplateDir(vendor, templateId), name);
    }

    /// <summary>
    /// Sanitize a vendor name into a portable folder name. Strips NTFS-forbidden chars
    /// (\\/:*?"&lt;&gt;|), replaces non [A-Za-z0-9._-] with underscore, collapses runs of
    /// underscores, and trims leading/trailing punctuation. Null or blank vendor maps to
    /// "_no_vendor_" so unclassified rows still get a stable folder.
    /// </summary>
    public static string SlugifyVendor(string? vendor)
    {
        if (string.IsNullOrWhiteSpace(vendor)) return "_no_vendor_";
        var sb = new System.Text.StringBuilder(vendor.Length);
        foreach (var ch in vendor.Trim())
        {
            if (char.IsLetterOrDigit(ch) || ch == '.' || ch == '-' || ch == '_') sb.Append(ch);
            else sb.Append('_');
        }
        var s = System.Text.RegularExpressions.Regex.Replace(sb.ToString(), "_+", "_").Trim('_', '.');
        return string.IsNullOrEmpty(s) ? "_no_vendor_" : s;
    }

    /// <summary>
    /// Slugify a vulnerability type ("DLL Sideloading") into an UPPER_SNAKE prefix
    /// ("DLL_SIDELOADING") suitable for use in filenames. Empty input falls back to "ADVISORY".
    /// </summary>
    public static string SlugifyVulnerabilityType(string? vulnType)
    {
        if (string.IsNullOrWhiteSpace(vulnType)) return "ADVISORY";
        var upper = vulnType.ToUpperInvariant();
        var sb = new System.Text.StringBuilder(upper.Length);
        foreach (var ch in upper)
        {
            if (ch is >= 'A' and <= 'Z' or >= '0' and <= '9') sb.Append(ch);
            else sb.Append('_');
        }
        var s = System.Text.RegularExpressions.Regex.Replace(sb.ToString(), "_+", "_").Trim('_');
        return string.IsNullOrEmpty(s) ? "ADVISORY" : s;
    }

    /// <summary>
    /// Atomic per-vendor sequence allocator. MAX(seq) over ALL rows (including
    /// soft-deleted) for the given vendor + 1, so numbers never recycle. Caller invokes
    /// inside an open transaction so the allocation and the consuming write can be
    /// committed together.
    /// </summary>
    private static async Task<int> AllocateSequenceForVendorAsync(SqliteConnection conn,
        SqliteTransaction tx, string? vendor)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = vendor is null
            ? @"SELECT COALESCE(MAX(sequence_number), 0) + 1 FROM advisory_records
                WHERE vendor IS NULL OR TRIM(vendor) = '';"
            : @"SELECT COALESCE(MAX(sequence_number), 0) + 1 FROM advisory_records
                WHERE LOWER(TRIM(vendor)) = LOWER(TRIM($v));";
        if (vendor is not null) cmd.Parameters.AddWithValue("$v", vendor);
        var v = await cmd.ExecuteScalarAsync();
        return Convert.ToInt32(v ?? 1);
    }

    /// <summary>Map our renderer ids to the file extension we use on disk.</summary>
    private static string ExtensionForTemplate(string templateId) => templateId switch
    {
        "markdown" => ".md",
        "ghsa"     => ".yaml",
        _          => ".txt",
    };

    /// <summary>
    /// Write rendered content to disk and register it as an artifact. Computes the path
    /// from the parent advisory's vendor + vulnerability_type + per-vendor sequence
    /// (allocated lazily on first call). UPSERT semantics: if an artifact row already
    /// exists for (advisory_id, template_id, path) the existing row is updated in-place
    /// — never duplicated. Without this, every Save would accumulate a new row pointing
    /// at the same physical file, and deleting one of those rows would unlink the file
    /// and orphan its siblings. The whole flow runs in one transaction.
    /// </summary>
    public async Task<AdvisoryArtifact> WriteArtifactAsync(string advisoryId, string templateId,
        ArtifactKind kind, string content, string? label = null)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        // Resolve the advisory's vendor / vuln type / sequence in the same tx so
        // sequence allocation can't race with another writer on the same vendor.
        string? vendor = null;
        var vulnType = "DLL Sideloading";
        int? seq = null;
        await using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = @"SELECT vendor, vulnerability_type, sequence_number
                                FROM advisory_records WHERE id=$id;";
            sel.Parameters.AddWithValue("$id", advisoryId);
            await using var r = await sel.ExecuteReaderAsync();
            if (!await r.ReadAsync())
                throw new InvalidOperationException($"Advisory {advisoryId} not found");
            vendor = r.IsDBNull(0) ? null : r.GetString(0);
            if (!r.IsDBNull(1) && !string.IsNullOrWhiteSpace(r.GetString(1))) vulnType = r.GetString(1);
            seq = r.IsDBNull(2) ? null : r.GetInt32(2);
        }

        if (seq is null)
        {
            seq = await AllocateSequenceForVendorAsync(conn, tx, vendor);
            await using var setSeq = conn.CreateCommand();
            setSeq.Transaction = tx;
            setSeq.CommandText = "UPDATE advisory_records SET sequence_number=$s WHERE id=$id;";
            setSeq.Parameters.AddWithValue("$s", seq.Value);
            setSeq.Parameters.AddWithValue("$id", advisoryId);
            await setSeq.ExecuteNonQueryAsync();
        }

        var ext = ExtensionForTemplate(templateId);
        var path = BuildArtifactPath(vendor, templateId, vulnType, seq.Value, ext);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(path, content, new System.Text.UTF8Encoding(false));
        var sha = Sha256(content);

        var artifact = await UpsertArtifactInTxAsync(conn, tx, advisoryId, templateId, kind, path, label, sha);
        await tx.CommitAsync();
        return artifact;
    }

    /// <summary>
    /// UPSERT helper that runs inside an existing transaction. Same semantics as the
    /// public path but doesn't open its own connection — used so allocate + write + upsert
    /// can be one atomic step.
    /// </summary>
    private static async Task<AdvisoryArtifact> UpsertArtifactInTxAsync(SqliteConnection conn,
        SqliteTransaction tx, string advisoryId, string? templateId, ArtifactKind kind,
        string path, string? label, string? sha256)
    {
        var now = DateTime.UtcNow;
        long id = 0;
        bool wasUpdate = false;

        await using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = templateId is null
                ? @"SELECT id FROM advisory_artifacts
                    WHERE advisory_id=$aid AND template_id IS NULL AND path=$path LIMIT 1;"
                : @"SELECT id FROM advisory_artifacts
                    WHERE advisory_id=$aid AND template_id=$tpl AND path=$path LIMIT 1;";
            sel.Parameters.AddWithValue("$aid", advisoryId);
            sel.Parameters.AddWithValue("$path", path);
            if (templateId is not null) sel.Parameters.AddWithValue("$tpl", templateId);
            var existing = await sel.ExecuteScalarAsync();
            if (existing is long lid) { id = lid; wasUpdate = true; }
        }

        if (wasUpdate)
        {
            await using var upd = conn.CreateCommand();
            upd.Transaction = tx;
            upd.CommandText = @"UPDATE advisory_artifacts
                                SET sha256=$sha, created_at_utc=$at, label=$label, artifact_kind=$kind
                                WHERE id=$id;";
            upd.Parameters.AddWithValue("$sha",   (object?)sha256 ?? DBNull.Value);
            upd.Parameters.AddWithValue("$at",    FormatUtc(now));
            upd.Parameters.AddWithValue("$label", (object?)label ?? DBNull.Value);
            upd.Parameters.AddWithValue("$kind",  (int)kind);
            upd.Parameters.AddWithValue("$id",    id);
            await upd.ExecuteNonQueryAsync();
        }
        else
        {
            await using var ins = conn.CreateCommand();
            ins.Transaction = tx;
            ins.CommandText = @"INSERT INTO advisory_artifacts
                (advisory_id, artifact_kind, path, label, sha256, created_at_utc, template_id)
                VALUES ($aid, $kind, $path, $label, $sha, $at, $tpl);
                SELECT last_insert_rowid();";
            ins.Parameters.AddWithValue("$aid",   advisoryId);
            ins.Parameters.AddWithValue("$kind",  (int)kind);
            ins.Parameters.AddWithValue("$path",  path);
            ins.Parameters.AddWithValue("$label", (object?)label ?? DBNull.Value);
            ins.Parameters.AddWithValue("$sha",   (object?)sha256 ?? DBNull.Value);
            ins.Parameters.AddWithValue("$at",    FormatUtc(now));
            ins.Parameters.AddWithValue("$tpl",   (object?)templateId ?? DBNull.Value);
            id = (long)(await ins.ExecuteScalarAsync() ?? 0L);
        }

        var verb = wasUpdate ? "Artifact updated" : "Artifact saved";
        var timelineKind = kind switch
        {
            ArtifactKind.Pdf => TimelineEventKind.ExportedPdf,
            _ => TimelineEventKind.ExportedMarkdown,
        };
        await InsertTimelineAsync(conn, tx, advisoryId, timelineKind,
            $"{verb}: {templateId ?? "attachment"}/{Path.GetFileName(path)}", null, null, null);

        await using (var touch = conn.CreateCommand())
        {
            touch.Transaction = tx;
            touch.CommandText = "UPDATE advisory_records SET updated_at_utc=$u WHERE id=$id;";
            touch.Parameters.AddWithValue("$u", FormatUtc(now));
            touch.Parameters.AddWithValue("$id", advisoryId);
            await touch.ExecuteNonQueryAsync();
        }

        return new AdvisoryArtifact
        {
            Id = id,
            AdvisoryId = advisoryId,
            ArtifactKind = kind,
            Path = path,
            Label = label,
            Sha256 = sha256,
            CreatedAtUtc = now,
            TemplateId = templateId,
        };
    }

    /// <summary>Register an artifact row without writing anything to disk (for pre-existing files).</summary>
    public async Task<AdvisoryArtifact> AddArtifactAsync(string advisoryId, string? templateId,
        ArtifactKind kind, string path, string? label, string? sha256)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync();

        var now = DateTime.UtcNow;
        long id;
        await using (var ins = conn.CreateCommand())
        {
            ins.Transaction = tx;
            ins.CommandText = @"INSERT INTO advisory_artifacts
                (advisory_id, artifact_kind, path, label, sha256, created_at_utc, template_id)
                VALUES ($aid, $kind, $path, $label, $sha, $at, $tpl);
                SELECT last_insert_rowid();";
            ins.Parameters.AddWithValue("$aid", advisoryId);
            ins.Parameters.AddWithValue("$kind", (int)kind);
            ins.Parameters.AddWithValue("$path", path);
            ins.Parameters.AddWithValue("$label", (object?)label ?? DBNull.Value);
            ins.Parameters.AddWithValue("$sha", (object?)sha256 ?? DBNull.Value);
            ins.Parameters.AddWithValue("$at", FormatUtc(now));
            ins.Parameters.AddWithValue("$tpl", (object?)templateId ?? DBNull.Value);
            id = (long)(await ins.ExecuteScalarAsync() ?? 0L);
        }

        var timelineKind = kind switch
        {
            ArtifactKind.Pdf => TimelineEventKind.ExportedPdf,
            _ => TimelineEventKind.ExportedMarkdown,
        };
        await InsertTimelineAsync(conn, tx, advisoryId, timelineKind,
            $"Artifact saved: {templateId ?? "attachment"}/{Path.GetFileName(path)}", null, null, null);

        await using (var touch = conn.CreateCommand())
        {
            touch.Transaction = tx;
            touch.CommandText = "UPDATE advisory_records SET updated_at_utc=$u WHERE id=$id;";
            touch.Parameters.AddWithValue("$u", FormatUtc(now));
            touch.Parameters.AddWithValue("$id", advisoryId);
            await touch.ExecuteNonQueryAsync();
        }
        await tx.CommitAsync();

        return new AdvisoryArtifact
        {
            Id = id,
            AdvisoryId = advisoryId,
            ArtifactKind = kind,
            Path = path,
            Label = label,
            Sha256 = sha256,
            CreatedAtUtc = now,
            TemplateId = templateId,
        };
    }

    public async Task DeleteArtifactAsync(long artifactId)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();

        // Fetch path so we can also unlink from disk.
        string? path = null;
        await using (var sel = conn.CreateCommand())
        {
            sel.CommandText = "SELECT path FROM advisory_artifacts WHERE id=$id;";
            sel.Parameters.AddWithValue("$id", artifactId);
            path = await sel.ExecuteScalarAsync() as string;
        }
        await using (var del = conn.CreateCommand())
        {
            del.CommandText = "DELETE FROM advisory_artifacts WHERE id=$id;";
            del.Parameters.AddWithValue("$id", artifactId);
            await del.ExecuteNonQueryAsync();
        }
        try { if (!string.IsNullOrEmpty(path) && File.Exists(path)) File.Delete(path); }
        catch { /* best effort */ }
    }

    /// <summary>Fetch the artifact rows for a single advisory.</summary>
    public async Task<List<AdvisoryArtifact>> GetArtifactsForAdvisoryAsync(string advisoryId)
    {
        var list = new List<AdvisoryArtifact>();
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT id, advisory_id, artifact_kind, path, label, sha256, created_at_utc, template_id, status
                            FROM advisory_artifacts WHERE advisory_id=$id
                            ORDER BY template_id, created_at_utc DESC;";
        cmd.Parameters.AddWithValue("$id", advisoryId);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            list.Add(new AdvisoryArtifact
            {
                Id = r.GetInt64(0),
                AdvisoryId = r.GetString(1),
                ArtifactKind = (ArtifactKind)r.GetInt32(2),
                Path = r.GetString(3),
                Label = r.IsDBNull(4) ? null : r.GetString(4),
                Sha256 = r.IsDBNull(5) ? null : r.GetString(5),
                CreatedAtUtc = ParseUtc(r.GetString(6)),
                TemplateId = r.IsDBNull(7) ? null : r.GetString(7),
                Status = r.IsDBNull(8) ? AdvisoryStatus.Draft : (AdvisoryStatus)r.GetInt32(8),
            });
        }
        return list;
    }

    /// <summary>Bulk fetch artifacts for every advisory in the library. Used by the tree to populate format folders.</summary>
    public async Task<Dictionary<string, List<AdvisoryArtifact>>> GetArtifactsIndexAsync()
    {
        var map = new Dictionary<string, List<AdvisoryArtifact>>(StringComparer.Ordinal);
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT id, advisory_id, artifact_kind, path, label, sha256, created_at_utc, template_id, status
                            FROM advisory_artifacts
                            ORDER BY template_id, created_at_utc DESC;";
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var art = new AdvisoryArtifact
            {
                Id = r.GetInt64(0),
                AdvisoryId = r.GetString(1),
                ArtifactKind = (ArtifactKind)r.GetInt32(2),
                Path = r.GetString(3),
                Label = r.IsDBNull(4) ? null : r.GetString(4),
                Sha256 = r.IsDBNull(5) ? null : r.GetString(5),
                CreatedAtUtc = ParseUtc(r.GetString(6)),
                TemplateId = r.IsDBNull(7) ? null : r.GetString(7),
                Status = r.IsDBNull(8) ? AdvisoryStatus.Draft : (AdvisoryStatus)r.GetInt32(8),
            };
            if (!map.TryGetValue(art.AdvisoryId, out var list))
                map[art.AdvisoryId] = list = new List<AdvisoryArtifact>();
            list.Add(art);
        }
        return map;
    }

    private static string Sha256(string text)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        var bytes = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    // ---- helpers -----------------------------------------------------------

    private static string InterpolateTitle(AdvisoryContext ctx)
    {
        return ctx.Title
            .Replace("{Product}", ctx.Product ?? "")
            .Replace("{Filename}", ctx.PeFilename ?? "")
            .Replace("{Vendor}", ctx.Vendor ?? "")
            .Replace("  ", " ").Trim();
    }

    private static async Task InsertRecordAsync(SqliteConnection conn, SqliteTransaction tx, AdvisoryRecord r)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = InsertRecordSql;
        BindRecordParameters(cmd, r, includeId: true);
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task InsertTimelineAsync(SqliteConnection conn, SqliteTransaction tx, string advisoryId,
        TimelineEventKind kind, string title, string? note, AdvisoryStatus? oldStatus, AdvisoryStatus? newStatus)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"INSERT INTO advisory_timeline_events
            (advisory_id, event_kind, event_at_utc, title, note, old_status, new_status)
            VALUES ($aid, $kind, $at, $title, $note, $old, $new);";
        cmd.Parameters.AddWithValue("$aid", advisoryId);
        cmd.Parameters.AddWithValue("$kind", (int)kind);
        cmd.Parameters.AddWithValue("$at", FormatUtc(DateTime.UtcNow));
        cmd.Parameters.AddWithValue("$title", title);
        cmd.Parameters.AddWithValue("$note", (object?)note ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$old", oldStatus.HasValue ? (object)(int)oldStatus.Value : DBNull.Value);
        cmd.Parameters.AddWithValue("$new", newStatus.HasValue ? (object)(int)newStatus.Value : DBNull.Value);
        await cmd.ExecuteNonQueryAsync();
    }

    private static void BindRecordParameters(SqliteCommand cmd, AdvisoryRecord r, bool includeId)
    {
        if (includeId) cmd.Parameters.AddWithValue("$id", r.Id);
        cmd.Parameters.AddWithValue("$created", FormatUtc(r.CreatedAtUtc));
        cmd.Parameters.AddWithValue("$updated", FormatUtc(r.UpdatedAtUtc));
        cmd.Parameters.AddWithValue("$status", (int)r.Status);
        cmd.Parameters.AddWithValue("$title", r.Title);
        cmd.Parameters.AddWithValue("$vendor", (object?)r.Vendor ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$product", (object?)r.Product ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$pversion", (object?)r.ProductVersion ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$arch", (object?)r.Architecture ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$pepath", (object?)r.PePath ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$pefile", (object?)r.PeFilename ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$installdir", (object?)r.InstallDirectory ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$vtype", r.VulnerabilityType);
        cmd.Parameters.AddWithValue("$cwe", r.CweId);
        cmd.Parameters.AddWithValue("$cwename", r.CweName);
        cmd.Parameters.AddWithValue("$rname", r.ResearcherName);
        cmd.Parameters.AddWithValue("$rhandle", r.ResearcherHandle);
        cmd.Parameters.AddWithValue("$rblog", r.ResearcherBlog);
        cmd.Parameters.AddWithValue("$remail", r.ResearcherEmail);
        cmd.Parameters.AddWithValue("$payload", (object?)r.PayloadDescription ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$importer", (object?)r.ImporterExe ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$gendll", (object?)r.GeneratedDllPath ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$dlp", r.DirectoryLowPrivWritable ? 1 : 0);
        cmd.Parameters.AddWithValue("$wbp", (object?)r.WritableByPrincipals ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$cvssv", (object?)r.CvssVector ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$cvsss", r.CvssScore.HasValue ? (object)r.CvssScore.Value : DBNull.Value);
        cmd.Parameters.AddWithValue("$cvsssev", (object?)r.CvssSeverity ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$discpol", r.DisclosurePolicy);
        cmd.Parameters.AddWithValue("$disc", r.DiscoveredOn.HasValue ? (object)FormatUtc(r.DiscoveredOn.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$rep", r.ReportedOn.HasValue ? (object)FormatUtc(r.ReportedOn.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$disclosed", r.DisclosedOn.HasValue ? (object)FormatUtc(r.DisclosedOn.Value) : DBNull.Value);
        cmd.Parameters.AddWithValue("$md", r.MarkdownBody);
        cmd.Parameters.AddWithValue("$notes", (object?)r.Notes ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$scd", (object?)r.SourceScanDir ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$sck", (object?)r.SourceCandidateKind ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$sckey", (object?)r.SourceCandidateKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$lem", (object?)r.LastExportedMarkdownPath ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$lep", (object?)r.LastExportedPdfPath ?? DBNull.Value);
        // Schema v4 — Template Fields
        cmd.Parameters.AddWithValue("$vtt",    (object?)r.VulnerabilityTypeText ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$vurl",   (object?)r.VendorUrl ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$vpn",    (object?)r.VendorPocName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$vpe",    (object?)r.VendorPocEmail ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$duref",  (object?)r.DeviceUrlReference ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$dbsum",  (object?)r.DeviceBriefSummary ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$afcomp", (object?)r.AffectedComponents ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$prereq", (object?)r.PreviousRequirements ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$propsol",(object?)r.ProposedSolution ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$hcvn",   (object?)r.HasContactedVendorNote ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$cv4v",   (object?)r.CvssV4Vector ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$cv4s",   r.CvssV4Score.HasValue ? (object)r.CvssV4Score.Value : DBNull.Value);
        cmd.Parameters.AddWithValue("$cv4sev", (object?)r.CvssV4Severity ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$rpgpf",  (object?)r.ResearcherPgpFingerprint ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$rpgpk",  (object?)r.ResearcherPgpKeyId ?? DBNull.Value);
        // Schema v5 — active template id
        cmd.Parameters.AddWithValue("$lastpl", (object?)r.LastTemplateId ?? DBNull.Value);
        // Schema v6 — per-vendor sequence number
        cmd.Parameters.AddWithValue("$seqn",   r.SequenceNumber.HasValue ? (object)r.SequenceNumber.Value : DBNull.Value);
    }

    private static AdvisoryRecord ReadRecord(SqliteDataReader r)
    {
        int i = 0;
        var rec = new AdvisoryRecord
        {
            Id = r.GetString(i++),
            CreatedAtUtc = ParseUtc(r.GetString(i++)),
            UpdatedAtUtc = ParseUtc(r.GetString(i++)),
            Status = (AdvisoryStatus)r.GetInt32(i++),
            Title = r.GetString(i++),
        };
        rec.Vendor = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.Product = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.ProductVersion = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.Architecture = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.PePath = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.PeFilename = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.InstallDirectory = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.VulnerabilityType = r.IsDBNull(i) ? "" : r.GetString(i); i++;
        rec.CweId = r.IsDBNull(i) ? "" : r.GetString(i); i++;
        rec.CweName = r.IsDBNull(i) ? "" : r.GetString(i); i++;
        rec.ResearcherName = r.IsDBNull(i) ? "" : r.GetString(i); i++;
        rec.ResearcherHandle = r.IsDBNull(i) ? "" : r.GetString(i); i++;
        rec.ResearcherBlog = r.IsDBNull(i) ? "" : r.GetString(i); i++;
        rec.ResearcherEmail = r.IsDBNull(i) ? "" : r.GetString(i); i++;
        rec.PayloadDescription = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.ImporterExe = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.GeneratedDllPath = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.DirectoryLowPrivWritable = !r.IsDBNull(i) && r.GetInt32(i) == 1; i++;
        rec.WritableByPrincipals = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.CvssVector = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.CvssScore = r.IsDBNull(i) ? null : r.GetDouble(i); i++;
        rec.CvssSeverity = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.DisclosurePolicy = r.IsDBNull(i) ? "" : r.GetString(i); i++;
        rec.DiscoveredOn = r.IsDBNull(i) ? null : ParseUtc(r.GetString(i)); i++;
        rec.ReportedOn = r.IsDBNull(i) ? null : ParseUtc(r.GetString(i)); i++;
        rec.DisclosedOn = r.IsDBNull(i) ? null : ParseUtc(r.GetString(i)); i++;
        rec.MarkdownBody = r.IsDBNull(i) ? "" : r.GetString(i); i++;
        rec.Notes = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.SourceScanDir = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.SourceCandidateKind = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.SourceCandidateKey = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.LastExportedMarkdownPath = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.LastExportedPdfPath = r.IsDBNull(i) ? null : r.GetString(i); i++;
        // Schema v4 — Template Fields
        rec.VulnerabilityTypeText  = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.VendorUrl              = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.VendorPocName          = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.VendorPocEmail         = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.DeviceUrlReference     = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.DeviceBriefSummary     = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.AffectedComponents     = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.PreviousRequirements   = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.ProposedSolution       = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.HasContactedVendorNote = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.CvssV4Vector           = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.CvssV4Score            = r.IsDBNull(i) ? null : r.GetDouble(i); i++;
        rec.CvssV4Severity         = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.ResearcherPgpFingerprint = r.IsDBNull(i) ? null : r.GetString(i); i++;
        rec.ResearcherPgpKeyId       = r.IsDBNull(i) ? null : r.GetString(i); i++;
        // Schema v5 — active template id (null on legacy rows; AdvisoryPage falls back to "markdown")
        rec.LastTemplateId           = r.IsDBNull(i) ? null : r.GetString(i); i++;
        // Schema v6 — per-vendor sequence number (null on legacy rows; allocated on first write)
        rec.SequenceNumber           = r.IsDBNull(i) ? null : (int?)r.GetInt32(i); i++;
        return rec;
    }

    private static string? NullIfBlank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static string FormatUtc(DateTime d) => d.ToUniversalTime().ToString("o");
    private static DateTime ParseUtc(string s) => DateTime.Parse(s, System.Globalization.CultureInfo.InvariantCulture,
        System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime();

    private static async Task ExecNonQueryAsync(SqliteConnection conn, string sql)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }

    // ---- SQL statements ----------------------------------------------------

    /// <summary>
    /// Column definitions added in schema v4 (Template Fields persistence). Listed here so the
    /// migration loop and the CREATE TABLE in <see cref="SchemaSql"/> can stay in sync. All
    /// columns are nullable so legacy rows survive without backfill.
    /// </summary>
    private static readonly string[] V4NewColumns =
    [
        "vulnerability_type_text TEXT",
        "vendor_url TEXT",
        "vendor_poc_name TEXT",
        "vendor_poc_email TEXT",
        "device_url_reference TEXT",
        "device_brief_summary TEXT",
        "affected_components TEXT",
        "previous_requirements TEXT",
        "proposed_solution TEXT",
        "has_contacted_vendor_note TEXT",
        "cvss_v4_vector TEXT",
        "cvss_v4_score REAL",
        "cvss_v4_severity TEXT",
        "researcher_pgp_fingerprint TEXT",
        "researcher_pgp_key_id TEXT",
    ];

    private const string SchemaSql = @"
CREATE TABLE IF NOT EXISTS schema_info (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS advisory_records (
    id TEXT PRIMARY KEY,
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    status INTEGER NOT NULL,
    title TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    product_version TEXT,
    architecture TEXT,
    pe_path TEXT,
    pe_filename TEXT,
    install_directory TEXT,
    vulnerability_type TEXT,
    cwe_id TEXT,
    cwe_name TEXT,
    researcher_name TEXT,
    researcher_handle TEXT,
    researcher_blog TEXT,
    researcher_email TEXT,
    payload_description TEXT,
    importer_exe TEXT,
    generated_dll_path TEXT,
    directory_low_priv_writable INTEGER NOT NULL DEFAULT 0,
    writable_by_principals TEXT,
    cvss_vector TEXT,
    cvss_score REAL,
    cvss_severity TEXT,
    disclosure_policy TEXT,
    discovered_on TEXT,
    reported_on TEXT,
    disclosed_on TEXT,
    markdown_body TEXT NOT NULL,
    notes TEXT,
    source_scan_dir TEXT,
    source_candidate_kind TEXT,
    source_candidate_key TEXT,
    last_exported_markdown_path TEXT,
    last_exported_pdf_path TEXT,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    deleted_at_utc TEXT,
    -- Template Fields (schema v4) — vendor / classification / PGP overrides
    vulnerability_type_text TEXT,
    vendor_url TEXT,
    vendor_poc_name TEXT,
    vendor_poc_email TEXT,
    device_url_reference TEXT,
    device_brief_summary TEXT,
    affected_components TEXT,
    previous_requirements TEXT,
    proposed_solution TEXT,
    has_contacted_vendor_note TEXT,
    cvss_v4_vector TEXT,
    cvss_v4_score REAL,
    cvss_v4_severity TEXT,
    researcher_pgp_fingerprint TEXT,
    researcher_pgp_key_id TEXT,
    -- Schema v5 — active template id (markdown / ghsa) so reopen restores the renderer
    last_template_id TEXT,
    -- Schema v6 — per-vendor sequence number (1-based) for human-readable filenames
    sequence_number INTEGER
);

CREATE INDEX IF NOT EXISTS ix_advisory_records_vendor_product ON advisory_records(vendor, product);
CREATE INDEX IF NOT EXISTS ix_advisory_records_status ON advisory_records(status);
CREATE INDEX IF NOT EXISTS ix_advisory_records_updated ON advisory_records(updated_at_utc DESC);

CREATE TABLE IF NOT EXISTS advisory_timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id TEXT NOT NULL,
    event_kind INTEGER NOT NULL,
    event_at_utc TEXT NOT NULL,
    title TEXT NOT NULL,
    note TEXT,
    old_status INTEGER,
    new_status INTEGER,
    FOREIGN KEY(advisory_id) REFERENCES advisory_records(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_timeline_advisory_time ON advisory_timeline_events(advisory_id, event_at_utc DESC);

CREATE TABLE IF NOT EXISTS advisory_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id TEXT NOT NULL,
    artifact_kind INTEGER NOT NULL,
    path TEXT NOT NULL,
    label TEXT,
    sha256 TEXT,
    created_at_utc TEXT NOT NULL,
    template_id TEXT,
    -- Schema v7: per-artifact workflow state, independent of the parent advisory's status
    status INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(advisory_id) REFERENCES advisory_records(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_artifacts_advisory ON advisory_artifacts(advisory_id);

CREATE TABLE IF NOT EXISTS advisory_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id TEXT NOT NULL,
    link_kind INTEGER NOT NULL,
    value TEXT NOT NULL,
    label TEXT,
    FOREIGN KEY(advisory_id) REFERENCES advisory_records(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_links_advisory_kind ON advisory_links(advisory_id, link_kind);
";

    private const string RecordColumns = @"id, created_at_utc, updated_at_utc, status, title,
        vendor, product, product_version, architecture,
        pe_path, pe_filename, install_directory,
        vulnerability_type, cwe_id, cwe_name,
        researcher_name, researcher_handle, researcher_blog, researcher_email,
        payload_description, importer_exe, generated_dll_path,
        directory_low_priv_writable, writable_by_principals,
        cvss_vector, cvss_score, cvss_severity,
        disclosure_policy, discovered_on, reported_on, disclosed_on,
        markdown_body, notes,
        source_scan_dir, source_candidate_kind, source_candidate_key,
        last_exported_markdown_path, last_exported_pdf_path,
        vulnerability_type_text,
        vendor_url, vendor_poc_name, vendor_poc_email,
        device_url_reference, device_brief_summary,
        affected_components, previous_requirements, proposed_solution,
        has_contacted_vendor_note,
        cvss_v4_vector, cvss_v4_score, cvss_v4_severity,
        researcher_pgp_fingerprint, researcher_pgp_key_id,
        last_template_id,
        sequence_number";

    private const string SelectRecordSql = "SELECT " + RecordColumns + " FROM advisory_records";

    private const string InsertRecordSql = @"INSERT INTO advisory_records
        (id, created_at_utc, updated_at_utc, status, title,
         vendor, product, product_version, architecture,
         pe_path, pe_filename, install_directory,
         vulnerability_type, cwe_id, cwe_name,
         researcher_name, researcher_handle, researcher_blog, researcher_email,
         payload_description, importer_exe, generated_dll_path,
         directory_low_priv_writable, writable_by_principals,
         cvss_vector, cvss_score, cvss_severity,
         disclosure_policy, discovered_on, reported_on, disclosed_on,
         markdown_body, notes,
         source_scan_dir, source_candidate_kind, source_candidate_key,
         last_exported_markdown_path, last_exported_pdf_path,
         vulnerability_type_text,
         vendor_url, vendor_poc_name, vendor_poc_email,
         device_url_reference, device_brief_summary,
         affected_components, previous_requirements, proposed_solution,
         has_contacted_vendor_note,
         cvss_v4_vector, cvss_v4_score, cvss_v4_severity,
         researcher_pgp_fingerprint, researcher_pgp_key_id,
         last_template_id,
         sequence_number)
        VALUES ($id, $created, $updated, $status, $title,
         $vendor, $product, $pversion, $arch,
         $pepath, $pefile, $installdir,
         $vtype, $cwe, $cwename,
         $rname, $rhandle, $rblog, $remail,
         $payload, $importer, $gendll,
         $dlp, $wbp,
         $cvssv, $cvsss, $cvsssev,
         $discpol, $disc, $rep, $disclosed,
         $md, $notes,
         $scd, $sck, $sckey,
         $lem, $lep,
         $vtt,
         $vurl, $vpn, $vpe,
         $duref, $dbsum,
         $afcomp, $prereq, $propsol,
         $hcvn,
         $cv4v, $cv4s, $cv4sev,
         $rpgpf, $rpgpk,
         $lastpl,
         $seqn);";

    private const string UpdateRecordSql = @"UPDATE advisory_records SET
         created_at_utc=$created, updated_at_utc=$updated, status=$status, title=$title,
         vendor=$vendor, product=$product, product_version=$pversion, architecture=$arch,
         pe_path=$pepath, pe_filename=$pefile, install_directory=$installdir,
         vulnerability_type=$vtype, cwe_id=$cwe, cwe_name=$cwename,
         researcher_name=$rname, researcher_handle=$rhandle, researcher_blog=$rblog, researcher_email=$remail,
         payload_description=$payload, importer_exe=$importer, generated_dll_path=$gendll,
         directory_low_priv_writable=$dlp, writable_by_principals=$wbp,
         cvss_vector=$cvssv, cvss_score=$cvsss, cvss_severity=$cvsssev,
         disclosure_policy=$discpol, discovered_on=$disc, reported_on=$rep, disclosed_on=$disclosed,
         markdown_body=$md, notes=$notes,
         source_scan_dir=$scd, source_candidate_kind=$sck, source_candidate_key=$sckey,
         last_exported_markdown_path=$lem, last_exported_pdf_path=$lep,
         vulnerability_type_text=$vtt,
         vendor_url=$vurl, vendor_poc_name=$vpn, vendor_poc_email=$vpe,
         device_url_reference=$duref, device_brief_summary=$dbsum,
         affected_components=$afcomp, previous_requirements=$prereq, proposed_solution=$propsol,
         has_contacted_vendor_note=$hcvn,
         cvss_v4_vector=$cv4v, cvss_v4_score=$cv4s, cvss_v4_severity=$cv4sev,
         researcher_pgp_fingerprint=$rpgpf, researcher_pgp_key_id=$rpgpk,
         last_template_id=$lastpl,
         sequence_number=$seqn
         WHERE id=$id;";
}
