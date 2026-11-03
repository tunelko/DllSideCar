using DllSidecar.Core.Services.AdvisoryLibrary;
using Microsoft.Data.Sqlite;

namespace DllSidecar.Core.Tests.AdvisoryLibrary;

public class AdvisoryRepositoryMigrationTests
{
    [Fact]
    public async Task V7ToV8_CreatesBackupAndPreservesIncibeArtifact()
    {
        var test = await CreateV7LibraryAsync();
        try
        {
            var repository = new AdvisoryRepository(test.DatabasePath);

            await repository.InitializeAsync();

            Assert.NotNull(repository.LastMigrationBackupPath);
            Assert.True(File.Exists(repository.LastMigrationBackupPath));
            Assert.True(File.Exists(test.ArtifactPath));
            Assert.Equal("8", await ScalarStringAsync(test.DatabasePath,
                "SELECT value FROM schema_info WHERE key='version';"));
            Assert.Equal("1", await ScalarStringAsync(test.DatabasePath,
                "SELECT count(*) FROM advisory_artifacts WHERE template_id='incibe';"));
            Assert.Null(await ScalarStringAsync(test.DatabasePath,
                "SELECT last_template_id FROM advisory_records WHERE id='adv-1';"));
            Assert.False(await ColumnExistsAsync(test.DatabasePath, "advisory_records", "attack_type"));

            Assert.Equal("7", await ScalarStringAsync(repository.LastMigrationBackupPath!,
                "SELECT value FROM schema_info WHERE key='version';"));
            Assert.Equal("incibe", await ScalarStringAsync(repository.LastMigrationBackupPath!,
                "SELECT last_template_id FROM advisory_records WHERE id='adv-1';"));
            Assert.True(await ColumnExistsAsync(
                repository.LastMigrationBackupPath!, "advisory_records", "attack_type"));
        }
        finally
        {
            DeleteDirectory(test.DirectoryPath);
        }
    }

    [Fact]
    public async Task Initialize_RejectsNewerSchemaWithoutRestampingIt()
    {
        var directory = CreateTempDirectory();
        var databasePath = Path.Combine(directory, "library.db");
        try
        {
            var seed = new AdvisoryRepository(databasePath);
            await seed.InitializeAsync();
            await ExecuteAsync(databasePath,
                "UPDATE schema_info SET value='99' WHERE key='version';");

            var repository = new AdvisoryRepository(databasePath);
            var error = await Assert.ThrowsAsync<InvalidDataException>(
                () => repository.InitializeAsync());

            Assert.Contains("not supported", error.Message);
            Assert.Null(repository.LastMigrationBackupPath);
            Assert.Equal("99", await ScalarStringAsync(databasePath,
                "SELECT value FROM schema_info WHERE key='version';"));
        }
        finally
        {
            DeleteDirectory(directory);
        }
    }

    private static async Task<TestLibrary> CreateV7LibraryAsync()
    {
        var directory = CreateTempDirectory();
        var databasePath = Path.Combine(directory, "library.db");
        var artifactPath = Path.Combine(directory, "INCIBE-legacy.txt");
        File.WriteAllText(artifactPath, "legacy INCIBE advisory");

        var seed = new AdvisoryRepository(databasePath);
        await seed.InitializeAsync();

        await using var connection = Open(databasePath);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = @"
            ALTER TABLE advisory_records ADD COLUMN attack_type TEXT;
            ALTER TABLE advisory_records ADD COLUMN impact_category TEXT;
            ALTER TABLE advisory_records ADD COLUMN incibe_ranking_opt_in INTEGER;
            ALTER TABLE advisory_records ADD COLUMN incibe_public_display_name TEXT;
            UPDATE schema_info SET value='7' WHERE key='version';
            INSERT INTO advisory_records
                (id, created_at_utc, updated_at_utc, status, title,
                 directory_low_priv_writable, markdown_body, last_template_id,
                 attack_type, impact_category, incibe_ranking_opt_in,
                 incibe_public_display_name)
            VALUES
                ('adv-1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0,
                 'Legacy INCIBE', 1, 'legacy body', 'incibe',
                 'Local', 'Privilege escalation', 1, 'Researcher');
            INSERT INTO advisory_artifacts
                (advisory_id, artifact_kind, path, label, created_at_utc, template_id, status)
            VALUES
                ('adv-1', 0, $path, 'INCIBE legacy', '2026-01-01T00:00:00Z', 'incibe', 0);";
        command.Parameters.AddWithValue("$path", artifactPath);
        await command.ExecuteNonQueryAsync();

        return new TestLibrary(directory, databasePath, artifactPath);
    }

    private static async Task ExecuteAsync(string databasePath, string sql)
    {
        await using var connection = Open(databasePath);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<string?> ScalarStringAsync(string databasePath, string sql)
    {
        await using var connection = Open(databasePath);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        var value = await command.ExecuteScalarAsync();
        return value == null || value == DBNull.Value ? null : Convert.ToString(value);
    }

    private static async Task<bool> ColumnExistsAsync(
        string databasePath,
        string table,
        string column)
    {
        await using var connection = Open(databasePath);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({table});";
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            if (string.Equals(reader.GetString(1), column, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static SqliteConnection Open(string databasePath) =>
        new($"Data Source={databasePath}");

    private static string CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dllsidecar-advisory-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private static void DeleteDirectory(string path)
    {
        try { Directory.Delete(path, recursive: true); } catch { }
    }

    private sealed record TestLibrary(
        string DirectoryPath,
        string DatabasePath,
        string ArtifactPath);
}
