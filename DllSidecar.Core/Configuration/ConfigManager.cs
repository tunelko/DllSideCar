using System.Text.Json;
using DllSidecar.Core.Logging;

namespace DllSidecar.Core.Configuration;

public static class ConfigManager
{
    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "DllSidecar");

    public static string ConfigPath { get; } = Path.Combine(ConfigDir, "config.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private static AppConfig? _current;
    public static AppConfig Current => _current ??= Load();

    public class ConfigResult
    {
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public static ConfigResult LastLoadResult { get; private set; } = new() { Success = true };
    public static ConfigResult LastSaveResult { get; private set; } = new() { Success = true };

    public static AppConfig Load()
    {
        if (!File.Exists(ConfigPath))
        {
            Log.Info("config", $"No config at {ConfigPath} — using defaults");
            LastLoadResult = new ConfigResult { Success = true };
            return new AppConfig();
        }
        try
        {
            var json = File.ReadAllText(ConfigPath);
            var cfg = JsonSerializer.Deserialize<AppConfig>(json, JsonOptions);
            if (cfg == null)
            {
                var msg = $"Config at {ConfigPath} deserialized to null — using defaults";
                Log.Warn("config", msg);
                LastLoadResult = new ConfigResult { Success = false, ErrorMessage = msg };
                return new AppConfig();
            }
            Log.Info("config", $"Loaded config from {ConfigPath}");
            LastLoadResult = new ConfigResult { Success = true };
            return cfg;
        }
        catch (JsonException ex)
        {
            Log.Error("config", $"Config JSON malformed at {ConfigPath}; using defaults", ex);
            LastLoadResult = new ConfigResult { Success = false, ErrorMessage = $"Malformed JSON: {ex.Message}" };
            return new AppConfig();
        }
        catch (IOException ex)
        {
            Log.Error("config", $"I/O error reading {ConfigPath}", ex);
            LastLoadResult = new ConfigResult { Success = false, ErrorMessage = ex.Message };
            return new AppConfig();
        }
        catch (UnauthorizedAccessException ex)
        {
            Log.Error("config", $"Permission denied reading {ConfigPath}", ex);
            LastLoadResult = new ConfigResult { Success = false, ErrorMessage = ex.Message };
            return new AppConfig();
        }
    }

    public static ConfigResult Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);
            var json = JsonSerializer.Serialize(Current, JsonOptions);
            File.WriteAllText(ConfigPath, json);
            Log.Info("config", $"Saved config to {ConfigPath}");
            LastSaveResult = new ConfigResult { Success = true };
            return LastSaveResult;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Error("config", $"Failed to save config to {ConfigPath}", ex);
            LastSaveResult = new ConfigResult { Success = false, ErrorMessage = ex.Message };
            return LastSaveResult;
        }
    }

    public static ConfigResult Reset()
    {
        _current = new AppConfig();
        return Save();
    }

    public static void Reload() => _current = Load();
}
