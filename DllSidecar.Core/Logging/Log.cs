namespace DllSidecar.Core.Logging;

public enum LogLevel { Debug, Info, Warn, Error }

public record LogEntry(DateTime Timestamp, LogLevel Level, string Category, string Message, Exception? Exception);

/// <summary>
/// Static logging facade for Core. GUI (or tests) subscribe to the Emitted event.
/// Never silently drops errors — every caught exception flows through here.
/// </summary>
public static class Log
{
    public static event Action<LogEntry>? Emitted;

    public static LogLevel MinLevel { get; set; } = LogLevel.Info;

    public static void Debug(string category, string message, Exception? ex = null) =>
        Write(LogLevel.Debug, category, message, ex);

    public static void Info(string category, string message, Exception? ex = null) =>
        Write(LogLevel.Info, category, message, ex);

    public static void Warn(string category, string message, Exception? ex = null) =>
        Write(LogLevel.Warn, category, message, ex);

    public static void Error(string category, string message, Exception? ex = null) =>
        Write(LogLevel.Error, category, message, ex);

    private static void Write(LogLevel level, string category, string message, Exception? ex)
    {
        if (level < MinLevel) return;
        var entry = new LogEntry(DateTime.Now, level, category, message, ex);
        try { Emitted?.Invoke(entry); }
        catch { /* subscriber threw — swallow to avoid logger recursion; no better option */ }
    }
}
