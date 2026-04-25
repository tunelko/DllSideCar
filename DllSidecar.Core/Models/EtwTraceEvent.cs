namespace DllSidecar.Core.Models;

public class EtwTraceEvent
{
    public required int ProcessId { get; set; }
    public required string ProcessName { get; set; }
    public required string FilePath { get; set; }
    public required DateTime Timestamp { get; set; }
    public int ParentProcessId { get; set; }
    public string? ProcessImagePath { get; set; }
    public bool IsChildOfTarget { get; set; }
    public string DllName => Path.GetFileName(FilePath);
    public string Directory => Path.GetDirectoryName(FilePath) ?? "";
}
