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

    /// <summary>Raw NT CreateOptions DWORD from the kernel FileIO/Create event.</summary>
    public uint CreateOptions { get; set; }

    /// <summary>Loader-vs-probe classification derived from <see cref="CreateOptions"/>.</summary>
    public AccessClass Access { get; set; } = AccessClass.Unknown;
}
