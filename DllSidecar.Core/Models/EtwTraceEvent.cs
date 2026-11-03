namespace DllSidecar.Core.Models;

public enum EtwEventKind { FileOpen, ImageLoad }

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

    public EtwEventKind Kind { get; set; }
    // Null also covers saved traces captured before completion correlation existed.
    public uint? NtStatus { get; set; }
    public DateTime? CompletedAt { get; set; }
    public bool IsMissing => Kind == EtwEventKind.FileOpen && NtStatus is 0xC0000034 or 0xC000003A;
    public bool IsVerified => Kind == EtwEventKind.ImageLoad || NtStatus.HasValue;
    public string Operation => Kind == EtwEventKind.ImageLoad ? "Load Image" : "CreateFile";
    public string Result => Kind == EtwEventKind.ImageLoad ? "IMAGE LOADED" : NtStatus switch
    {
        null => "UNKNOWN (no completion)",
        0 => "SUCCESS",
        0xC0000034 => "NAME NOT FOUND",
        0xC000003A => "PATH NOT FOUND",
        0xC0000022 => "ACCESS DENIED",
        0xC0000043 => "SHARING VIOLATION",
        _ => $"NTSTATUS 0x{NtStatus:X8}",
    };
}
