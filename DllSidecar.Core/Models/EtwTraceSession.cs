namespace DllSidecar.Core.Models;

public enum TraceMode { LaunchExe, AttachPid, WatchByName }

public class EtwTraceFilter
{
    public string ProcessFilter { get; set; } = "";
    public bool IncludeChildren { get; set; } = true;
    public bool NameNotFoundOnly { get; set; } = true;
    public bool DllOnly { get; set; } = true;

    // When set, EtwDllTracer.StartWatchByName picks up every ProcessStart whose
    // image basename matches (case-insensitive, with or without .exe). Used to
    // capture services that restart and change PID (splunkd, sshd, etc.).
    public string? WatchProcessName { get; set; }
}

public class EtwTraceResult
{
    public List<EtwTraceEvent> Events { get; set; } = [];
    public List<ProcmonAggregation> ByDll { get; set; } = [];
    public HashSet<int> TrackedPids { get; set; } = [];
    public List<TracedProcess> ProcessTree { get; set; } = [];
    public TracedProcess? RootProcess { get; set; }
    public TimeSpan Duration { get; set; }
    public int TotalEventsReceived { get; set; }
    public int FilteredEvents { get; set; }
    public string? Error { get; set; }
}
