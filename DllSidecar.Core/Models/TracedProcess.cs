namespace DllSidecar.Core.Models;

public class TracedProcess
{
    public required int Pid { get; set; }
    public int ParentPid { get; set; }
    public required string Name { get; set; }
    public string? ImagePath { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime? ExitTime { get; set; }
    public bool IsRootTarget { get; set; }
    public int DllMissCount { get; set; }
    public List<TracedProcess> Children { get; set; } = [];

    // Token signals captured at process detection time; drive SandboxClassifier's dynamic verdict.
    public IntegrityLevel IntegrityLevel { get; set; } = IntegrityLevel.Unknown;
    public bool IsAppContainer { get; set; }

    public TimeSpan? Lifetime => ExitTime.HasValue ? ExitTime.Value - StartTime : null;
    public string LifetimeLabel => Lifetime.HasValue
        ? $"{Lifetime.Value.TotalMilliseconds:F0}ms"
        : "running";
}
