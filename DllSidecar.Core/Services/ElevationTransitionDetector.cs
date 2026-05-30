using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>Detects UAC elevation transitions in a sequence of <see cref="ProcmonEvent"/>.</summary>
public static class ElevationTransitionDetector
{
    /// <summary>
    /// Scan the event list, identify elevation transitions, and tag each event's <see cref="ProcmonEvent.Phase"/>. Idempotent.
    /// </summary>
    public static List<ElevationTransition> DetectAndTag(
        IList<ProcmonEvent> events,
        IReadOnlyDictionary<int, IntegrityLevel>? pidIntegrity = null)
    {
        var transitions = Detect(events, pidIntegrity);
        TagEvents(events, transitions);
        return transitions;
    }

    /// <summary>
    /// Detect transitions without mutating events. When <paramref name="pidIntegrity"/>
    /// is non-null (live ETW path), requires the child PID to be High or System IL AND
    /// strictly higher than the parent PID's IL — drops false positives like Battle.net
    /// where a launcher spawns same-name children that never elevate.
    /// </summary>
    public static List<ElevationTransition> Detect(
        IEnumerable<ProcmonEvent> events,
        IReadOnlyDictionary<int, IntegrityLevel>? pidIntegrity = null)
    {
        var result = new List<ElevationTransition>();

        var byName = events
            .Where(e => e.Pid.HasValue)
            .GroupBy(e => e.ProcessName, StringComparer.OrdinalIgnoreCase);

        foreach (var nameGroup in byName)
        {
            var byPid = nameGroup
                .GroupBy(e => e.Pid!.Value)
                .ToList();
            if (byPid.Count < 2) continue;

            var windows = byPid
                .Select(g => new
                {
                    Pid = g.Key,
                    First = g.Min(e => e.Timestamp),
                    Last  = g.Max(e => e.Timestamp),
                    Count = g.Count(),
                })
                .ToList();

            for (int i = 0; i < windows.Count; i++)
            {
                for (int j = 0; j < windows.Count; j++)
                {
                    if (i == j) continue;
                    var parent = windows[i];
                    var child  = windows[j];

                    if (parent.Last == null || child.First == null) continue;
                    if (parent.Last >= child.First) continue;

                    // IL gate: when we have integrity data, require child High/System AND > parent.
                    if (pidIntegrity != null)
                    {
                        pidIntegrity.TryGetValue(child.Pid, out var childIl);
                        pidIntegrity.TryGetValue(parent.Pid, out var parentIl);
                        bool childElevated = childIl == IntegrityLevel.High || childIl == IntegrityLevel.System;
                        if (!childElevated) continue;
                        if (parentIl != IntegrityLevel.Unknown && (int)childIl <= (int)parentIl) continue;
                    }

                    if (result.Any(t =>
                        string.Equals(t.ProcessName, nameGroup.Key, StringComparison.OrdinalIgnoreCase)
                        && (t.ChildPid == child.Pid || t.ParentPid == child.Pid)))
                        continue;
                    if (result.Any(t =>
                        string.Equals(t.ProcessName, nameGroup.Key, StringComparison.OrdinalIgnoreCase)
                        && t.ParentPid == parent.Pid))
                        continue;

                    result.Add(new ElevationTransition(
                        ProcessName: nameGroup.Key,
                        ParentPid: parent.Pid,
                        ChildPid: child.Pid,
                        ParentLastSeen: parent.Last,
                        ChildFirstSeen: child.First));
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Apply the detected transitions, setting each event's <see cref="ProcmonEvent.Phase"/>.
    /// </summary>
    public static void TagEvents(IEnumerable<ProcmonEvent> events, IEnumerable<ElevationTransition> transitions)
    {
        var byName = transitions.GroupBy(t => t.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        foreach (var ev in events)
        {
            if (!ev.Pid.HasValue) continue;
            if (!byName.TryGetValue(ev.ProcessName, out var ts)) continue;

            foreach (var t in ts)
            {
                if (ev.Pid.Value == t.ParentPid) { ev.Phase = IlPhase.MediumIl; break; }
                if (ev.Pid.Value == t.ChildPid)  { ev.Phase = IlPhase.HighIl;   break; }
            }
        }
    }

    /// <summary>
    /// Re-derive the per-aggregation HighIlSearch flag from the tagged event list.
    /// </summary>
    public static void PopulateAggregationFlags(IList<ProcmonAggregation> aggregations, IEnumerable<ProcmonEvent> events)
    {
        var highIlByDll = events
            .Where(e => e.Phase == IlPhase.HighIl)
            .Select(e => e.DllName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var agg in aggregations)
            agg.HighIlSearch = highIlByDll.Contains(agg.DllName);
    }

    /// <summary>
    /// Runs detect, tag, and populate-aggregations in sequence. Idempotent.
    /// </summary>
    public static List<ElevationTransition> RunFullPipeline(
        IList<ProcmonEvent> events,
        IList<ProcmonAggregation> aggregations,
        IReadOnlyDictionary<int, IntegrityLevel>? pidIntegrity = null)
    {
        var transitions = DetectAndTag(events, pidIntegrity);
        PopulateAggregationFlags(aggregations, events);
        if (transitions.Count > 0)
        {
            foreach (var t in transitions)
                Log.Info("elevation.detector",
                    $"Transition detected: {t.ProcessName} PID {t.ParentPid} -> {t.ChildPid} (gap: {t.Gap?.TotalMilliseconds ?? -1:F0} ms)");
        }
        return transitions;
    }
}
