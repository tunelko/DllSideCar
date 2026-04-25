using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using DllSidecar.Core.Helpers;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace DllSidecar.Core.Services;

public enum PreflightStatus { Ready, NotElevated, SessionConflict, Unknown }

public class PreflightResult
{
    public PreflightStatus Status { get; set; }
    public string Message { get; set; } = "";
}

/// <summary>
/// Integrity level at which the traced EXE should start.
/// </summary>
public enum LaunchMode
{
    /// <summary>Try MediumIntegrity first; fall back to SameIntegrity if no shell is available or the de-elevation API fails.</summary>
    Auto,
    /// <summary>Inherit the tracer's (elevated) token. Works fine for normal apps (Notepad++, CLI tools). Breaks sandboxed apps.</summary>
    SameIntegrity,
    /// <summary>Launch via explorer.exe's token. Required for Acrobat/Chrome/Edge/Teams — apps that refuse to run correctly when inheriting a High-IL token.</summary>
    MediumIntegrity,
}

public class EtwDllTracer : IDisposable
{
    private readonly EtwTraceFilter _filter;
    private readonly ConcurrentDictionary<int, ProcessInfo> _trackedPids = new();
    private readonly ConcurrentBag<EtwTraceEvent> _events = new();
    private readonly ConcurrentBag<ProcessLifecycle> _processEvents = new();
    private int _rootPid;
    private TraceEventSession? _session;
    private Task? _processingTask;
    private readonly Stopwatch _stopwatch = new();
    private int _totalReceived;
    private bool _disposed;
    private string? _pendingProcessName;
    private string? _pendingExePath;

    public event Action<EtwTraceEvent>? EventCaptured;
    public event Action<TracedProcess>? ProcessDetected;
    public event Action<string>? StatusChanged;

    public bool IsRunning => _session != null && _processingTask is { IsCompleted: false };
    public int RootPid => _rootPid;

    public EtwDllTracer(EtwTraceFilter filter)
    {
        _filter = filter;
    }

    public static PreflightResult Preflight()
    {
        try
        {
            var elevated = TraceEventSession.IsElevated();
            if (elevated == false)
                return new PreflightResult
                {
                    Status = PreflightStatus.NotElevated,
                    Message = "ETW kernel tracing requires administrator privileges. Relaunch as admin.",
                };

            return new PreflightResult { Status = PreflightStatus.Ready, Message = "Ready to trace" };
        }
        catch (Exception ex)
        {
            return new PreflightResult
            {
                Status = PreflightStatus.Unknown,
                Message = $"Preflight check failed: {ex.Message}",
            };
        }
    }

    /// <summary>
    /// Launch mode: start ETW session first, then launch the EXE.
    /// Zero events lost — tracing is active before the first LoadLibrary.
    /// </summary>
    public void StartWithExe(string exePath, string? arguments, LaunchMode mode, CancellationToken ct)
    {
        if (IsRunning)
            throw new InvalidOperationException("Trace session already running");

        var preflight = Preflight();
        if (preflight.Status != PreflightStatus.Ready)
            throw new InvalidOperationException(preflight.Message);

        if (!File.Exists(exePath))
            throw new FileNotFoundException($"Target EXE not found: {exePath}");

        Log.Info("etw", $"Starting ETW before launching {Path.GetFileName(exePath)} (mode={mode})");
        StatusChanged?.Invoke($"Starting ETW session...");

        StartEtwSession(ct);

        var exeName = Path.GetFileName(exePath);
        var procBaseName = Path.GetFileNameWithoutExtension(exePath);
        _pendingProcessName = procBaseName;
        _pendingExePath = exePath;
        StatusChanged?.Invoke($"Launching {exeName}...");

        try
        {
            int? pid = null;
            Process? proc = null;
            bool wentMediumIL = false;

            // 1. Try medium-IL launch if requested
            if (mode == LaunchMode.Auto || mode == LaunchMode.MediumIntegrity)
            {
                try
                {
                    pid = DeElevatedLauncher.Launch(exePath, arguments, Path.GetDirectoryName(exePath));
                    wentMediumIL = pid.HasValue;
                }
                catch (Exception ex)
                {
                    if (mode == LaunchMode.MediumIntegrity)
                    {
                        Log.Error("etw", "Forced medium-IL launch failed — aborting", ex);
                        Stop();
                        throw;
                    }
                    Log.Warn("etw", $"Medium-IL launch failed ({ex.GetType().Name}: {ex.Message}) — falling back to same integrity");
                }
            }

            // 2. Fall back to same-integrity launch (or it was explicitly requested)
            if (pid == null)
            {
                var psi = new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = arguments ?? "",
                    UseShellExecute = true,
                    WorkingDirectory = Path.GetDirectoryName(exePath) ?? "",
                };
                proc = Process.Start(psi);
                if (proc != null) pid = proc.Id;
            }

            if (pid.HasValue)
            {
                _rootPid = pid.Value;
                var name = procBaseName + ".exe";
                _trackedPids[_rootPid] = new ProcessInfo(name, exePath, 0, true);
                _processEvents.Add(new ProcessLifecycle(_rootPid, 0, name, exePath, DateTime.Now, true));
                _pendingProcessName = null;
                _pendingExePath = null;

                var ilLabel = wentMediumIL ? "medium IL" : "same IL";
                Log.Info("etw", $"Launched {name} (PID {_rootPid}) at {ilLabel}");
                StatusChanged?.Invoke($"Tracing {name} (PID {_rootPid}, {ilLabel}) — interact with the app, then STOP.");
                NotifyProcessDetected(_rootPid, 0, name, exePath, true);

                // Same-IL launch: force the window visible because elevated parents produce
                // invisible windows. Medium-IL launch: the window appears on its own.
                if (!wentMediumIL && proc != null)
                    BringWindowToFront(proc, procBaseName);
            }
            else
            {
                Log.Info("etw", $"No PID returned — auto-detecting '{procBaseName}' via ETW");
                StatusChanged?.Invoke($"Tracing active — waiting for {exeName}...");
            }
        }
        catch (Exception ex)
        {
            Log.Error("etw", $"Failed to launch {exePath}", ex);
            Stop();
            throw;
        }
    }

    /// <summary>
    /// Attach mode: start tracing an already-running process by PID.
    /// Events before attach are lost.
    /// </summary>
    public void AttachToPid(int pid, CancellationToken ct)
    {
        if (IsRunning)
            throw new InvalidOperationException("Trace session already running");

        var preflight = Preflight();
        if (preflight.Status != PreflightStatus.Ready)
            throw new InvalidOperationException(preflight.Message);

        var (name, imagePath) = ResolveProcess(pid);
        _rootPid = pid;
        _trackedPids[pid] = new ProcessInfo(name, imagePath, 0, true);
        _processEvents.Add(new ProcessLifecycle(pid, 0, name, imagePath, DateTime.Now, true));

        Log.Info("etw", $"Attach mode: PID {pid} ({name}), children={_filter.IncludeChildren}");
        StatusChanged?.Invoke($"Starting trace for {name} (PID {pid})...");

        // ETW only delivers ProcessStart events from now on — pre-existing children
        // (e.g. Acrobat's AcroCEF/RdrCEF helpers that spawned at app launch) would
        // otherwise be silently filtered out of FileIOCreate events. Seed them.
        if (_filter.IncludeChildren)
            SeedExistingDescendants(pid);

        StartEtwSession(ct);

        StatusChanged?.Invoke($"Tracing {name} (PID {pid}) — interact with the application, then STOP.");
        NotifyProcessDetected(pid, 0, name, imagePath, true);
    }

    /// <summary>
    /// Walks the live process tree and adds every descendant of <paramref name="rootPid"/>
    /// to <see cref="_trackedPids"/>. Uses CreateToolhelp32Snapshot for parent-PID lookup
    /// (not exposed by System.Diagnostics.Process directly).
    /// </summary>
    private void SeedExistingDescendants(int rootPid)
    {
        var parentByPid = SnapshotParentMap();
        if (parentByPid.Count == 0) return;

        // Build children lookup once
        var childrenByParent = new Dictionary<int, List<int>>();
        foreach (var (childPid, parentPid) in parentByPid)
        {
            if (!childrenByParent.TryGetValue(parentPid, out var list))
                childrenByParent[parentPid] = list = new List<int>();
            list.Add(childPid);
        }

        var seeded = 0;
        var queue = new Queue<int>();
        queue.Enqueue(rootPid);
        var visited = new HashSet<int> { rootPid };

        while (queue.Count > 0)
        {
            var parent = queue.Dequeue();
            if (!childrenByParent.TryGetValue(parent, out var kids)) continue;
            foreach (var childPid in kids)
            {
                if (!visited.Add(childPid)) continue;
                if (_trackedPids.ContainsKey(childPid)) { queue.Enqueue(childPid); continue; }

                string childName = $"PID-{childPid}";
                string? childPath = null;
                try
                {
                    using var cp = Process.GetProcessById(childPid);
                    childName = cp.ProcessName + ".exe";
                    try { childPath = cp.MainModule?.FileName; } catch { }
                }
                catch { /* exited between snapshot and now */ }

                _trackedPids[childPid] = new ProcessInfo(childName, childPath, parent, false);
                _processEvents.Add(new ProcessLifecycle(childPid, parent, childName, childPath, DateTime.Now, false));
                NotifyProcessDetected(childPid, parent, childName, childPath, false);
                seeded++;

                queue.Enqueue(childPid);
            }
        }

        Log.Info("etw", $"Attach: seeded {seeded} pre-existing descendants of PID {rootPid}");
    }

    private static Dictionary<int, int> SnapshotParentMap()
    {
        var map = new Dictionary<int, int>();
        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == IntPtr.Zero || snap == InvalidHandleValue) return map;
        try
        {
            var pe = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            if (!Process32FirstW(snap, ref pe)) return map;
            do { map[(int)pe.th32ProcessID] = (int)pe.th32ParentProcessID; }
            while (Process32NextW(snap, ref pe));
        }
        finally { CloseHandle(snap); }
        return map;
    }

    public EtwTraceResult Stop()
    {
        _stopwatch.Stop();

        try { _session?.Source?.StopProcessing(); } catch { }
        try { _processingTask?.Wait(TimeSpan.FromSeconds(3)); } catch { }
        try { _session?.Stop(); } catch { }

        KillTrackedProcesses();

        var result = BuildResult();

        Log.Info("etw",
            $"Trace complete: {result.FilteredEvents} DLL misses from {result.TotalEventsReceived} kernel events, " +
            $"{result.ByDll.Count} unique DLLs, {_trackedPids.Count} tracked PIDs, {result.Duration.TotalSeconds:F1}s");
        Log.Info("etw",
            $"Filter stats: skipped_pid={_debugSkippedPid} skipped_ext={_debugSkippedExt} " +
            $"skipped_exists={_debugSkippedExists} skipped_known={_debugSkippedKnown} passed={_debugPassedFilter}");
        Log.Info("etw",
            $"Tracked PIDs: {string.Join(", ", _trackedPids.Keys.Select(k => $"{k}"))}");

        StatusChanged?.Invoke(
            $"Trace complete — {result.FilteredEvents} DLL misses, {result.ByDll.Count} unique DLLs");

        return result;
    }

    private void StartEtwSession(CancellationToken ct)
    {
        var sessionName = $"DllSidecar-{Guid.NewGuid():N}";
        _session = new TraceEventSession(sessionName) { StopOnDispose = true };

        _session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.FileIOInit |
            KernelTraceEventParser.Keywords.Process);

        _session.Source.Kernel.FileIOCreate += data => OnFileCreate(data, ct);
        _session.Source.Kernel.ProcessStart += OnProcessStart;
        _session.Source.Kernel.ProcessStop += OnProcessStop;

        _stopwatch.Restart();

        _processingTask = Task.Run(() =>
        {
            try
            {
                ct.Register(() =>
                {
                    try { _session?.Source?.StopProcessing(); } catch { }
                });
                _session.Source.Process();
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Log.Error("etw", "ETW processing failed", ex);
            }
        }, CancellationToken.None);
    }

    private int _debugSkippedPid;
    private int _debugSkippedExt;
    private int _debugSkippedExists;
    private int _debugSkippedKnown;
    private int _debugPassedFilter;

    private void OnFileCreate(FileIOCreateTraceData data, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        Interlocked.Increment(ref _totalReceived);

        if (!_trackedPids.TryGetValue(data.ProcessID, out var procInfo))
        {
            Interlocked.Increment(ref _debugSkippedPid);
            return;
        }

        var path = data.FileName;
        if (string.IsNullOrEmpty(path)) return;
        if (_filter.DllOnly && !path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            Interlocked.Increment(ref _debugSkippedExt);
            return;
        }
        if (_filter.NameNotFoundOnly && File.Exists(path))
        {
            Interlocked.Increment(ref _debugSkippedExists);
            return;
        }

        var dllName = Path.GetFileName(path);
        if (KnownDlls.IsKnown(dllName))
        {
            Interlocked.Increment(ref _debugSkippedKnown);
            return;
        }

        Interlocked.Increment(ref _debugPassedFilter);

        var ev = new EtwTraceEvent
        {
            ProcessId = data.ProcessID,
            ProcessName = procInfo.Name,
            ProcessImagePath = procInfo.ImagePath,
            ParentProcessId = procInfo.ParentPid,
            IsChildOfTarget = !procInfo.IsRoot,
            FilePath = path,
            Timestamp = data.TimeStamp,
        };

        _events.Add(ev);
        try { EventCaptured?.Invoke(ev); } catch { }
    }

    private void OnProcessStart(ProcessTraceData data)
    {
        // Auto-detect pending process by name (launched via explorer)
        if (_pendingProcessName != null
            && string.Equals(data.ProcessName, _pendingProcessName, StringComparison.OrdinalIgnoreCase))
        {
            _rootPid = data.ProcessID;
            var rName = data.ProcessName + ".exe";
            var rPath = data.ImageFileName ?? _pendingExePath ?? "";
            _trackedPids[data.ProcessID] = new ProcessInfo(rName, rPath, 0, true);
            _processEvents.Add(new ProcessLifecycle(data.ProcessID, 0, rName, rPath, data.TimeStamp, true));
            _pendingProcessName = null;
            _pendingExePath = null;
            Log.Info("etw", $"Auto-detected {rName} (PID {data.ProcessID})");
            StatusChanged?.Invoke($"Tracing {rName} (PID {data.ProcessID}) — interact with the application, then STOP.");
            NotifyProcessDetected(data.ProcessID, 0, rName, rPath, true);
            return;
        }

        if (!_filter.IncludeChildren) return;
        if (!_trackedPids.ContainsKey(data.ParentID)) return;

        var name = data.ProcessName + ".exe";
        var imagePath = data.ImageFileName;
        _trackedPids[data.ProcessID] = new ProcessInfo(name, imagePath, data.ParentID, false);
        _processEvents.Add(new ProcessLifecycle(data.ProcessID, data.ParentID, name, imagePath, data.TimeStamp, false));

        Log.Debug("etw", $"Child process: {name} (PID {data.ProcessID}, parent {data.ParentID})");
        StatusChanged?.Invoke($"Child: {name} (PID {data.ProcessID})");

        NotifyProcessDetected(data.ProcessID, data.ParentID, name, imagePath, false);
    }

    private void OnProcessStop(ProcessTraceData data)
    {
        if (!_trackedPids.ContainsKey(data.ProcessID)) return;

        foreach (var pe in _processEvents)
        {
            if (pe.Pid == data.ProcessID && pe.ExitTime == null)
            {
                pe.ExitTime = data.TimeStamp;
                break;
            }
        }
    }

    private void NotifyProcessDetected(int pid, int parentPid, string name, string? imagePath, bool isRoot)
    {
        try
        {
            ProcessDetected?.Invoke(new TracedProcess
            {
                Pid = pid,
                ParentPid = parentPid,
                Name = name,
                ImagePath = imagePath,
                StartTime = DateTime.Now,
                IsRootTarget = isRoot,
            });
        }
        catch { }
    }

    private EtwTraceResult BuildResult()
    {
        var events = _events.ToList();

        // Count DLL misses per process
        var missCountByPid = events
            .GroupBy(e => e.ProcessId)
            .ToDictionary(g => g.Key, g => g.Count());

        // Build flat list of TracedProcess, then assemble tree
        var allProcs = new Dictionary<int, TracedProcess>();
        foreach (var pe in _processEvents)
        {
            missCountByPid.TryGetValue(pe.Pid, out var missCount);
            allProcs[pe.Pid] = new TracedProcess
            {
                Pid = pe.Pid,
                ParentPid = pe.ParentPid,
                Name = pe.Name,
                ImagePath = pe.ImagePath,
                StartTime = pe.StartTime,
                ExitTime = pe.ExitTime,
                IsRootTarget = pe.IsRoot,
                DllMissCount = missCount,
            };
        }

        // Wire parent→children
        TracedProcess? root = null;
        foreach (var proc in allProcs.Values)
        {
            if (proc.IsRootTarget)
            {
                root = proc;
                continue;
            }
            if (allProcs.TryGetValue(proc.ParentPid, out var parent))
                parent.Children.Add(proc);
        }

        var result = new EtwTraceResult
        {
            Events = events,
            TrackedPids = new HashSet<int>(_trackedPids.Keys),
            ProcessTree = allProcs.Values.ToList(),
            RootProcess = root,
            Duration = _stopwatch.Elapsed,
            TotalEventsReceived = _totalReceived,
            FilteredEvents = events.Count,
        };

        // Aggregate by DLL
        var byDll = events
            .GroupBy(e => e.DllName, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count());

        foreach (var g in byDll)
        {
            var agg = new ProcmonAggregation { DllName = g.Key };
            foreach (var e in g)
            {
                agg.Processes.Add(e.ProcessName);
                agg.SearchedDirs.Add(e.Directory);
                agg.EventCount++;
                if (IsLikelyUserWritable(e.Directory)) agg.AnyDirUserSpace = true;
            }
            result.ByDll.Add(agg);
        }

        return result;
    }

    private static bool IsLikelyUserWritable(string dir)
    {
        if (string.IsNullOrEmpty(dir)) return false;
        var lower = dir.ToLowerInvariant();
        if (lower.StartsWith(@"c:\windows")) return false;
        if (lower.StartsWith(@"c:\program files")) return false;
        return true;
    }

    private static (string Name, string? ImagePath) ResolveProcess(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            string? imagePath = null;
            try { imagePath = proc.MainModule?.FileName; } catch { }
            return (proc.ProcessName + ".exe", imagePath);
        }
        catch
        {
            return ($"PID-{pid}", null);
        }
    }

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool AllowSetForegroundWindow(int processId);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    private const int SW_RESTORE = 9;
    private const int SW_SHOWDEFAULT = 10;

    // Toolhelp — cheapest way to read parent PID for every running process.
    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private static readonly IntPtr InvalidHandleValue = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private void BringWindowToFront(Process proc, string procBaseName)
    {
        Task.Run(async () =>
        {
            var targetPids = new HashSet<uint> { (uint)proc.Id };

            for (int attempt = 0; attempt < 20; attempt++)
            {
                await Task.Delay(750);

                // Refresh the set of PIDs we're looking for — child processes
                // appear over time (Acrobat, Chrome, etc.)
                foreach (var p in Process.GetProcessesByName(procBaseName))
                {
                    try { targetPids.Add((uint)p.Id); }
                    finally { p.Dispose(); }
                }

                // Also add any child PID the ETW tracer already discovered
                foreach (var pid in _trackedPids.Keys)
                    targetPids.Add((uint)pid);

                IntPtr found = IntPtr.Zero;
                EnumWindows((hWnd, _) =>
                {
                    GetWindowThreadProcessId(hWnd, out var pid);
                    if (!targetPids.Contains(pid)) return true;
                    if (GetWindowTextLength(hWnd) == 0) return true;

                    found = hWnd;
                    return false;
                }, IntPtr.Zero);

                if (found != IntPtr.Zero)
                {
                    GetWindowThreadProcessId(found, out var ownerPid);
                    AllowSetForegroundWindow((int)ownerPid);
                    ShowWindow(found, SW_RESTORE);
                    SetForegroundWindow(found);
                    Log.Info("etw", $"Brought window to front (hwnd=0x{found:X}, owner PID={ownerPid}, attempt {attempt + 1})");
                    return;
                }
            }
            Log.Debug("etw", $"No visible window found for {procBaseName} after 20 attempts ({string.Join(",", targetPids)})");
        });
    }

    private void KillTrackedProcesses()
    {
        foreach (var pid in _trackedPids.Keys)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                if (!proc.HasExited)
                {
                    proc.Kill(entireProcessTree: true);
                    Log.Info("etw", $"Killed PID {pid} ({proc.ProcessName})");
                }
            }
            catch (ArgumentException) { }
            catch (Exception ex) { Log.Debug("etw", $"Could not kill PID {pid}", ex); }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try { _session?.Source?.StopProcessing(); } catch { }
        try { _session?.Stop(); } catch { }
        try { _session?.Dispose(); } catch { }
        _session = null;

        GC.SuppressFinalize(this);
    }

    private record ProcessInfo(string Name, string? ImagePath, int ParentPid, bool IsRoot);

    private class ProcessLifecycle
    {
        public int Pid { get; }
        public int ParentPid { get; }
        public string Name { get; }
        public string? ImagePath { get; }
        public DateTime StartTime { get; }
        public bool IsRoot { get; }
        public DateTime? ExitTime { get; set; }

        public ProcessLifecycle(int pid, int parentPid, string name, string? imagePath, DateTime start, bool isRoot)
        {
            Pid = pid;
            ParentPid = parentPid;
            Name = name;
            ImagePath = imagePath;
            StartTime = start;
            IsRoot = isRoot;
        }
    }
}
