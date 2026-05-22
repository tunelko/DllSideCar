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
    // When set, OnProcessStart adopts every new process whose name matches.
    // Survives multiple PID generations (e.g. service stop+start cycles).
    private string? _watchProcessName;
    // Optional command-line substring required for the watch to adopt a match.
    // Use case: svchost-hosted services. The image basename (svchost.exe) is
    // shared by hundreds of unrelated svchost groups, so name-only watching
    // floods with noise. Setting this to "-s BITS" (or whatever -s arg the
    // service uses) restricts adoption to the right svchost instance.
    private string? _watchCmdLineFilter;

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
    /// Watch-by-name mode: start the ETW session with no PID and adopt every
    /// future process whose image name matches <paramref name="processName"/>.
    /// Then optionally fire a CLI command to trigger the lookup (sc start svc,
    /// regsvr32 evil.dll, splunk restart, etc.).
    ///
    /// <paramref name="cmdLineFilter"/> is an optional case-insensitive substring
    /// the new process's command line must contain to be adopted. Use this when
    /// the image name is shared (svchost.exe) — pass "-s BITS" to capture only
    /// the BITS-hosting svchost group. Empty/null = name-only matching.
    ///
    /// Designed for services that change PID across restarts: the session stays
    /// up across multiple stop/start cycles and aggregates events from every PID
    /// that matched the name (and the optional cmd-line filter).
    /// </summary>
    public void StartWatchByName(string processName, string? runCommand, CancellationToken ct, string? cmdLineFilter = null)
    {
        if (IsRunning)
            throw new InvalidOperationException("Trace session already running");
        if (string.IsNullOrWhiteSpace(processName))
            throw new ArgumentException("Process name is required", nameof(processName));

        var preflight = Preflight();
        if (preflight.Status != PreflightStatus.Ready)
            throw new InvalidOperationException(preflight.Message);

        // Strip .exe so we match TraceEvent's ProcessName field (basename, no ext).
        var bareName = Path.GetFileNameWithoutExtension(processName.Trim());
        if (string.IsNullOrEmpty(bareName))
            throw new ArgumentException($"Could not derive a process name from '{processName}'", nameof(processName));

        _watchProcessName = bareName;
        _watchCmdLineFilter = string.IsNullOrWhiteSpace(cmdLineFilter) ? null : cmdLineFilter.Trim();
        var filterLog = _watchCmdLineFilter == null ? "" : $", cmdline~='{_watchCmdLineFilter}'";
        Log.Info("etw", $"Watch-by-name mode: target='{bareName}'{filterLog}, children={_filter.IncludeChildren}");
        StatusChanged?.Invoke($"Starting ETW session — watching for '{bareName}'...");

        StartEtwSession(ct);

        // Optionally fire a CLI command to trigger whatever loads the target DLL.
        // Spawned via cmd.exe /c so users can chain (sc stop x && sc start x),
        // pipe, redirect — any normal shell construct.
        if (!string.IsNullOrWhiteSpace(runCommand))
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {runCommand}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                var proc = Process.Start(psi);
                if (proc != null)
                {
                    Log.Info("etw", $"Launched watcher command (PID {proc.Id}): {runCommand}");
                    // Drain output asynchronously so the command can complete; we
                    // don't block the caller — the ETW session is the long-running part.
                    Task.Run(() =>
                    {
                        try
                        {
                            var stdout = proc.StandardOutput.ReadToEnd();
                            var stderr = proc.StandardError.ReadToEnd();
                            proc.WaitForExit(30_000);
                            if (!string.IsNullOrWhiteSpace(stdout))
                                Log.Info("etw", $"cmd stdout: {stdout.Trim()}");
                            if (!string.IsNullOrWhiteSpace(stderr))
                                Log.Warn("etw", $"cmd stderr: {stderr.Trim()}");
                            Log.Info("etw", $"Watcher command exited with code {proc.ExitCode}");
                        }
                        catch (Exception ex) { Log.Warn("etw", $"Watcher command drain failed: {ex.Message}"); }
                    });
                }
            }
            catch (Exception ex)
            {
                Log.Error("etw", $"Failed to launch watcher command '{runCommand}'", ex);
                // Don't tear down the session — the user may still trigger the target
                // manually from another shell, and the ETW session is already capturing.
            }
        }

        StatusChanged?.Invoke(
            $"Watching for '{bareName}' — trigger the target now (or any restart cycle), then STOP.");
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

        // Watch-by-name targets are typically services (splunkd, sshd, etc.) the
        // user does NOT want killed on stop. Only kill processes we launched
        // ourselves via StartWithExe.
        if (_watchProcessName == null)
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

        // CreateOptions on FileIOCreateTraceData is signed in some TraceEvent
        // builds; cast through an unchecked uint so the bit pattern is preserved.
        var createOptions = unchecked((uint)data.CreateOptions);
        var ev = new EtwTraceEvent
        {
            ProcessId = data.ProcessID,
            ProcessName = procInfo.Name,
            ProcessImagePath = procInfo.ImagePath,
            ParentProcessId = procInfo.ParentPid,
            IsChildOfTarget = !procInfo.IsRoot,
            FilePath = path,
            Timestamp = data.TimeStamp,
            CreateOptions = createOptions,
            Access = AccessClassifier.Classify(createOptions),
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
            // Launch mode: the user-supplied full path is the ground truth — it's
            // literally what they want to land in Craft's Host EXE field after
            // Promote. ETW's data.ImageFileName arrives as a kernel device path
            // ("\Device\HarddiskVolume3\…") or a basename depending on the kernel
            // build, neither of which is useful for compilation. Prefer the
            // user's input; fall back to ETW only when StartWithExe wasn't the
            // entry point (e.g. tracer was attached after process startup).
            var rPath = !string.IsNullOrEmpty(_pendingExePath) ? _pendingExePath : (data.ImageFileName ?? "");
            _trackedPids[data.ProcessID] = new ProcessInfo(rName, rPath, 0, true);
            _processEvents.Add(new ProcessLifecycle(data.ProcessID, 0, rName, rPath, data.TimeStamp, true));
            _pendingProcessName = null;
            _pendingExePath = null;
            Log.Info("etw", $"Auto-detected {rName} (PID {data.ProcessID})");
            StatusChanged?.Invoke($"Tracing {rName} (PID {data.ProcessID}) — interact with the application, then STOP.");
            NotifyProcessDetected(data.ProcessID, 0, rName, rPath, true);
            return;
        }

        // Watch-by-name mode: every new process whose name matches becomes a
        // tracked root. Allows multiple PID generations (service restarts) to
        // accumulate into the same trace result.
        if (_watchProcessName != null
            && string.Equals(data.ProcessName, _watchProcessName, StringComparison.OrdinalIgnoreCase)
            && !_trackedPids.ContainsKey(data.ProcessID))
        {
            // Optional cmd-line filter: required for svchost-style shared hosts
            // where many unrelated PIDs share the same image name.
            if (_watchCmdLineFilter != null)
            {
                var cmd = data.CommandLine ?? "";
                if (!cmd.Contains(_watchCmdLineFilter, StringComparison.OrdinalIgnoreCase))
                {
                    Log.Debug("etw", $"Watch-by-name skipped {data.ProcessName} PID {data.ProcessID}: cmdline does not contain '{_watchCmdLineFilter}'");
                    return;
                }
            }
            var rName = data.ProcessName + ".exe";
            // ETW's data.ImageFileName is unreliable for newly-started processes —
            // it arrives as a kernel device path (\Device\HarddiskVolume3\...) or
            // a bare basename depending on the kernel build. Neither helps the
            // downstream consumers (CraftStage Host EXE, AttackPath Analyze).
            // The process is guaranteed alive at this point (PID just appeared in
            // ETW), so QueryFullProcessImageName gives us the canonical drive-
            // letter path. Falls back to whatever ETW handed us only if Win32
            // refuses the lookup (process died between events, etc.).
            var rPath = ResolveImagePathForLivePid(data.ProcessID, data.ImageFileName);
            // First match becomes the "root" for tree-building purposes;
            // subsequent matches are tagged as roots too so they all show up
            // at the top level of the process tree.
            var isFirst = _rootPid == 0;
            if (isFirst) _rootPid = data.ProcessID;
            _trackedPids[data.ProcessID] = new ProcessInfo(rName, rPath, 0, true);
            _processEvents.Add(new ProcessLifecycle(data.ProcessID, 0, rName, rPath, data.TimeStamp, true));
            Log.Info("etw", $"Watch-by-name matched: {rName} (PID {data.ProcessID}) at {rPath}");
            StatusChanged?.Invoke($"Adopted {rName} (PID {data.ProcessID})");
            NotifyProcessDetected(data.ProcessID, 0, rName, rPath, true);
            return;
        }

        if (!_filter.IncludeChildren) return;
        if (!_trackedPids.ContainsKey(data.ParentID)) return;

        var name = data.ProcessName + ".exe";
        // Same path-quality issue as the Watch branch above: ETW's ImageFileName
        // is unreliable for fresh PIDs, so we resolve via Win32 while the child
        // is still alive. Downstream code (EtwResultConverter, CraftStage) reads
        // these paths verbatim — if they're basenames the Host EXE field ends
        // up degraded after Promote.
        var imagePath = ResolveImagePathForLivePid(data.ProcessID, data.ImageFileName);
        _trackedPids[data.ProcessID] = new ProcessInfo(name, imagePath, data.ParentID, false);
        _processEvents.Add(new ProcessLifecycle(data.ProcessID, data.ParentID, name, imagePath, data.TimeStamp, false));

        Log.Debug("etw", $"Child process: {name} (PID {data.ProcessID}, parent {data.ParentID})");
        StatusChanged?.Invoke($"Child: {name} (PID {data.ProcessID})");

        NotifyProcessDetected(data.ProcessID, data.ParentID, name, imagePath, false);
    }

    /// <summary>
    /// Best-effort rooted full-path resolver for a process the ETW kernel just
    /// announced. <see cref="ProcessImagePath.TryGet"/> uses
    /// <c>QueryFullProcessImageName</c> which works cross-architecture (x64 host
    /// reading an x86 process and vice versa). When the Win32 call returns
    /// something rooted we trust it; otherwise we fall through to whatever ETW
    /// gave us (basename / kernel device path / null) so the lifecycle record
    /// still has *some* identifier downstream.
    /// </summary>
    private static string ResolveImagePathForLivePid(int pid, string? etwImagePath)
    {
        try
        {
            var win32 = Helpers.ProcessImagePath.TryGet(pid);
            if (!string.IsNullOrEmpty(win32) && Path.IsPathRooted(win32))
                return win32;
        }
        catch { /* swallow — fall through to ETW value */ }
        return etwImagePath ?? "";
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
            // Sandbox-relevant token signals captured here while the process is
            // guaranteed alive. Same data is also stamped on the matching
            // ProcessLifecycle so BuildResult can populate the persisted tree.
            var (il, isAc) = CaptureTokenInfo(pid);
            AnnotateLifecycle(pid, il, isAc);

            ProcessDetected?.Invoke(new TracedProcess
            {
                Pid = pid,
                ParentPid = parentPid,
                Name = name,
                ImagePath = imagePath,
                StartTime = DateTime.Now,
                IsRootTarget = isRoot,
                IntegrityLevel = il,
                IsAppContainer = isAc,
            });
        }
        catch { }
    }

    private void AnnotateLifecycle(int pid, IntegrityLevel il, bool isAppContainer)
    {
        // ProcessLifecycle is appended right BEFORE NotifyProcessDetected in every
        // hook (StartWithExe, AttachToPid, SeedExistingDescendants, OnProcessStart).
        // The order means the matching record exists by the time we reach here —
        // we just stamp the token fields on it.
        foreach (var pe in _processEvents)
        {
            if (pe.Pid == pid && pe.IntegrityLevel == IntegrityLevel.Unknown)
            {
                pe.IntegrityLevel = il;
                pe.IsAppContainer = isAppContainer;
                break;
            }
        }
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
                IntegrityLevel = pe.IntegrityLevel,
                IsAppContainer = pe.IsAppContainer,
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
                switch (e.Access)
                {
                    case AccessClass.LoaderLike:    agg.LoaderLikeCount++; break;
                    case AccessClass.MetadataProbe: agg.MetadataProbeCount++; break;
                }
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
            // Prefer QueryFullProcessImageName via ProcessImagePath helper — works
            // cross-arch where Process.MainModule throws (x64 host reading an x86
            // process or vice versa). MainModule is the last resort.
            var imagePath = ProcessImagePath.TryGet(pid);
            if (string.IsNullOrEmpty(imagePath))
            {
                try { imagePath = proc.MainModule?.FileName; } catch { }
            }
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

        // Captured at detection time, while the process is still alive — once the
        // process exits, OpenProcess fails and we can't recover these. Default to
        // Unknown so a missed-capture path still serializes cleanly.
        public IntegrityLevel IntegrityLevel { get; set; } = IntegrityLevel.Unknown;
        public bool IsAppContainer { get; set; }

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

    // ──────────────── Token signal capture (Phase 2 dynamic) ────────────────
    //
    // Queried right after a process is detected (alive guaranteed at that moment).
    // Failures are swallowed — token info is best-effort; the static classifier
    // already covers the high-value research targets when this gap appears.

    /// <summary>Read the process token and populate (IntegrityLevel, IsAppContainer)
    /// for use by <see cref="SandboxClassifier"/>. Returns defaults on any failure.</summary>
    private static (IntegrityLevel IL, bool IsAppContainer) CaptureTokenInfo(int pid)
    {
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        const uint TOKEN_QUERY = 0x0008;
        const int  TokenIsAppContainer = 29;

        IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero) return (IntegrityLevel.Unknown, false);
        try
        {
            if (!OpenProcessToken(hProc, TOKEN_QUERY, out var hTok) || hTok == IntPtr.Zero)
                return (IntegrityLevel.Unknown, false);
            try
            {
                bool isAc = QueryTokenBool(hTok, TokenIsAppContainer);
                var il = QueryTokenIntegrity(hTok);
                return (il, isAc);
            }
            finally { CloseHandle(hTok); }
        }
        finally { CloseHandle(hProc); }
    }

    private static bool QueryTokenBool(IntPtr hTok, int infoClass)
    {
        // TokenIsAppContainer returns a 4-byte DWORD (0/1).
        uint size = 4;
        IntPtr buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (!GetTokenInformation(hTok, infoClass, buf, size, out _)) return false;
            return Marshal.ReadInt32(buf) != 0;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static IntegrityLevel QueryTokenIntegrity(IntPtr hTok)
    {
        const int TokenIntegrityLevel = 25;
        // First call discovers required buffer size, second call fills it.
        GetTokenInformation(hTok, TokenIntegrityLevel, IntPtr.Zero, 0, out var needed);
        if (needed == 0) return IntegrityLevel.Unknown;
        IntPtr buf = Marshal.AllocHGlobal((int)needed);
        try
        {
            if (!GetTokenInformation(hTok, TokenIntegrityLevel, buf, needed, out _))
                return IntegrityLevel.Unknown;
            // TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label } — Label.Sid is a
            // pointer to the integrity SID; the last sub-authority is the RID.
            IntPtr pSid = Marshal.ReadIntPtr(buf);
            if (pSid == IntPtr.Zero) return IntegrityLevel.Unknown;
            // GetSidSubAuthorityCount returns a pointer to a byte; index its value.
            IntPtr pCount = GetSidSubAuthorityCount(pSid);
            if (pCount == IntPtr.Zero) return IntegrityLevel.Unknown;
            byte count = Marshal.ReadByte(pCount);
            if (count == 0) return IntegrityLevel.Unknown;
            IntPtr pSub = GetSidSubAuthority(pSid, (uint)(count - 1));
            if (pSub == IntPtr.Zero) return IntegrityLevel.Unknown;
            uint rid = (uint)Marshal.ReadInt32(pSub);
            return rid switch
            {
                0 => IntegrityLevel.Untrusted,
                0x1000 => IntegrityLevel.Low,        // 4096
                0x2000 => IntegrityLevel.Medium,     // 8192
                0x2100 => IntegrityLevel.MediumPlus, // 8448
                0x3000 => IntegrityLevel.High,       // 12288
                0x4000 => IntegrityLevel.System,     // 16384
                0x5000 => IntegrityLevel.ProtectedProcess, // 20480
                _ => IntegrityLevel.Unknown,
            };
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr hProcess, uint desiredAccess, out IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr hToken, int tokenInfoClass,
        IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);
}
