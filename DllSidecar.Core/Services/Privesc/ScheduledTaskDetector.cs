using System.Xml;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Execution;
using DllSidecar.Core.Models.Privesc;
using DllSidecar.Core.Services.Execution;

namespace DllSidecar.Core.Services.Privesc;

/// <summary>
/// Enumerates scheduled tasks stored as XML under %SystemRoot%\System32\Tasks. Each
/// task file is an XML with schema http://schemas.microsoft.com/windows/2004/02/mit/task.
///
/// Sprint-2 robustness: in addition to Exec.Command we parse Arguments, WorkingDirectory,
/// and ALL Exec actions under Actions (a task may chain several). The combined command
/// is passed to <see cref="ExecutionResolver"/> to peel one level of wrapper (cmd/c,
/// powershell -File, rundll32, msiexec). Findings carry full context so consumers
/// (Sprint-3 targeted re-scan) can act on the resolved target.
/// </summary>
public class ScheduledTaskDetector : IPrivescDetector
{
    public string Name => "ScheduledTaskDetector";

    private readonly Dictionary<string, List<TaskEntry>> _peToTasks =
        new(StringComparer.OrdinalIgnoreCase);

    public class TaskEntry
    {
        public required string TaskName { get; set; }
        public required string OriginalCommand { get; set; }
        public string? ResolvedPath { get; set; }
        public string? Arguments { get; set; }
        public string? WorkingDirectory { get; set; }
        public WrapperKind Wrapper { get; set; } = WrapperKind.None;
        public ResolutionStatus ResolutionStatus { get; set; } = ResolutionStatus.Resolved;
        public string? UserId { get; set; }
        public string? GroupId { get; set; }
        public string? RunLevel { get; set; }

        public bool ResolvedViaWrapper => Wrapper != WrapperKind.None;

        public bool RunsAsSystem =>
            !string.IsNullOrEmpty(UserId) &&
            (UserId.Equals("S-1-5-18", StringComparison.OrdinalIgnoreCase) ||
             UserId.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
             UserId.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase));

        public bool RunsElevated =>
            RunsAsSystem || string.Equals(RunLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase);
    }

    public void Prepare(PrivescDetectorContext ctx, CancellationToken ct)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
        if (!Directory.Exists(root))
        {
            Log.Warn("privesc.tasks", $"Tasks directory not found: {root}");
            return;
        }

        int totalTasks = 0, matched = 0;
        try
        {
            foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                totalTasks++;
                try
                {
                    string taskName;
                    try { taskName = Path.GetRelativePath(root, file); }
                    catch { taskName = Path.GetFileName(file); }

                    var xml = File.ReadAllText(file);
                    var entries = ParseTaskXml(xml, taskName);
                    foreach (var entry in entries)
                    {
                        if (TryMatchScanned(entry, ctx, out var matchKey))
                        {
                            AddMatch(matchKey, entry);
                            matched++;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { /* some tasks restrict ACLs — skip */ }
                catch (XmlException ex)
                {
                    Log.Debug("privesc.tasks", $"Task XML malformed: {file}", ex);
                }
                catch (Exception ex)
                {
                    Log.Debug("privesc.tasks", $"Error parsing {file}", ex);
                }
            }
            Log.Info("privesc.tasks",
                $"Enumerated {totalTasks} scheduled tasks; {matched} match scanned PEs");
        }
        catch (OperationCanceledException) { throw; }
        catch (UnauthorizedAccessException ex)
        {
            Log.Warn("privesc.tasks", $"Access denied under {root} — results may be partial", ex);
        }
    }

    public IEnumerable<PrivescFinding> Detect(PeAnalysis pe, PrivescDetectorContext ctx, CancellationToken ct)
    {
        if (!_peToTasks.TryGetValue(pe.Path, out var tasks)) yield break;

        foreach (var t in tasks)
        {
            var severity = t.RunsAsSystem
                ? PrivescSeverity.High
                : t.RunsElevated
                    ? PrivescSeverity.Medium
                    : PrivescSeverity.Informational;

            var finding = new PrivescFinding
            {
                Vector = PrivescVector.ScheduledTask,
                Severity = severity,
                DetectorName = Name,
                Title = t.ResolvedViaWrapper
                    ? $"Executed by scheduled task '{t.TaskName}' via {t.Wrapper.ToString().ToLowerInvariant()}"
                    : $"Executed by scheduled task '{t.TaskName}'",
                Evidence = BuildEvidence(t),
                PrivilegedProcessPath = t.ResolvedPath ?? t.OriginalCommand,
                PrivilegedAccount = t.UserId ?? t.GroupId ?? "(unspecified)",
                Extras =
                {
                    ["TaskName"]           = t.TaskName,
                    ["RunLevel"]           = t.RunLevel ?? "LeastPrivilege",
                    ["UserId"]             = t.UserId ?? "",
                    ["GroupId"]            = t.GroupId ?? "",
                    ["OriginalCommand"]    = t.OriginalCommand,
                    ["ResolvedTarget"]     = t.ResolvedPath ?? "",
                    ["ResolvedViaWrapper"] = t.ResolvedViaWrapper ? "true" : "false",
                    ["WrapperKind"]        = t.Wrapper.ToString(),
                    ["ResolutionStatus"]   = t.ResolutionStatus.ToString(),
                },
            };
            if (!string.IsNullOrEmpty(t.Arguments))
                finding.Extras["Arguments"] = t.Arguments;
            if (!string.IsNullOrEmpty(t.WorkingDirectory))
                finding.Extras["WorkingDirectory"] = t.WorkingDirectory;

            yield return finding;
        }
    }

    private static string BuildEvidence(TaskEntry t)
    {
        var parts = new List<string>
        {
            $"Task XML: %SystemRoot%\\System32\\Tasks\\{t.TaskName}",
            $"Command: {t.OriginalCommand}",
        };
        if (t.ResolvedViaWrapper)
            parts.Add($"Wrapper: {t.Wrapper} → {t.ResolvedPath ?? "(unresolved)"}");
        if (!string.IsNullOrEmpty(t.WorkingDirectory))
            parts.Add($"WorkingDir: {t.WorkingDirectory}");
        return string.Join("  ·  ", parts);
    }

    private static bool TryMatchScanned(TaskEntry entry, PrivescDetectorContext ctx, out string matchKey)
    {
        matchKey = "";
        if (string.IsNullOrEmpty(entry.ResolvedPath)) return false;
        try
        {
            var normalized = Path.GetFullPath(entry.ResolvedPath).ToLowerInvariant();
            if (ctx.AllScannedPaths.Contains(normalized))
            {
                // PE lookup key expected by _peToTasks is the original PE.Path (case-preserving)
                matchKey = ctx.PathToPe[normalized].Path;
                return true;
            }
        }
        catch (ArgumentException) { /* bad path characters — skip */ }
        catch (NotSupportedException) { /* likewise */ }
        return false;
    }

    private void AddMatch(string path, TaskEntry entry)
    {
        if (!_peToTasks.TryGetValue(path, out var list))
        {
            list = [];
            _peToTasks[path] = list;
        }
        list.Add(entry);
    }

    /// <summary>
    /// Parse a Task Scheduler XML into zero or more TaskEntry (one per Exec action).
    /// Pure — no file I/O, no environment side effects beyond env-var expansion inside
    /// the resolver. Exposed publicly for unit tests.
    /// </summary>
    public static List<TaskEntry> ParseTaskXml(string xml, string taskName)
    {
        var doc = new XmlDocument();
        doc.LoadXml(xml);

        var nsmgr = new XmlNamespaceManager(doc.NameTable);
        var ns = doc.DocumentElement?.NamespaceURI ?? "";
        if (!string.IsNullOrEmpty(ns)) nsmgr.AddNamespace("t", ns);
        var prefix = string.IsNullOrEmpty(ns) ? "" : "t:";

        // Principal — accounts and run level (same across all Exec actions in one task file)
        var principalNode = doc.SelectSingleNode($"//{prefix}Principals/{prefix}Principal", nsmgr);
        var userId = principalNode?.SelectSingleNode($"{prefix}UserId", nsmgr)?.InnerText;
        var groupId = principalNode?.SelectSingleNode($"{prefix}GroupId", nsmgr)?.InnerText;
        var runLevel = principalNode?.SelectSingleNode($"{prefix}RunLevel", nsmgr)?.InnerText;

        var entries = new List<TaskEntry>();
        var execNodes = doc.SelectNodes($"//{prefix}Actions/{prefix}Exec", nsmgr);
        if (execNodes == null) return entries;

        foreach (XmlNode exec in execNodes)
        {
            var command = exec.SelectSingleNode($"{prefix}Command", nsmgr)?.InnerText?.Trim();
            if (string.IsNullOrEmpty(command)) continue;

            var arguments = exec.SelectSingleNode($"{prefix}Arguments", nsmgr)?.InnerText?.Trim();
            var workingDir = exec.SelectSingleNode($"{prefix}WorkingDirectory", nsmgr)?.InnerText?.Trim();

            // Strip outer quotes from Command (common quirk); leave args untouched
            command = command.Trim('"');

            var resolved = ExecutionResolver.Resolve(command, arguments, workingDir);

            entries.Add(new TaskEntry
            {
                TaskName = taskName,
                OriginalCommand = resolved.OriginalCommand,
                ResolvedPath = resolved.ResolvedPath,
                Arguments = resolved.Arguments,
                WorkingDirectory = resolved.WorkingDirectory,
                Wrapper = resolved.Wrapper,
                ResolutionStatus = resolved.Status,
                UserId = userId,
                GroupId = groupId,
                RunLevel = runLevel,
            });
        }

        return entries;
    }
}
