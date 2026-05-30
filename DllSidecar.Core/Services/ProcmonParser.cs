using System.Globalization;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Parses ProcMon CSV exports (UTF-8 BOM; columns: Time of Day, Process Name, PID, Operation, Path, Result, Detail) and extracts DLL-resolution failures.
/// </summary>
public static class ProcmonParser
{
    public class ParseResult
    {
        public List<ProcmonEvent> Events { get; } = [];
        public List<ProcmonAggregation> ByDll { get; } = [];
        public int TotalRows { get; set; }
        public int FilteredRows { get; set; }
        public string? Error { get; set; }
        /// <summary>
        /// UAC elevation transitions detected in the event stream. Empty when none.
        /// </summary>
        public List<ElevationTransition> Transitions { get; set; } = [];
    }

    public static ParseResult Parse(string csvPath, string? processFilter = null)
    {
        var result = new ParseResult();

        if (!File.Exists(csvPath))
        {
            result.Error = $"File not found: {csvPath}";
            Log.Error("procmon", result.Error);
            return result;
        }

        try
        {
            using var sr = new StreamReader(csvPath, System.Text.Encoding.UTF8);
            var headerLine = sr.ReadLine();
            if (headerLine == null)
            {
                result.Error = "Empty CSV";
                return result;
            }
            var headers = SplitCsvLine(headerLine);

            int idxProc   = IndexOf(headers, "Process Name");
            int idxPid    = IndexOf(headers, "PID");
            int idxOp     = IndexOf(headers, "Operation");
            int idxPath   = IndexOf(headers, "Path");
            int idxResult = IndexOf(headers, "Result");
            int idxTime   = IndexOf(headers, "Time of Day");
            int idxDetail = IndexOf(headers, "Detail");

            if (idxProc < 0 || idxOp < 0 || idxPath < 0 || idxResult < 0)
            {
                result.Error = "CSV missing required columns (Process Name / Operation / Path / Result)";
                Log.Error("procmon", result.Error);
                return result;
            }

            string? line;
            while ((line = sr.ReadLine()) != null)
            {
                result.TotalRows++;
                var cols = SplitCsvLine(line);
                if (cols.Count <= Math.Max(idxProc, Math.Max(idxPath, idxResult))) continue;

                var proc   = cols[idxProc];
                var op     = cols[idxOp];
                var resCol = cols[idxResult];
                var path   = cols[idxPath];

                if (!string.IsNullOrEmpty(processFilter) &&
                    !proc.Contains(processFilter, StringComparison.OrdinalIgnoreCase)) continue;

                if (!resCol.Contains("NAME NOT FOUND", StringComparison.OrdinalIgnoreCase)) continue;
                if (!path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) continue;

                string? detail = null;
                if (idxDetail >= 0 && idxDetail < cols.Count) detail = cols[idxDetail];

                var ev = new ProcmonEvent
                {
                    ProcessName = proc,
                    Operation = op,
                    Result = resCol,
                    Path = path,
                    Detail = detail,
                    Access = AccessClassifier.Classify(detail),
                };
                if (idxPid >= 0 && idxPid < cols.Count && int.TryParse(cols[idxPid], out var pid))
                    ev.Pid = pid;
                if (idxTime >= 0 && idxTime < cols.Count &&
                    DateTime.TryParse(cols[idxTime], CultureInfo.InvariantCulture, DateTimeStyles.None, out var ts))
                    ev.Timestamp = ts;

                result.Events.Add(ev);
                result.FilteredRows++;
            }

            // Aggregate by DLL name
            var byDll = result.Events
                .GroupBy(e => e.DllName, StringComparer.OrdinalIgnoreCase);
            foreach (var g in byDll)
            {
                var agg = new ProcmonAggregation { DllName = g.Key };
                foreach (var e in g)
                {
                    agg.Processes.Add(e.ProcessName);
                    if (!string.IsNullOrEmpty(e.SearchDir)) agg.SearchedDirs.Add(e.SearchDir);
                    agg.EventCount++;
                    if (IsLikelyUserSpace(e.SearchDir)) agg.AnyDirUserSpace = true;
                    switch (e.Access)
                    {
                        case AccessClass.LoaderLike:    agg.LoaderLikeCount++; break;
                        case AccessClass.MetadataProbe: agg.MetadataProbeCount++; break;
                        // Unknown intentionally uncounted.
                    }
                }
                result.ByDll.Add(agg);
            }
            result.ByDll.Sort((a, b) => b.EventCount.CompareTo(a.EventCount));

            // UAC elevation transition detection (idempotent, always runs).
            result.Transitions = ElevationTransitionDetector.RunFullPipeline(result.Events, result.ByDll);

            Log.Info("procmon",
                $"Parsed {csvPath}: {result.TotalRows} rows -> {result.FilteredRows} DLL NAME-NOT-FOUND events, {result.ByDll.Count} unique DLLs, {result.Transitions.Count} elevation transition(s)");
        }
        catch (IOException ex)
        {
            result.Error = $"I/O error: {ex.Message}";
            Log.Error("procmon", $"Failed to read {csvPath}", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            result.Error = $"Permission denied: {ex.Message}";
            Log.Error("procmon", $"Permission denied on {csvPath}", ex);
        }

        return result;
    }

    private static bool IsLikelyUserSpace(string dir)
    {
        if (string.IsNullOrEmpty(dir)) return false;
        var lower = dir.ToLowerInvariant();
        if (lower.StartsWith(@"c:\windows")) return false;
        if (lower.StartsWith(@"c:\program files")) return false;
        return true;
    }

    private static int IndexOf(List<string> headers, string name)
    {
        for (int i = 0; i < headers.Count; i++)
            if (string.Equals(headers[i], name, StringComparison.OrdinalIgnoreCase)) return i;
        return -1;
    }

    /// <summary>
    /// Minimal RFC 4180 CSV line splitter (quoted fields, escaped double-quotes).
    /// </summary>
    private static List<string> SplitCsvLine(string line)
    {
        var result = new List<string>();
        var sb = new System.Text.StringBuilder();
        bool inQuotes = false;

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"')
                    {
                        sb.Append('"');
                        i++;
                    }
                    else inQuotes = false;
                }
                else sb.Append(c);
            }
            else
            {
                if (c == ',') { result.Add(sb.ToString()); sb.Clear(); }
                else if (c == '"') inQuotes = true;
                else sb.Append(c);
            }
        }
        result.Add(sb.ToString());
        return result;
    }
}
