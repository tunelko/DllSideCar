using System.Text;
using System.Text.RegularExpressions;
using DllSidecar.Core.Models.Execution;

namespace DllSidecar.Core.Services.Execution;

/// <summary>
/// Resolves a command line into a <see cref="ResolvedExecutionTarget"/>; peels one wrapper level (cmd, powershell, rundll32, msiexec).
/// </summary>
public static class ExecutionResolver
{
    private static readonly HashSet<string> CmdNames        = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "cmd" };
    private static readonly HashSet<string> PowerShellNames = new(StringComparer.OrdinalIgnoreCase) { "powershell.exe", "powershell", "pwsh.exe", "pwsh" };
    private static readonly HashSet<string> RunDll32Names   = new(StringComparer.OrdinalIgnoreCase) { "rundll32.exe", "rundll32" };
    private static readonly HashSet<string> MsiExecNames    = new(StringComparer.OrdinalIgnoreCase) { "msiexec.exe", "msiexec" };

    /// <summary>
    /// Resolve a command line; if <paramref name="arguments"/> is non-null, respect the caller's Command/Arguments split.
    /// </summary>
    public static ResolvedExecutionTarget Resolve(string command, string? arguments = null, string? workingDir = null)
    {
        var original = BuildOriginal(command, arguments);
        var result = new ResolvedExecutionTarget
        {
            OriginalCommand = original,
            WorkingDirectory = string.IsNullOrWhiteSpace(workingDir) ? null : ExpandEnv(workingDir),
        };

        if (string.IsNullOrWhiteSpace(command))
        {
            result.Status = ResolutionStatus.Unresolved;
            return result;
        }

        // Step 1: expand env vars everywhere
        var expandedCommand   = ExpandEnv(command);
        var expandedArguments = arguments == null ? null : ExpandEnv(arguments);

        // Step 2: split head (exe) from tail (args)
        var (head, tail) = SplitHead(expandedCommand, expandedArguments);
        var headName = Path.GetFileName(head.Trim('"')).Trim();

        // Step 3: wrapper dispatch
        if (CmdNames.Contains(headName))         return ParseCmd(original, tail, result);
        if (PowerShellNames.Contains(headName))  return ParsePowerShell(original, tail, result);
        if (RunDll32Names.Contains(headName))    return ParseRunDll32(original, tail, result);
        if (MsiExecNames.Contains(headName))     return ParseMsiExec(original, tail, result);

        // Direct invocation — head is the target
        result.ResolvedPath = StripQuotes(head);
        result.Arguments = NullIfEmpty(tail);
        result.Status = ResolutionStatus.Resolved;
        return result;
    }

    // ─────────── Wrapper parsers ───────────

    private static ResolvedExecutionTarget ParseCmd(string original, string tail, ResolvedExecutionTarget r)
    {
        r.Wrapper = WrapperKind.Cmd;
        // /c or /k: take the first following token (respecting quotes) as the target.
        var tokens = Tokenize(tail);
        for (int i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i];
            if (t.Equals("/c", StringComparison.OrdinalIgnoreCase) ||
                t.Equals("/k", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= tokens.Count) break;
                var target = tokens[i + 1];
                r.ResolvedPath = StripQuotes(target);
                r.Arguments = tokens.Count > i + 2 ? string.Join(" ", tokens.Skip(i + 2)) : null;
                r.Status = LooksLikePath(r.ResolvedPath) ? ResolutionStatus.Resolved : ResolutionStatus.Partial;
                return r;
            }
        }
        // No /c or /k — treat as partial (some old scripts use cmd without switch)
        r.Status = ResolutionStatus.Partial;
        return r;
    }

    private static ResolvedExecutionTarget ParsePowerShell(string original, string tail, ResolvedExecutionTarget r)
    {
        r.Wrapper = WrapperKind.PowerShell;
        var tokens = Tokenize(tail);
        for (int i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i].TrimStart('-', '/').ToLowerInvariant();
            if ((t == "file" || t == "f") && i + 1 < tokens.Count)
            {
                r.ResolvedPath = StripQuotes(tokens[i + 1]);
                r.Arguments = tokens.Count > i + 2 ? string.Join(" ", tokens.Skip(i + 2)) : null;
                r.Status = ResolutionStatus.Resolved;
                return r;
            }
            if ((t == "encodedcommand" || t == "enc" || t == "e" || t == "ec") && i + 1 < tokens.Count)
            {
                var decoded = TryDecodePowerShellBase64(tokens[i + 1]);
                if (decoded != null)
                {
                    var path = ExtractFirstPath(decoded);
                    if (path != null)
                    {
                        r.ResolvedPath = path;
                        r.Status = ResolutionStatus.Partial; // First-path heuristic, not authoritative
                        return r;
                    }
                }
                r.Status = ResolutionStatus.Partial;
                return r;
            }
            if (t == "command" || t == "c")
            {
                // -Command inline script — look for a literal path inside remaining tokens
                var rest = string.Join(" ", tokens.Skip(i + 1));
                var path = ExtractFirstPath(rest);
                if (path != null) { r.ResolvedPath = path; r.Status = ResolutionStatus.Partial; return r; }
                r.Status = ResolutionStatus.Partial;
                return r;
            }
        }
        r.Status = ResolutionStatus.Partial;
        return r;
    }

    private static ResolvedExecutionTarget ParseRunDll32(string original, string tail, ResolvedExecutionTarget r)
    {
        r.Wrapper = WrapperKind.RunDll32;
        var tokens = Tokenize(tail);
        // Skip leading switches (rundll32 doesn't really use any well-known ones, but be safe)
        var first = tokens.FirstOrDefault(t => !t.StartsWith('/') && !t.StartsWith('-'));
        if (first == null) { r.Status = ResolutionStatus.Partial; return r; }

        // rundll32 "path,Entry" comma form is the common one.
        var commaIdx = first.LastIndexOf(',');
        var target = commaIdx > 0 ? first[..commaIdx] : first;
        r.ResolvedPath = StripQuotes(target);
        r.Arguments = tokens.Count > 1 ? string.Join(" ", tokens.Skip(1)) : null;
        r.Status = LooksLikePath(r.ResolvedPath) ? ResolutionStatus.Resolved : ResolutionStatus.Partial;
        return r;
    }

    private static ResolvedExecutionTarget ParseMsiExec(string original, string tail, ResolvedExecutionTarget r)
    {
        r.Wrapper = WrapperKind.MsiExec;
        var tokens = Tokenize(tail);
        for (int i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i].ToLowerInvariant();
            if ((t == "/i" || t == "/x" || t == "/a" || t == "/package") && i + 1 < tokens.Count)
            {
                r.ResolvedPath = StripQuotes(tokens[i + 1]);
                r.Arguments = tokens.Count > i + 2 ? string.Join(" ", tokens.Skip(i + 2)) : null;
                r.Status = LooksLikePath(r.ResolvedPath) ? ResolutionStatus.Resolved : ResolutionStatus.Partial;
                return r;
            }
        }
        r.Status = ResolutionStatus.Partial;
        return r;
    }

    // ─────────── Helpers ───────────

    private static string BuildOriginal(string command, string? arguments) =>
        string.IsNullOrEmpty(arguments) ? command : $"{command} {arguments}";

    private static string ExpandEnv(string s)
    {
        try { return Environment.ExpandEnvironmentVariables(s); }
        catch { return s; }
    }

    /// <summary>
    /// Split head/tail: if arguments supplied separately, command IS the exe verbatim.
    /// </summary>
    private static (string head, string tail) SplitHead(string command, string? arguments)
    {
        if (arguments != null)
            return (command.Trim(), arguments.Trim());

        var tokens = Tokenize(command);
        if (tokens.Count == 0) return (command, "");
        var head = tokens[0];
        var tail = tokens.Count > 1 ? string.Join(" ", tokens.Skip(1)) : "";
        return (head, tail);
    }

    /// <summary>Whitespace tokenizer that respects double-quoted spans.</summary>
    private static List<string> Tokenize(string s)
    {
        var tokens = new List<string>();
        if (string.IsNullOrEmpty(s)) return tokens;
        var sb = new StringBuilder();
        bool inQuotes = false;
        foreach (var ch in s)
        {
            if (ch == '"') { sb.Append(ch); inQuotes = !inQuotes; continue; }
            if (!inQuotes && char.IsWhiteSpace(ch))
            {
                if (sb.Length > 0) { tokens.Add(sb.ToString()); sb.Clear(); }
            }
            else sb.Append(ch);
        }
        if (sb.Length > 0) tokens.Add(sb.ToString());
        return tokens;
    }

    private static string StripQuotes(string s) =>
        s.Length >= 2 && s.StartsWith('"') && s.EndsWith('"') ? s[1..^1] : s;

    private static string? NullIfEmpty(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s;

    private static bool LooksLikePath(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        s = s.Trim().Trim('"');
        if (s.Length < 2) return false;
        // Drive letter (C:), UNC (\\server), env var remnant (%x%\...)
        return (char.IsLetter(s[0]) && s[1] == ':') ||
               s.StartsWith(@"\\") ||
               s.Contains('%');
    }

    private static string? TryDecodePowerShellBase64(string b64)
    {
        try
        {
            var bytes = Convert.FromBase64String(b64);
            // PowerShell -EncodedCommand uses UTF-16 LE
            return Encoding.Unicode.GetString(bytes);
        }
        catch { return null; }
    }

    private static readonly Regex PathRegex = new(
        @"(?:[A-Za-z]:\\[^\s"";|<>]+|%[^%]+%\\[^\s"";|<>]+|\\\\[^\s"";|<>]+)",
        RegexOptions.Compiled);

    private static string? ExtractFirstPath(string text)
    {
        var m = PathRegex.Match(text);
        return m.Success ? m.Value : null;
    }
}
