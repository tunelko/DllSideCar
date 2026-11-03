using System.Text;
using System.Text.RegularExpressions;

namespace DllSidecar.Core.Services.Compilation;

/// <summary>Preserves forwarders without LINK's fuzzy symbol lookup on .def/command-line exports.</summary>
internal static class MsvcDefinitionAdapter
{
    public sealed record Adapted(string Definition, string Directives, int Forwarders);

    public static Adapted Adapt(string definition)
    {
        var def = new StringBuilder();
        var directives = new StringBuilder("/* MSVC linker directives; no executable code. */\r\n");
        int count = 0;
        foreach (var line in definition.ReplaceLineEndings("\n").Split('\n'))
        {
            var match = Regex.Match(line, "^\\s*(?<name>\"[^\"]+\"|[^\\s=;]+)\\s*=\\s*(?<target>\"[^\"]+\"|[^\\s;]+)\\s*(?<options>[^;]*)(?:;.*)?$");
            var target = match.Groups["target"].Value.Trim('"');
            if (!match.Success || !target.Contains('.')) { def.AppendLine(line); continue; }
            var name = match.Groups["name"].Value.Trim('"');
            var options = match.Groups["options"].Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (options.Any(o => !Regex.IsMatch(o, "^(@[0-9]+|NONAME|PRIVATE|DATA)$", RegexOptions.IgnoreCase)))
                throw new InvalidDataException("Unsupported MSVC forwarder options: " + line);
            var directive = "/export:" + name + "=" + target + (options.Length == 0 ? "" : "," + string.Join(',', options));
            directives.AppendLine("#pragma comment(linker, \"" + directive.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\")");
            count++;
        }
        return new(def.ToString(), directives.ToString(), count);
    }
}
