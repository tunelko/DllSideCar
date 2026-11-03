using System.Text.RegularExpressions;

namespace DllSidecar.Core.Services;

/// <summary>Resolves quoted template includes transitively and copies a complete, self-contained header set.</summary>
public static partial class TemplateDependencyResolver
{
    [GeneratedRegex("^\\s*#\\s*include\\s*\"(?<name>[^\"]+)\"", RegexOptions.Multiline)]
    private static partial Regex LocalIncludeRegex();

    public static IReadOnlyList<string> CopyRequiredHeaders(
        IEnumerable<string> generatedSources, string templatesDir, string outputDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(templatesDir);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDir);

        var required = ResolveRequiredHeaders(generatedSources, templatesDir);
        Directory.CreateDirectory(outputDir);
        foreach (var header in required)
            File.Copy(Path.Combine(templatesDir, header), Path.Combine(outputDir, header), true);
        return required;
    }

    public static IReadOnlyList<string> ResolveRequiredHeaders(
        IEnumerable<string> generatedSources, string templatesDir)
    {
        ArgumentNullException.ThrowIfNull(generatedSources);
        if (!Directory.Exists(templatesDir))
            throw new DirectoryNotFoundException($"Template directory not found: {templatesDir}");

        var queue = new Queue<string>(generatedSources.SelectMany(QuotedIncludes));
        var resolved = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (queue.TryDequeue(out var include))
        {
            var header = ValidateHeaderName(include);
            if (!seen.Add(header)) continue;

            var source = Path.Combine(templatesDir, header);
            if (!File.Exists(source))
                throw new FileNotFoundException($"Required template header '{header}' was not found", source);

            resolved.Add(header);
            foreach (var dependency in QuotedIncludes(File.ReadAllText(source)))
                queue.Enqueue(dependency);
        }

        return resolved;
    }

    private static IEnumerable<string> QuotedIncludes(string source) =>
        LocalIncludeRegex().Matches(source).Select(m => m.Groups["name"].Value);

    private static string ValidateHeaderName(string include)
    {
        var name = include.Replace('/', Path.DirectorySeparatorChar);
        if (Path.IsPathRooted(name) || name != Path.GetFileName(name) ||
            !name.EndsWith(".h", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"Unsupported local template include: {include}");
        return name;
    }
}
