using System.Text.RegularExpressions;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;

namespace DllSidecar.Core.Services.Privesc;

/// <summary>
/// Parses each PE's embedded application manifest (RT_MANIFEST, type 24 / id 1) and
/// flags:
///   - autoElevate=true   → classic UAC bypass surface (fodhelper, sdclt, ...)
///   - level=requireAdministrator → runs at high integrity when launched
///   - uiAccess=true      → bypass UIPI, used with signed binaries for UI injection
/// A DLL sideload on any of these yields elevation without UAC prompt when the EXE
/// is signed by Microsoft.
/// </summary>
public class AutoElevateDetector : IPrivescDetector
{
    public string Name => "AutoElevateDetector";

    // Precompiled regexes — manifests are small XML docs, regex is enough and avoids
    // pulling in XmlDocument for what is essentially three flag checks.
    private static readonly Regex RxAutoElevate =
        new(@"<\s*autoElevate\s*>\s*true\s*<\s*/\s*autoElevate\s*>", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex RxLevel =
        new(@"requestedExecutionLevel[^>]*\blevel\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex RxUiAccess =
        new(@"requestedExecutionLevel[^>]*\buiAccess\s*=\s*[""']true[""']", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public void Prepare(PrivescDetectorContext ctx, CancellationToken ct) { /* stateless */ }

    public IEnumerable<PrivescFinding> Detect(PeAnalysis pe, PrivescDetectorContext ctx, CancellationToken ct)
    {
        if (pe.IsDll) yield break; // manifests on DLLs exist but don't drive elevation

        string? manifest = TryReadManifest(pe.Path);
        if (string.IsNullOrEmpty(manifest)) yield break;

        bool autoElevate = RxAutoElevate.IsMatch(manifest);
        bool uiAccess = RxUiAccess.IsMatch(manifest);
        string? level = null;
        var levelMatch = RxLevel.Match(manifest);
        if (levelMatch.Success) level = levelMatch.Groups[1].Value;

        if (autoElevate)
        {
            yield return new PrivescFinding
            {
                Vector = PrivescVector.AutoElevate,
                Severity = PrivescSeverity.High,
                DetectorName = Name,
                Title = "EXE manifest declares autoElevate=true",
                Evidence = "<autoElevate>true</autoElevate>",
                Extras =
                {
                    ["ExecutionLevel"] = level ?? "not-set",
                    ["UiAccess"] = uiAccess.ToString(),
                },
            };
        }

        if (!autoElevate && string.Equals(level, "requireAdministrator", StringComparison.OrdinalIgnoreCase))
        {
            yield return new PrivescFinding
            {
                Vector = PrivescVector.HighIntegrity,
                Severity = PrivescSeverity.Medium,
                DetectorName = Name,
                Title = "EXE requires Administrator (prompts UAC)",
                Evidence = $"requestedExecutionLevel level=\"{level}\"",
                Extras = { ["UiAccess"] = uiAccess.ToString() },
            };
        }

        if (uiAccess)
        {
            yield return new PrivescFinding
            {
                Vector = PrivescVector.AutoElevate,
                Severity = PrivescSeverity.Medium,
                DetectorName = Name,
                Title = "EXE requests uiAccess=true (UIPI bypass)",
                Evidence = "uiAccess=\"true\"",
                Extras = { ["ExecutionLevel"] = level ?? "not-set" },
            };
        }
    }

    /// <summary>
    /// Read RT_MANIFEST resource from PE. Uses PeNet if possible; falls back to a scan
    /// of the file bytes for &lt;assembly...&gt; + &lt;/assembly&gt; marker pair. Manifests
    /// are small (&lt;4KB typically), so the fallback is cheap.
    /// </summary>
    private static string? TryReadManifest(string path)
    {
        // Attempt PeNet's native resource parsing first
        try
        {
            var pe = new PeNet.PeFile(path);
            // PeNet 5.0 exposes manifest string when present
            var mf = pe.Resources?.GetType().GetProperty("Manifest")?.GetValue(pe.Resources) as string;
            if (!string.IsNullOrEmpty(mf)) return mf;
        }
        catch (Exception ex)
        {
            Log.Debug("privesc.autoelevate", $"PeNet manifest read failed for {path}", ex);
        }

        // Fallback: raw byte scan. Manifests are embedded as UTF-8 with <assembly ...>
        // wrapping — locate and extract.
        try
        {
            var bytes = File.ReadAllBytes(path);
            var needle = "<assembly"u8.ToArray();
            int start = IndexOf(bytes, needle, 0);
            if (start < 0) return null;
            var endNeedle = "</assembly>"u8.ToArray();
            int end = IndexOf(bytes, endNeedle, start);
            if (end < 0) return null;
            int stop = end + endNeedle.Length;
            return System.Text.Encoding.UTF8.GetString(bytes, start, stop - start);
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    private static int IndexOf(byte[] haystack, byte[] needle, int from)
    {
        for (int i = from; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }
}
