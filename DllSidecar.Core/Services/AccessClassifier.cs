using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Classifies a CreateFile-on-DLL event as <see cref="AccessClass.LoaderLike"/> vs <see cref="AccessClass.MetadataProbe"/> from either a ProcMon Detail string or NT CreateOptions DWORD.
/// </summary>
public static class AccessClassifier
{
    // ── NT CreateOptions flags (subset relevant to load vs probe) ────────────
    public const uint FILE_DIRECTORY_FILE          = 0x00000001;
    public const uint FILE_WRITE_THROUGH           = 0x00000002;
    public const uint FILE_SEQUENTIAL_ONLY         = 0x00000004;
    public const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
    public const uint FILE_NON_DIRECTORY_FILE      = 0x00000040;
    public const uint FILE_OPEN_REPARSE_POINT      = 0x00200000;

    // ── ProcMon Detail parsing ───────────────────────────────────────────────

    /// <summary>
    /// Known ProcMon field names; split key boundaries since values can contain commas.
    /// </summary>
    private static readonly string[] FieldKeys =
    {
        "Desired Access:",
        "Disposition:",
        "Options:",
        "Attributes:",
        "ShareMode:",
        "AllocationSize:",
        "OpenResult:",
        "Impersonating:",
    };

    /// <summary>
    /// Parse a ProcMon Detail string into a field map.
    /// </summary>
    public static Dictionary<string, string> ParseDetail(string? detail)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(detail)) return result;

        // Locate field offsets, then slice between adjacent starts.
        var positions = new List<(int Idx, string Key)>();
        foreach (var fk in FieldKeys)
        {
            int from = 0;
            while (from < detail.Length)
            {
                var idx = detail.IndexOf(fk, from, StringComparison.OrdinalIgnoreCase);
                if (idx < 0) break;
                positions.Add((idx, fk));
                from = idx + fk.Length;
            }
        }
        positions.Sort((a, b) => a.Idx.CompareTo(b.Idx));

        for (int i = 0; i < positions.Count; i++)
        {
            var (idx, key) = positions[i];
            var valStart = idx + key.Length;
            var valEnd = i + 1 < positions.Count ? positions[i + 1].Idx : detail.Length;
            var val = detail.Substring(valStart, valEnd - valStart).Trim().TrimEnd(',').Trim();
            result[key.TrimEnd(':')] = val;
        }
        return result;
    }

    /// <summary>
    /// Classify a ProcMon CSV row from its Detail string.
    /// </summary>
    public static AccessClass Classify(string? procmonDetail)
    {
        if (string.IsNullOrEmpty(procmonDetail)) return AccessClass.Unknown;
        var f = ParseDetail(procmonDetail);
        f.TryGetValue("Desired Access", out var desired);
        f.TryGetValue("Options", out var options);
        desired ??= "";
        options ??= "";

        // Loader fingerprint: ReadData/GenericRead/Execute, or NonDir+SyncIO image-map shape.
        var hasReadData =
            desired.Contains("Read Data", StringComparison.OrdinalIgnoreCase) ||
            desired.Contains("Generic Read", StringComparison.OrdinalIgnoreCase) ||
            desired.Contains("Execute", StringComparison.OrdinalIgnoreCase);
        var hasLoadOptions =
            options.Contains("Non-Directory File", StringComparison.OrdinalIgnoreCase) &&
            options.Contains("Synchronous IO Non-Alert", StringComparison.OrdinalIgnoreCase);
        if (hasReadData || hasLoadOptions) return AccessClass.LoaderLike;

        // Probe fingerprint: Open Reparse Point (GetFileAttributes/PathFileExists/FindFirstFile).
        if (options.Contains("Open Reparse Point", StringComparison.OrdinalIgnoreCase))
            return AccessClass.MetadataProbe;

        return AccessClass.Unknown;
    }

    // ── ETW CreateOptions classification ─────────────────────────────────────

    /// <summary>
    /// Classify a kernel FileIO/Create event from its CreateOptions DWORD.
    /// </summary>
    public static AccessClass Classify(uint createOptions)
    {
        var hasNonDir = (createOptions & FILE_NON_DIRECTORY_FILE) != 0;
        var hasSyncIo = (createOptions & FILE_SYNCHRONOUS_IO_NONALERT) != 0;
        var hasReparse = (createOptions & FILE_OPEN_REPARSE_POINT) != 0;

        // Loader-style: NonDir + SyncIO, no reparse-point flag.
        if (hasNonDir && hasSyncIo && !hasReparse) return AccessClass.LoaderLike;

        // Pure probe: reparse-point flag alone.
        if (hasReparse && !hasNonDir && !hasSyncIo) return AccessClass.MetadataProbe;

        // Default-open (CreateOptions==0) is ambiguous.
        return AccessClass.Unknown;
    }

    // ── UI labels ────────────────────────────────────────────────────────────

    /// <summary>
    /// ProcMon-faithful labels (shared via <see cref="AccessClassLabels"/>).
    /// </summary>
    public const string LabelLoad  = AccessClassLabels.Load;
    public const string LabelProbe = AccessClassLabels.Probe;
    public const string LabelMixed = AccessClassLabels.Mixed;

    public static string Label(AccessClass cls) => cls switch
    {
        AccessClass.LoaderLike    => AccessClassLabels.Load,
        AccessClass.MetadataProbe => AccessClassLabels.Probe,
        _                         => "",
    };
}
