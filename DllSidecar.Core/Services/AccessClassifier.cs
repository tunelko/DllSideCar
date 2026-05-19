using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Single source of truth for classifying a CreateFile-on-DLL event as a real loader
/// open (<see cref="AccessClass.LoaderLike"/>) vs an app-internal metadata probe
/// (<see cref="AccessClass.MetadataProbe"/>).
///
/// Two input shapes:
///   - ProcMon CSV "Detail" string (human-readable, with named fields)
///   - ETW kernel FileIO / Create "CreateOptions" DWORD (NT flags)
///
/// Both should yield the same classification for equivalent events so ProcMon-driven
/// and runtime-driven flows agree on whether to upgrade Confidence.
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
    /// Known field names in the order ProcMon emits them. Used to split the Detail
    /// string into key→value pairs since values themselves can contain commas
    /// (e.g. "ShareMode: Read, Write, Delete").
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
    /// Parse a ProcMon Detail string into a field map. Public so UI / debug tools can
    /// surface individual fields without re-implementing the splitter.
    /// </summary>
    public static Dictionary<string, string> ParseDetail(string? detail)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(detail)) return result;

        // Locate every field's starting offset. A second pass slices the detail
        // string between adjacent field starts to get the value.
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
    /// Classify a ProcMon CSV row from its Detail string. Falls back to
    /// <see cref="AccessClass.Unknown"/> when neither fingerprint matches.
    /// </summary>
    public static AccessClass Classify(string? procmonDetail)
    {
        if (string.IsNullOrEmpty(procmonDetail)) return AccessClass.Unknown;
        var f = ParseDetail(procmonDetail);
        f.TryGetValue("Desired Access", out var desired);
        f.TryGetValue("Options", out var options);
        desired ??= "";
        options ??= "";

        // Loader fingerprint: Read Data / Generic Read / Execute in access OR
        // Non-Directory File + Synchronous IO Non-Alert in options (the loader's
        // canonical image-map CreateFile shape).
        var hasReadData =
            desired.Contains("Read Data", StringComparison.OrdinalIgnoreCase) ||
            desired.Contains("Generic Read", StringComparison.OrdinalIgnoreCase) ||
            desired.Contains("Execute", StringComparison.OrdinalIgnoreCase);
        var hasLoadOptions =
            options.Contains("Non-Directory File", StringComparison.OrdinalIgnoreCase) &&
            options.Contains("Synchronous IO Non-Alert", StringComparison.OrdinalIgnoreCase);
        if (hasReadData || hasLoadOptions) return AccessClass.LoaderLike;

        // Probe fingerprint: Open Reparse Point in options without any loader signal.
        // This is the GetFileAttributes / PathFileExists / FindFirstFile shape.
        if (options.Contains("Open Reparse Point", StringComparison.OrdinalIgnoreCase))
            return AccessClass.MetadataProbe;

        return AccessClass.Unknown;
    }

    // ── ETW CreateOptions classification ─────────────────────────────────────

    /// <summary>
    /// Classify a kernel FileIO/Create event using only the CreateOptions DWORD.
    /// ETW does not expose Desired Access (that lives on the IRP, which only a
    /// minifilter like ProcMon can read). The reparse-point flag is the most
    /// reliable proxy for the metadata-probe class.
    /// </summary>
    public static AccessClass Classify(uint createOptions)
    {
        var hasNonDir = (createOptions & FILE_NON_DIRECTORY_FILE) != 0;
        var hasSyncIo = (createOptions & FILE_SYNCHRONOUS_IO_NONALERT) != 0;
        var hasReparse = (createOptions & FILE_OPEN_REPARSE_POINT) != 0;

        // Loader-style image-map open: NonDir + SyncIO and no reparse-point flag.
        if (hasNonDir && hasSyncIo && !hasReparse) return AccessClass.LoaderLike;

        // Pure probe: reparse-point flag alone (or with no load-ish flags).
        if (hasReparse && !hasNonDir && !hasSyncIo) return AccessClass.MetadataProbe;

        // CreateOptions==0 is "default open" — most kernel-mode opens look like
        // this when no flags were specified. Without more signal we cannot tell;
        // treat as Unknown so downstream defaults to LoaderLike (conservative).
        return AccessClass.Unknown;
    }

    // ── UI labels ────────────────────────────────────────────────────────────

    /// <summary>
    /// Long, ProcMon-faithful label for grid cells. Mirrors the canonical value that
    /// ProcMon shows in the <c>Options:</c> field of its Detail string so an operator
    /// glancing between the grid and a ProcMon export reads the same nomenclature.
    /// Forwards to <see cref="AccessClassLabels"/> so all surfaces share one vocabulary.
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
