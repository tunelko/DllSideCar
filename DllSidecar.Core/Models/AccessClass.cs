namespace DllSidecar.Core.Models;

/// <summary>Loader image-map open vs metadata-only probe classification for CreateFile events.</summary>
public enum AccessClass
{
    /// <summary>Detail unavailable; treated as LoaderLike downstream.</summary>
    Unknown = 0,

    /// <summary>CreateFile shaped like the OS loader's image-map open. Planted DLL gets executed.</summary>
    LoaderLike = 1,

    /// <summary>Metadata-only probe (GetFileAttributes / PathFileExists / FindFirstFile). Planted DLL is NOT executed.</summary>
    MetadataProbe = 2,
}

/// <summary>User-facing labels mirroring ProcMon's <c>Options:</c> field values.</summary>
public static class AccessClassLabels
{
    // Canonical NT kernel constants from wdm.h.
    public const string Load  = "FILE_NON_DIRECTORY_FILE";
    public const string Probe = "FILE_OPEN_REPARSE_POINT";
    public const string Mixed = "MIXED";

    /// <summary>Compute the label from the two counts. Empty when neither side has hits.</summary>
    public static string FromCounts(int loadCount, int probeCount)
    {
        if (loadCount > 0 && probeCount > 0) return Mixed;
        if (loadCount > 0)                   return Load;
        if (probeCount > 0)                  return Probe;
        return "";
    }
}
