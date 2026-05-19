namespace DllSidecar.Core.Models;

/// <summary>
/// Whether a CreateFile event is the loader actually attempting to map a DLL, or just
/// the application probing file metadata. Distinguishes ground-truth sideload signals
/// from app-internal PATH enumeration (which-style scans), which look identical at
/// path level but never trigger code execution.
/// </summary>
public enum AccessClass
{
    /// <summary>
    /// Detail / CreateOptions not available, or pattern does not match either tier.
    /// Treated as LoaderLike for safety so we never silently drop real loads.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// CreateFile shaped like the OS loader's image-map open: Read Data / Generic Read
    /// / Execute in Desired Access, or Synchronous IO Non-Alert + Non-Directory File in
    /// Options. Real load attempt — a planted DLL here gets executed.
    /// </summary>
    LoaderLike = 1,

    /// <summary>
    /// Metadata-only probe (GetFileAttributes / PathFileExists / FindFirstFile):
    /// Desired Access = Read Attributes only, Options carries Open Reparse Point.
    /// The app is checking whether the file exists; a planted DLL is NOT executed.
    /// </summary>
    MetadataProbe = 2,
}

/// <summary>
/// Single source of truth for the user-facing labels mirroring ProcMon's <c>Options:</c>
/// field values. Used by every UI surface that displays access classification — keeps
/// the vocabulary identical across ProcMon page, Runtime trace page and the wizard.
/// </summary>
public static class AccessClassLabels
{
    // Canonical NT kernel constants from wdm.h — single, unambiguous identifier
    // shared across every grid, export and tooltip. No invented vocabulary.
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
