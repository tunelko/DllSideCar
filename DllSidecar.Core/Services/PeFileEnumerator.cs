using System.Security;

namespace DllSidecar.Core.Services;

internal enum DirectoryEnumerationOperation
{
    Files,
    Subdirectories,
    Attributes,
}

internal sealed record DirectoryEnumerationFailure(
    string Path,
    DirectoryEnumerationOperation Operation,
    Exception Exception);

internal interface IDirectoryTreeAccess
{
    IEnumerable<string> EnumerateFiles(string directory);
    IEnumerable<string> EnumerateDirectories(string directory);
    FileAttributes GetAttributes(string path);
}

internal sealed class PhysicalDirectoryTreeAccess : IDirectoryTreeAccess
{
    public IEnumerable<string> EnumerateFiles(string directory) =>
        Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly);

    public IEnumerable<string> EnumerateDirectories(string directory) =>
        Directory.EnumerateDirectories(directory, "*", SearchOption.TopDirectoryOnly);

    public FileAttributes GetAttributes(string path) => File.GetAttributes(path);
}

internal static class PeFileEnumerator
{
    private static readonly HashSet<string> PeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".dll",
        ".exe",
        ".sys",
        ".ocx",
        ".cpl",
    };

    public static List<string> Enumerate(
        string root,
        CancellationToken ct,
        Action<DirectoryEnumerationFailure>? onFailure = null) =>
        Enumerate(root, new PhysicalDirectoryTreeAccess(), ct, onFailure);

    internal static List<string> Enumerate(
        string root,
        IDirectoryTreeAccess access,
        CancellationToken ct,
        Action<DirectoryEnumerationFailure>? onFailure = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        ArgumentNullException.ThrowIfNull(access);

        var files = new List<string>();
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.TryPop(out var directory))
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                foreach (var file in access.EnumerateFiles(directory))
                {
                    ct.ThrowIfCancellationRequested();
                    if (PeExtensions.Contains(Path.GetExtension(file)))
                        files.Add(file);
                }
            }
            catch (Exception ex) when (IsRecoverable(ex))
            {
                onFailure?.Invoke(new DirectoryEnumerationFailure(
                    directory, DirectoryEnumerationOperation.Files, ex));
            }

            try
            {
                foreach (var child in access.EnumerateDirectories(directory))
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        // Following a junction can leave the requested root or create cycles.
                        if ((access.GetAttributes(child) & FileAttributes.ReparsePoint) == 0)
                            pending.Push(child);
                    }
                    catch (Exception ex) when (IsRecoverable(ex))
                    {
                        onFailure?.Invoke(new DirectoryEnumerationFailure(
                            child, DirectoryEnumerationOperation.Attributes, ex));
                    }
                }
            }
            catch (Exception ex) when (IsRecoverable(ex))
            {
                onFailure?.Invoke(new DirectoryEnumerationFailure(
                    directory, DirectoryEnumerationOperation.Subdirectories, ex));
            }
        }

        return files;
    }

    private static bool IsRecoverable(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or SecurityException;
}
