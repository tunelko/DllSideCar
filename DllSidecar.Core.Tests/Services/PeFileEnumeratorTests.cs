using DllSidecar.Core.Services;

namespace DllSidecar.Core.Tests.Services;

public class PeFileEnumeratorTests
{
    [Fact]
    public void Enumerate_ContinuesWithSiblingAfterAccessDenied()
    {
        var access = new FakeDirectoryTreeAccess()
            .WithDirectories("root", "root\\blocked", "root\\good")
            .WithFiles("root")
            .WithFileFailure("root\\blocked", new UnauthorizedAccessException("denied"))
            .WithDirectories("root\\blocked")
            .WithFiles("root\\good", "root\\good\\candidate.DLL")
            .WithDirectories("root\\good");
        var failures = new List<DirectoryEnumerationFailure>();

        var result = PeFileEnumerator.Enumerate("root", access, CancellationToken.None, failures.Add);

        Assert.Equal(["root\\good\\candidate.DLL"], result);
        var failure = Assert.Single(failures);
        Assert.Equal("root\\blocked", failure.Path);
        Assert.Equal(DirectoryEnumerationOperation.Files, failure.Operation);
    }

    [Fact]
    public void Enumerate_StillVisitsChildrenWhenParentFileEnumerationFails()
    {
        var access = new FakeDirectoryTreeAccess()
            .WithFileFailure("root", new IOException("directory changed"))
            .WithDirectories("root", "root\\child")
            .WithFiles("root\\child", "root\\child\\service.exe")
            .WithDirectories("root\\child");

        var result = PeFileEnumerator.Enumerate("root", access, CancellationToken.None);

        Assert.Equal(["root\\child\\service.exe"], result);
    }

    [Fact]
    public void Enumerate_PreservesFilesYieldedBeforeDeferredFailure()
    {
        var access = new FakeDirectoryTreeAccess()
            .WithDeferredFileFailure("root", "root\\first.sys", new IOException("mid-enumeration"))
            .WithDirectories("root");
        var failures = new List<DirectoryEnumerationFailure>();

        var result = PeFileEnumerator.Enumerate("root", access, CancellationToken.None, failures.Add);

        Assert.Equal(["root\\first.sys"], result);
        Assert.Single(failures);
    }

    [Fact]
    public void Enumerate_SkipsReparsePointDirectories()
    {
        var access = new FakeDirectoryTreeAccess()
            .WithDirectories("root", "root\\junction", "root\\normal")
            .WithAttributes("root\\junction", FileAttributes.Directory | FileAttributes.ReparsePoint)
            .WithFiles("root")
            .WithFiles("root\\normal", "root\\normal\\plugin.ocx")
            .WithDirectories("root\\normal");

        var result = PeFileEnumerator.Enumerate("root", access, CancellationToken.None);

        Assert.Equal(["root\\normal\\plugin.ocx"], result);
        Assert.DoesNotContain("root\\junction", access.VisitedFileDirectories);
    }

    [Fact]
    public void Enumerate_FiltersExtensionsCaseInsensitively()
    {
        var access = new FakeDirectoryTreeAccess()
            .WithFiles("root",
                "root\\a.dll",
                "root\\b.EXE",
                "root\\c.Sys",
                "root\\d.oCx",
                "root\\control.CPL",
                "root\\notes.txt",
                "root\\no-extension")
            .WithDirectories("root");

        var result = PeFileEnumerator.Enumerate("root", access, CancellationToken.None);

        Assert.Equal(5, result.Count);
        Assert.DoesNotContain(result, path => path.EndsWith(".txt", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Enumerate_PropagatesCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Throws<OperationCanceledException>(() =>
            PeFileEnumerator.Enumerate("root", new FakeDirectoryTreeAccess(), cts.Token));
    }

    private sealed class FakeDirectoryTreeAccess : IDirectoryTreeAccess
    {
        private readonly Dictionary<string, Func<IEnumerable<string>>> _files =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Func<IEnumerable<string>>> _directories =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, FileAttributes> _attributes =
            new(StringComparer.OrdinalIgnoreCase);

        public List<string> VisitedFileDirectories { get; } = [];

        public FakeDirectoryTreeAccess WithFiles(string directory, params string[] files)
        {
            _files[directory] = () => files;
            return this;
        }

        public FakeDirectoryTreeAccess WithDirectories(string directory, params string[] directories)
        {
            _directories[directory] = () => directories;
            return this;
        }

        public FakeDirectoryTreeAccess WithFileFailure(string directory, Exception exception)
        {
            _files[directory] = () => throw exception;
            return this;
        }

        public FakeDirectoryTreeAccess WithDeferredFileFailure(
            string directory,
            string firstFile,
            Exception exception)
        {
            _files[directory] = () => YieldThenThrow(firstFile, exception);
            return this;
        }

        public FakeDirectoryTreeAccess WithAttributes(string path, FileAttributes attributes)
        {
            _attributes[path] = attributes;
            return this;
        }

        public IEnumerable<string> EnumerateFiles(string directory)
        {
            VisitedFileDirectories.Add(directory);
            return _files.TryGetValue(directory, out var factory) ? factory() : [];
        }

        public IEnumerable<string> EnumerateDirectories(string directory) =>
            _directories.TryGetValue(directory, out var factory) ? factory() : [];

        public FileAttributes GetAttributes(string path) =>
            _attributes.TryGetValue(path, out var attributes) ? attributes : FileAttributes.Directory;

        private static IEnumerable<string> YieldThenThrow(string firstFile, Exception exception)
        {
            yield return firstFile;
            throw exception;
        }
    }
}
