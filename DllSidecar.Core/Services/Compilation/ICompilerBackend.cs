using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services.Compilation;

public sealed record DllBuildRequest(string SourceFile, string DefFile, string OutputFile, string Arch,
    IEnumerable<string>? IncludeDirs = null, IEnumerable<string>? ExtraObjects = null,
    IEnumerable<string>? ExtraLibs = null, IProgress<string>? Progress = null);

public interface ICompilerBackend
{
    CompilerKind Kind { get; }
    Task<BuildResult> CompileAsync(DllBuildRequest request);
}

public sealed class MingwBackend : ICompilerBackend
{
    public CompilerKind Kind => CompilerKind.MinGW;
    public Task<BuildResult> CompileAsync(DllBuildRequest r) => BuildSystem.CompileMingwAsync(
        r.SourceFile, r.DefFile, r.OutputFile, r.Arch, r.IncludeDirs, r.ExtraObjects, r.ExtraLibs, r.Progress);
}
