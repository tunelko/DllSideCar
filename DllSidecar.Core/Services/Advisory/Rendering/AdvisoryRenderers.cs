namespace DllSidecar.Core.Services.Advisory.Rendering;

/// <summary>
/// Flat registry of every template available in the app. AdvisoryPage's dropdown is
/// populated from <see cref="All"/>; the library uses <see cref="ById"/> to look up
/// the renderer when materializing a saved artifact.
///
/// Order matters — <see cref="All"/> drives the dropdown order. Put the most common
/// target first.
/// </summary>
public static class AdvisoryRenderers
{
    public static IReadOnlyList<IAdvisoryRenderer> All { get; } = new IAdvisoryRenderer[]
    {
        new MarkdownRenderer(),
        new GhsaRenderer(),
    };

    public static IAdvisoryRenderer? ById(string id) =>
        All.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));
}
