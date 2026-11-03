using System.Text;
using DllSidecar.Core.Models;
using DllSidecar.Core.Services;
using DllSidecar.Core.Services.Community;

namespace DllSidecar.Core.Tests.Services;

public class CommunityEvidenceTests
{
    private static HijackLibsCatalog Catalog() => HijackLibsCatalog.Parse(Encoding.UTF8.GetBytes("""
        [{"Name":"sample.dll","Vendor":"Vendor","url":"https://hijacklibs.net/entries/sample.html",
          "VulnerableExecutables":[{"Path":"%PROGRAMFILES%\\Vendor\\app.exe","Type":"Sideloading"}]}]
        """), DateTime.UtcNow);

    [Fact]
    public void NameOnlyAndPairMatchesRemainDistinctWithoutChangingScores()
    {
        var catalog = Catalog();
        Assert.Equal(CommunityMatch.DllName, Assert.Single(catalog.Match("SAMPLE.dll", [])).Match);
        var importer = new ImporterRef { ExePath = @"C:\Vendor\app.exe", ExeFilename = "APP.exe", ResolutionKind = ImportResolutionKind.ResolvedLocal };
        var pair = Assert.Single(catalog.Match("sample.dll", [importer]));
        Assert.Equal(CommunityMatch.ExeDllNames, pair.Match);
        Assert.Equal(64, pair.DatasetSha256.Length);
        var candidate = new PhantomCandidate { DllName = "sample.dll", DirectoryPath = @"C:\Vendor", Importers = [importer] };
        candidate.Score = ExploitabilityScorer.ScorePhantom(candidate);
        var total = candidate.Score.Total;
        catalog.Enrich(new ScanResults { Phantoms = [candidate] });
        Assert.Equal(total, candidate.Score.Total);
        importer.ResolutionKind = ImportResolutionKind.Ambiguous;
        Assert.Equal(CommunityMatch.DllName, Assert.Single(catalog.Match("sample.dll", [importer])).Match);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("[{\"Name\":\"x.dll\",\"url\":\"file:///C:/secrets\"}]")]
    public void InvalidOrUntrustedDatasetIsRejected(string json) =>
        Assert.ThrowsAny<Exception>(() => HijackLibsCatalog.Parse(Encoding.UTF8.GetBytes(json), DateTime.UtcNow));
}
