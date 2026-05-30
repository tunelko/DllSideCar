using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Cve;

namespace DllSidecar.Core.Services.Cve;

/// <summary>
/// Cache-first NVD CVE dedup; ranks matches by confidence.
/// </summary>
public static class CveDedupService
{
    /// <summary>
    /// Query NVD with "{vendor} {product} dll hijacking" + optional "sideloading" fallback; dedup and score.
    /// </summary>
    public static async Task<CveQueryResult> QueryAsync(PeAnalysis pe, CancellationToken ct = default)
    {
        var vendor = NormalizeVendor(pe);
        var product = NormalizeProduct(pe);
        var filename = pe.Filename;

        if (string.IsNullOrWhiteSpace(vendor) && string.IsNullOrWhiteSpace(product))
        {
            return new CveQueryResult
            {
                Error = "No vendor/product metadata in PE — cannot query NVD reliably. " +
                        "Try a PE with version resources.",
            };
        }

        var primary = BuildQuery(vendor, product, "dll hijacking");
        var alternate = BuildQuery(vendor, product, "dll sideloading");

        var combined = new CveQueryResult { Query = primary };

        // Primary query
        var r1 = CveCache.TryGet(primary) ?? await FetchAndCache(primary, ct);
        Merge(combined, r1);

        // Alternate if primary gave us little
        if (r1.Matches.Count < 5 && alternate != primary)
        {
            var r2 = CveCache.TryGet(alternate) ?? await FetchAndCache(alternate, ct);
            Merge(combined, r2);
        }

        // Score every match against this specific PE
        foreach (var m in combined.Matches)
            ScoreMatch(m, vendor, product, filename);

        // Rank: Exact → Likely → Related → Unrelated, then newest first within each
        combined.Matches = combined.Matches
            .OrderByDescending(m => (int)m.Confidence)
            .ThenByDescending(m => m.PublishedDate ?? DateTime.MinValue)
            .ToList();

        Log.Info("cve.dedup",
            $"Query for {vendor}/{product}/{filename}: " +
            $"{combined.ExactCount} exact, {combined.LikelyCount} likely, {combined.Matches.Count} total");

        return combined;
    }

    private static async Task<CveQueryResult> FetchAndCache(string query, CancellationToken ct)
    {
        using var client = new NvdClient();
        var r = await client.SearchAsync(query, resultsPerPage: 50, ct);
        if (string.IsNullOrEmpty(r.Error))
            CveCache.Save(query, r);
        return r;
    }

    private static void Merge(CveQueryResult dest, CveQueryResult src)
    {
        if (!string.IsNullOrEmpty(src.Error) && string.IsNullOrEmpty(dest.Error))
            dest.Error = src.Error;
        dest.TotalFromApi = Math.Max(dest.TotalFromApi, src.TotalFromApi);

        var seen = new HashSet<string>(dest.Matches.Select(m => m.CveId), StringComparer.OrdinalIgnoreCase);
        foreach (var m in src.Matches)
            if (seen.Add(m.CveId)) dest.Matches.Add(m);
    }

    /// <summary>Score a match by how closely it relates to the target PE.</summary>
    private static void ScoreMatch(CveMatch m, string vendor, string product, string filename)
    {
        var desc = m.Description.ToLowerInvariant();
        var fnameLower = filename.ToLowerInvariant();
        var fnameStem = Path.GetFileNameWithoutExtension(filename).ToLowerInvariant();
        var vendorLower = vendor.ToLowerInvariant();
        var productLower = product.ToLowerInvariant();

        bool filenameMention = !string.IsNullOrEmpty(fnameLower) &&
            (desc.Contains(fnameLower) ||
             (fnameStem.Length >= 4 && desc.Contains(fnameStem)));
        bool vendorMention = !string.IsNullOrEmpty(vendorLower) && desc.Contains(vendorLower);
        bool productMention = !string.IsNullOrEmpty(productLower) && desc.Contains(productLower);
        bool cweMatch = m.Cwes.Any(c => c is "CWE-427" or "CWE-426" or "CWE-114");
        bool sideloadingKw = desc.Contains("dll hijack") || desc.Contains("dll sideload") ||
                             desc.Contains("dll planting") || desc.Contains("dll search order");

        var reasons = m.MatchReasons;
        if (filenameMention) reasons.Add($"description mentions '{fnameLower}'");
        if (vendorMention)   reasons.Add($"vendor '{vendorLower}' mentioned");
        if (productMention)  reasons.Add($"product '{productLower}' mentioned");
        if (cweMatch)        reasons.Add($"CWE match: {string.Join(", ", m.Cwes.Intersect(new[] { "CWE-427", "CWE-426", "CWE-114" }))}");
        if (sideloadingKw)   reasons.Add("sideloading keyword in description");

        // Scoring ladder
        if (filenameMention && (vendorMention || productMention))
            m.Confidence = MatchConfidence.Exact;
        else if ((vendorMention || productMention) && (cweMatch || sideloadingKw))
            m.Confidence = MatchConfidence.Likely;
        else if (cweMatch || sideloadingKw)
            m.Confidence = MatchConfidence.Related;
        else
            m.Confidence = MatchConfidence.Unrelated;
    }

    private static string BuildQuery(string vendor, string product, string extra)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(vendor)) parts.Add(vendor);
        if (!string.IsNullOrWhiteSpace(product)) parts.Add(product);
        if (!string.IsNullOrWhiteSpace(extra)) parts.Add(extra);
        return string.Join(" ", parts);
    }

    /// <summary>
    /// Reduce to a first-word vendor token (e.g. "Adobe Inc." -> "adobe").
    /// </summary>
    private static string NormalizeVendor(PeAnalysis pe)
    {
        var raw = pe.ProductName;
        if (string.IsNullOrWhiteSpace(raw)) return "";
        var firstWord = raw.Split(new[] { ' ', '_', '-' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
        return firstWord.Trim().Trim('"');
    }

    private static string NormalizeProduct(PeAnalysis pe)
    {
        if (!string.IsNullOrWhiteSpace(pe.ProductName))
            return pe.ProductName.Trim();
        // Fallback to the file's original name sans extension
        var of = pe.OriginalFilename;
        if (!string.IsNullOrWhiteSpace(of))
            return Path.GetFileNameWithoutExtension(of);
        return Path.GetFileNameWithoutExtension(pe.Filename);
    }
}
