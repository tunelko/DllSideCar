using System.Net;
using System.Net.Http;
using System.Text.Json;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models.Cve;

namespace DllSidecar.Core.Services.Cve;

/// <summary>
/// Thin HttpClient over the NVD REST API v2. Handles:
///   - HTTPS enforcement (hard-coded host — we never talk to anyone else)
///   - Optional apiKey header (raises rate limit 5/30s → 50/30s)
///   - Backoff on 429 Too Many Requests
///   - 45s per-request timeout (NVD is slow under load, especially
///     without an API key)
///   - Response parsing into our CveMatch model (a flat subset of NVD's JSON)
/// </summary>
public class NvdClient : IDisposable
{
    private const string BaseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    // NVD without an API key throttles to 5 req/30s and individual responses
    // can take 20-30s on cold cache. 15s was too tight and caused frequent
    // user-visible timeouts; 45s is generous enough that a single slow
    // response doesn't kill the search but short enough to bail on a
    // genuinely unreachable endpoint.
    private const int TimeoutSeconds = 45;

    private readonly HttpClient _http;

    public NvdClient()
    {
        _http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(TimeoutSeconds),
        };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("DllSidecar-Research/1.0 (+https://blogs.tunelko.com)");

        var key = ConfigManager.Current.Tools.NvdApiKey;
        if (!string.IsNullOrWhiteSpace(key))
            _http.DefaultRequestHeaders.Add("apiKey", key.Trim());
    }

    /// <summary>
    /// Raw keyword search. Returns up to resultsPerPage matches. CveDedupService drives
    /// the scoring — this method just fetches and parses.
    /// </summary>
    public async Task<CveQueryResult> SearchAsync(string keywords, int resultsPerPage = 50, CancellationToken ct = default)
    {
        var result = new CveQueryResult { Query = keywords };

        if (string.IsNullOrWhiteSpace(keywords))
        {
            result.Error = "empty query";
            return result;
        }

        // Build URL. NVD wants URL-encoded keywordSearch.
        var url = $"{BaseUrl}?keywordSearch={Uri.EscapeDataString(keywords)}" +
                  $"&resultsPerPage={resultsPerPage}";

        try
        {
            using var resp = await SendWithBackoffAsync(url, ct);
            if (!resp.IsSuccessStatusCode)
            {
                result.Error = $"HTTP {(int)resp.StatusCode}: {resp.ReasonPhrase}";
                Log.Warn("cve.nvd", $"Query failed — {result.Error} — url={url}");
                return result;
            }

            var body = await resp.Content.ReadAsStringAsync(ct);
            ParseInto(body, result);
            Log.Info("cve.nvd", $"NVD returned {result.Matches.Count} results (total {result.TotalFromApi}) for '{keywords}'");
        }
        catch (TaskCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (TaskCanceledException)
        {
            // Hint about API key when the user is hitting timeouts — NVD
            // without one is throttled and noticeably slower under load.
            var keyHint = string.IsNullOrWhiteSpace(ConfigManager.Current.Tools.NvdApiKey)
                ? " (no NVD API key configured — Config → Tools → NVD API Key for higher rate limits)"
                : "";
            result.Error = $"Timeout after {TimeoutSeconds}s{keyHint}";
            Log.Warn("cve.nvd", $"Timeout querying NVD for '{keywords}'");
        }
        catch (HttpRequestException ex)
        {
            result.Error = $"HTTP error: {ex.Message}";
            Log.Warn("cve.nvd", $"HTTP error", ex);
        }
        catch (JsonException ex)
        {
            result.Error = $"Response parse failed: {ex.Message}";
            Log.Warn("cve.nvd", $"JSON parse failed", ex);
        }
        return result;
    }

    /// <summary>Send with exponential backoff on 429 (rate-limited). Max 3 retries.</summary>
    private async Task<HttpResponseMessage> SendWithBackoffAsync(string url, CancellationToken ct)
    {
        int delayMs = 2000;
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            var resp = await _http.GetAsync(url, ct);
            if (resp.StatusCode != HttpStatusCode.TooManyRequests) return resp;

            Log.Warn("cve.nvd", $"NVD rate-limited (429). Attempt {attempt}/3, backing off {delayMs}ms");
            resp.Dispose();
            await Task.Delay(delayMs, ct);
            delayMs *= 2;
        }
        // Last attempt, let the caller see the 429
        return await _http.GetAsync(url, ct);
    }

    private static void ParseInto(string json, CveQueryResult result)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("totalResults", out var total))
            result.TotalFromApi = total.GetInt32();

        if (!root.TryGetProperty("vulnerabilities", out var vulns)) return;

        foreach (var v in vulns.EnumerateArray())
        {
            if (!v.TryGetProperty("cve", out var cve)) continue;
            var match = new CveMatch
            {
                CveId = cve.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "",
                Description = FirstEnglishDescription(cve),
            };
            if (string.IsNullOrEmpty(match.CveId)) continue;

            if (cve.TryGetProperty("published", out var pub) &&
                DateTime.TryParse(pub.GetString(), out var pubDt))
                match.PublishedDate = pubDt;
            if (cve.TryGetProperty("lastModified", out var mod) &&
                DateTime.TryParse(mod.GetString(), out var modDt))
                match.LastModifiedDate = modDt;

            // CVSS v3.1 preferred, fallback to v3.0 then v2
            TryParseCvss(cve, match);

            // CWEs
            if (cve.TryGetProperty("weaknesses", out var weaknesses))
            {
                foreach (var w in weaknesses.EnumerateArray())
                {
                    if (!w.TryGetProperty("description", out var descs)) continue;
                    foreach (var d in descs.EnumerateArray())
                    {
                        var value = d.TryGetProperty("value", out var v2) ? v2.GetString() : null;
                        if (!string.IsNullOrEmpty(value) && value.StartsWith("CWE-") && !match.Cwes.Contains(value))
                            match.Cwes.Add(value);
                    }
                }
            }

            // References
            if (cve.TryGetProperty("references", out var refs))
            {
                foreach (var r in refs.EnumerateArray())
                {
                    var u = r.TryGetProperty("url", out var urlEl) ? urlEl.GetString() : null;
                    if (!string.IsNullOrEmpty(u)) match.References.Add(u);
                }
            }

            // CPE vendor/product — take first parseable CPE from configurations
            if (cve.TryGetProperty("configurations", out var configs))
            {
                foreach (var cfg in configs.EnumerateArray())
                {
                    if (!cfg.TryGetProperty("nodes", out var nodes)) continue;
                    foreach (var node in nodes.EnumerateArray())
                    {
                        if (!node.TryGetProperty("cpeMatch", out var cpeMatches)) continue;
                        foreach (var cpe in cpeMatches.EnumerateArray())
                        {
                            if (!cpe.TryGetProperty("criteria", out var crit)) continue;
                            var crt = crit.GetString();
                            if (string.IsNullOrEmpty(crt)) continue;
                            var parts = crt.Split(':');
                            if (parts.Length >= 5)
                            {
                                match.Vendor ??= parts[3];
                                match.Product ??= parts[4];
                            }
                        }
                        if (match.Vendor != null) break;
                    }
                    if (match.Vendor != null) break;
                }
            }

            result.Matches.Add(match);
        }
    }

    private static string FirstEnglishDescription(JsonElement cve)
    {
        if (!cve.TryGetProperty("descriptions", out var descs)) return "";
        foreach (var d in descs.EnumerateArray())
        {
            var lang = d.TryGetProperty("lang", out var l) ? l.GetString() : null;
            if (lang == "en" && d.TryGetProperty("value", out var v))
                return v.GetString() ?? "";
        }
        // Fallback: first available
        foreach (var d in descs.EnumerateArray())
            if (d.TryGetProperty("value", out var v))
                return v.GetString() ?? "";
        return "";
    }

    private static void TryParseCvss(JsonElement cve, CveMatch match)
    {
        if (!cve.TryGetProperty("metrics", out var metrics)) return;
        foreach (var keyName in new[] { "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
        {
            if (!metrics.TryGetProperty(keyName, out var list)) continue;
            foreach (var entry in list.EnumerateArray())
            {
                if (!entry.TryGetProperty("cvssData", out var data)) continue;
                if (data.TryGetProperty("baseScore", out var score))
                    match.CvssScore = score.GetDouble();
                if (data.TryGetProperty("baseSeverity", out var sev))
                    match.CvssSeverity = sev.GetString();
                if (data.TryGetProperty("vectorString", out var vec))
                    match.CvssVector = vec.GetString();
                return; // first one wins
            }
        }
    }

    public void Dispose() => _http.Dispose();
}
