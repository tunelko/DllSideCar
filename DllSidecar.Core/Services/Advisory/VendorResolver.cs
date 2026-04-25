using System.IO;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services.Advisory;

/// <summary>
/// Shared heuristic for resolving a vendor name from a PE's version info. Prefers the
/// explicit CompanyName over parsing ProductName — CompanyName is what signed binaries
/// put there ("Blizzard Entertainment, Inc.", "Mobatek", "Microsoft Corporation"), while
/// ProductName can be anything ("Battle.net Update Agent"). Strips common legal suffixes
/// so "Blizzard Entertainment, Inc." and "Blizzard Entertainment" cluster together in
/// the Library tree.
/// </summary>
public static class VendorResolver
{
    public static string? Extract(PeAnalysis pe)
    {
        if (!string.IsNullOrWhiteSpace(pe.CompanyName))
            return Normalize(pe.CompanyName);
        if (!string.IsNullOrWhiteSpace(pe.ProductName))
        {
            var first = pe.ProductName.Split(new[] { ' ', '_', '-' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            return first is null ? null : Normalize(first);
        }
        return null;
    }

    /// <summary>
    /// Best-effort vendor lookup from a file path. Priority:
    ///   1. Authenticode certificate Subject CN (most authoritative — cryptographically bound to publisher identity)
    ///   2. PE version info CompanyName (self-reported, unsigned-file fallback)
    ///   3. PE version info ProductName first token (last resort)
    /// Returns null when the file is unreachable or has no usable signal. Always safe.
    /// </summary>
    public static string? ResolveFromFile(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return null;

        try
        {
            var signing = AuthenticodeVerifier.Verify(filePath);
            if (!string.IsNullOrWhiteSpace(signing.SubjectCommonName))
                return Normalize(signing.SubjectCommonName!);
        }
        catch
        {
            // Authenticode path may throw on weird/corrupt PE files — fall through to version info.
        }

        try
        {
            var pe = PeAnalyzer.Analyze(filePath);
            return Extract(pe);
        }
        catch
        {
            return null;
        }
    }

    public static string Normalize(string raw)
    {
        var v = raw.Trim();
        string[] suffixes = { ", Inc.", ", Inc", " Inc.", " Inc", ", LLC", " LLC", ", Ltd.", " Ltd.", " Ltd",
                              ", Corp.", " Corp.", " Corp", ", GmbH", " GmbH", " S.A.", " S.L.", " B.V." };
        foreach (var s in suffixes)
        {
            if (v.EndsWith(s, StringComparison.OrdinalIgnoreCase))
            {
                v = v.Substring(0, v.Length - s.Length).TrimEnd(',').Trim();
                break;
            }
        }
        return v;
    }
}
