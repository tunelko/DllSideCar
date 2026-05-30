using System.IO;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services.Advisory;

/// <summary>
/// Resolve a vendor name from PE version info; CompanyName preferred, then ProductName first token. Legal suffixes stripped.
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
    /// Vendor lookup from a file path: Authenticode Subject CN -> CompanyName -> ProductName first token.
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
        catch { /* fall through to version info */ }

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
