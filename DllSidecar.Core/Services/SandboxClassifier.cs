using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Decide whether a target process is sandboxed enough to require <see cref="Models.PayloadType.SandboxEscape"/>. Dynamic token signals trump static heuristics.
/// </summary>
public static class SandboxClassifier
{
    // Case-insensitive exact-basename match for known sandboxed hosts.
    private static readonly HashSet<string> SandboxedBasenames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Adobe — Acrobat / Reader CEF subprocess + companions
        "AcroCEF.exe",
        "AcroCEFShim.exe",
        "RdrCEF.exe",
        "RdrCEFShim.exe",
        // Microsoft Edge WebView2 runtime — always sandboxed when embedded
        "msedgewebview2.exe",
        // UWP / AppContainer hosts
        "WWAHost.exe",
        "ApplicationFrameHost.exe",
        "RuntimeBroker.exe",
        // Office Click-to-Run sandboxed renderers (WV2-based)
        "ai.exe",       // Office AI host
    };

    // Case-insensitive ProductName substring markers.
    private static readonly string[] SandboxedProductMarkers =
    {
        "Chromium Embedded Framework",
        "Microsoft Edge WebView2",
    };

    /// <summary>Static classification from a PE on disk.</summary>
    public static SandboxKind Classify(string? exePath)
    {
        if (string.IsNullOrEmpty(exePath)) return SandboxKind.None;
        var basename = Path.GetFileName(exePath);
        if (string.IsNullOrEmpty(basename)) return SandboxKind.None;

        if (SandboxedBasenames.Contains(basename))
        {
            return basename.Equals("WWAHost.exe", StringComparison.OrdinalIgnoreCase)
                || basename.Equals("ApplicationFrameHost.exe", StringComparison.OrdinalIgnoreCase)
                || basename.Equals("RuntimeBroker.exe", StringComparison.OrdinalIgnoreCase)
                ? SandboxKind.AppContainer
                : SandboxKind.RendererSubprocess;
        }

        // Fall back to ProductName from PE VersionInfo.
        try
        {
            if (!File.Exists(exePath)) return SandboxKind.None;
            var pe = PeAnalyzer.Analyze(exePath);
            var prod = pe.ProductName ?? "";
            foreach (var marker in SandboxedProductMarkers)
                if (prod.Contains(marker, StringComparison.OrdinalIgnoreCase))
                    return SandboxKind.RendererSubprocess;
        }
        catch { /* unreadable PE — leave as None */ }

        return SandboxKind.None;
    }

    /// <summary>Dynamic classification from token info captured during ETW trace.</summary>
    public static SandboxKind FromTokenInfo(bool isAppContainer, IntegrityLevel level)
    {
        if (isAppContainer) return SandboxKind.AppContainer;
        if (level == IntegrityLevel.Low || level == IntegrityLevel.Untrusted)
            return SandboxKind.LowIntegrity;
        return SandboxKind.None;
    }

    /// <summary>Combine static + dynamic; dynamic wins on disagreement.</summary>
    public static SandboxKind Combine(SandboxKind staticKind, SandboxKind dynamicKind)
    {
        if (dynamicKind != SandboxKind.None) return dynamicKind;
        return staticKind;
    }

    /// <summary>True when SandboxEscape is the appropriate payload.</summary>
    public static bool RecommendsSandboxEscape(SandboxKind kind) => kind != SandboxKind.None;
}
