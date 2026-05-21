using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Decide whether a target process is sandboxed enough that a sideloaded DLL's
/// payload needs <see cref="Models.PayloadType.SandboxEscape"/> to land a visible cmd on
/// WinSta0\\Default. Static lookup by filename + PE ProductName covers the high-value
/// research targets (Adobe Acrobat / Reader, Microsoft Edge WebView2, UWP hosts).
/// Dynamic signals captured in EtwDllTracer (TokenIsAppContainer / IntegrityLevel)
/// win when they're present — they trump the heuristic on disagreement.
/// </summary>
public static class SandboxClassifier
{
    // Filename match (case-insensitive, exact match on the basename — no substring
    // games). Every entry here is a binary we've seen run with AppContainer or
    // renderer restrictions in real findings or in the Chromium / Office stack.
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

    // ProductName substrings (case-insensitive). Matches anywhere in the PE's
    // VersionInfo ProductName. CEF subprocesses ship with this string verbatim.
    private static readonly string[] SandboxedProductMarkers =
    {
        "Chromium Embedded Framework",
        "Microsoft Edge WebView2",
    };

    /// <summary>Static classification from a PE on disk. Returns None when nothing
    /// in the PE indicates a sandbox — caller should still consult dynamic signals
    /// (token IL / AppContainer) if a live trace is available.</summary>
    public static SandboxKind Classify(string? exePath)
    {
        if (string.IsNullOrEmpty(exePath)) return SandboxKind.None;
        var basename = Path.GetFileName(exePath);
        if (string.IsNullOrEmpty(basename)) return SandboxKind.None;

        if (SandboxedBasenames.Contains(basename))
        {
            // Filename alone is reliable for these — they only exist as renderer
            // subprocesses or AppContainer hosts.
            return basename.Equals("WWAHost.exe", StringComparison.OrdinalIgnoreCase)
                || basename.Equals("ApplicationFrameHost.exe", StringComparison.OrdinalIgnoreCase)
                || basename.Equals("RuntimeBroker.exe", StringComparison.OrdinalIgnoreCase)
                ? SandboxKind.AppContainer
                : SandboxKind.RendererSubprocess;
        }

        // Fall back to ProductName from PE VersionInfo. Skip if we can't read the
        // PE (file missing, locked, malformed) — that path means we can't tell.
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

    /// <summary>Dynamic classification using token info captured during ETW trace.
    /// Both flags are populated by <c>EtwDllTracer.CaptureTokenInfo</c> when a
    /// process is first detected. Returns None when no token info is present.</summary>
    public static SandboxKind FromTokenInfo(bool isAppContainer, IntegrityLevel level)
    {
        if (isAppContainer) return SandboxKind.AppContainer;
        if (level == IntegrityLevel.Low || level == IntegrityLevel.Untrusted)
            return SandboxKind.LowIntegrity;
        return SandboxKind.None;
    }

    /// <summary>Combine static + dynamic. Dynamic wins on disagreement — a live
    /// AppContainer token is ground truth; a filename heuristic is just a guess.</summary>
    public static SandboxKind Combine(SandboxKind staticKind, SandboxKind dynamicKind)
    {
        if (dynamicKind != SandboxKind.None) return dynamicKind;
        return staticKind;
    }

    /// <summary>True when SandboxEscape is the right payload — anything other than
    /// None. Surface this to the Payload picker so the operator sees it only when
    /// it adds something the WinExec / reverse-shell payloads can't deliver.</summary>
    public static bool RecommendsSandboxEscape(SandboxKind kind) => kind != SandboxKind.None;
}
