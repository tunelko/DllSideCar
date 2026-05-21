namespace DllSidecar.Core.Models;

/// <summary>
/// Verdict from <see cref="DllSidecar.Core.Services.SandboxClassifier"/>. Drives whether
/// the SandboxEscape payload variant is recommended (and shown) for a given target.
/// </summary>
public enum SandboxKind
{
    /// <summary>Host runs at Medium+ IL, no AppContainer, no renderer flag. WinExec from
    /// DLL_PROCESS_ATTACH lands on the user's interactive desktop — SandboxEscape is
    /// dead weight here.</summary>
    None,

    /// <summary>Token has TokenIsAppContainer = true (UWP/WWA host). Spawned processes
    /// inherit the AppContainer and CreateProcessA usually fails outright. Needs
    /// cross-process injection into a non-AppContainer sibling to land cmd on
    /// WinSta0\\Default.</summary>
    AppContainer,

    /// <summary>Token integrity level is Low (S-1-16-4096) or Untrusted. Common for
    /// browser/Office content processes. Same problem as AppContainer for visible
    /// PoCs.</summary>
    LowIntegrity,

    /// <summary>Chromium Embedded Framework subprocess — Acrobat's AcroCEF/RdrCEF,
    /// msedgewebview2.exe, chrome.exe/msedge.exe launched with --type=renderer.
    /// Even when the token IL itself is medium, the sandbox restrictions block
    /// direct cmd spawn on the desktop.</summary>
    RendererSubprocess,
}
