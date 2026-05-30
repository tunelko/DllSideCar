namespace DllSidecar.Core.Models;

/// <summary>SandboxClassifier verdict; gates the SandboxEscape payload variant.</summary>
public enum SandboxKind
{
    /// <summary>Medium+ IL, no AppContainer. WinExec lands on the user's desktop.</summary>
    None,

    /// <summary>Token has TokenIsAppContainer = true (UWP/WWA host).</summary>
    AppContainer,

    /// <summary>Token integrity level is Low (S-1-16-4096) or Untrusted.</summary>
    LowIntegrity,

    /// <summary>Chromium Embedded Framework subprocess (AcroCEF/RdrCEF, msedgewebview2, --type=renderer).</summary>
    RendererSubprocess,
}
