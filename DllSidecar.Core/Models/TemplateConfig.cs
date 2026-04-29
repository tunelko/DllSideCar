namespace DllSidecar.Core.Models;

public class TemplateConfig
{
    public bool DInvoke { get; set; }
    public bool EncryptStrings { get; set; }
    public bool DirectSyscalls { get; set; }
    public int DelayMs { get; set; }
    public PayloadType Payload { get; set; } = PayloadType.MessageBox;
    public string PayloadData { get; set; } = "";
    public string? TargetExport { get; set; }
    public ThreadMode Thread { get; set; } = ThreadMode.Calling;
    public byte XorKey { get; set; } = (byte)Random.Shared.Next(0x10, 0xFE);
    public string Researcher { get; set; } = "@tunelko";
    public bool CloneMetadata { get; set; }
    public bool StompTimestamps { get; set; }
    public GenerationMode Mode { get; set; } = GenerationMode.Proxy;

    // ── Deploy + Run integration (optional) ──
    // When DeployTargetDir + HostExePath are both set, the generated build .bat
    // appends a tail that: copies the built DLL to DeployTargetDir\DeployTargetName,
    // launches HostExePath via start /WAIT, then on host exit deletes the deployed
    // DLL and taskkills any lingering host process. Origin: phantom hand-off from
    // Scan/RuntimeTrace where we already know the NAME-NOT-FOUND slot + importer EXE.
    public string? DeployTargetDir { get; set; }
    public string? DeployTargetName { get; set; }   // null → reuse analysis.Filename
    public string? HostExePath { get; set; }

    // Canonical system copy (System32\X.dll or SysWOW64\X.dll) for well-known DLLs.
    // When set + Mode=Proxy, the generated .bat copies it as <base>_orig.dll next
    // to the deployed proxy so forward chains (winmm_orig.PlaySound etc.) resolve.
    public string? SystemOrigPath { get; set; }

    // Payload diagnostics — a ~80-byte file written to %TEMP% proving DllMain ran.
    // Useful when the MessageBox is invisible (service desktop, X server, headless).
    public bool WriteProofFile { get; set; } = true;

    // Optional delay in seconds inserted in the .bat between Deploy and Run.
    // Gives AV time to settle, or the user time to attach a debugger.
    public int PreLaunchDelaySec { get; set; } = 0;

    // true  → .bat uses start /WAIT (blocks until host closes), current default.
    // false → .bat uses start "" + timeout NonBlockingTimeoutSec, then auto-cleanup.
    //         Pair with WriteProofFile=true so the bat can show evidence after timeout.
    public bool WaitForHostExit { get; set; } = true;
    public int NonBlockingTimeoutSec { get; set; } = 15;

    // SandboxEscape-only: comma-separated list of sibling process names to try
    // injecting into (in order). First one that passes OpenProcess(ALL_ACCESS)
    // + VirtualAllocEx RWX smoke test wins. Host-specific — Adobe default ships
    // the Acrobat helper names, but Office/Edge/Chrome/Teams need their own.
    public string SandboxTargets { get; set; } = "AcroCEF.exe,AdobeCollabSync.exe";

    // MessageBox payload — editable title + body so the researcher can stamp
    // the popup with a session/case identifier without hand-patching the
    // generated C. {Researcher} placeholder is substituted at template time.
    // Newlines and quotes are escaped for C string literal embedding.
    public string MessageBoxTitle { get; set; } = "DllSidecar PoC {Researcher}";
    public string MessageBoxBody { get; set; } = "DLL Sideloading PoC\nResearcher: {Researcher}\nDllSidecar — BugAInters 2026";

    // ── Evasion techniques (extra opt-ins on top of DInvoke/syscalls/encrypt) ──
    // AMSI Evasion via Hardware Breakpoint Hooks — installs a patchless hook
    // on AmsiScanBuffer using Dr0-3 registers + a VEH handler. All AmsiScanBuffer
    // calls in-process return AMSI_RESULT_CLEAN. Source: BigPolarBear1's
    // HardwareBreakPointLib bundled under Resources/Evasion/AmsiHwBp.
    // x64 only (uses GETPARM_6 macros). Adds ~30KB compiled to the DLL.
    public bool AmsiHookHwBp { get; set; }
}

public enum PayloadType
{
    MessageBox,
    Command,
    Shellcode,
    // Cross-process inject payload for AppContainer / sandboxed targets.
    // Scans siblings for one we can OpenProcess(ALL_ACCESS) + VirtualAllocEx
    // RWX, then remote-thread executes CreateProcessA with WinSta0\Default
    // desktop so the spawned cmd is visible to the user.
    SandboxEscape
}

public enum ThreadMode
{
    Calling,
    Std,
    Native
}

public enum GenerationMode
{
    Tracer,
    Proxy,
    Sideload
}
