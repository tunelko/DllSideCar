namespace DllSidecar.Core.Models;

public class SecurityFlags
{
    public bool Aslr { get; set; }
    public bool HighEntropyAslr { get; set; }
    public bool Dep { get; set; }
    public bool Cfg { get; set; }
    public bool SafeSeh { get; set; }
    public bool ForceIntegrity { get; set; }
    public bool Authenticode { get; set; }
    public uint DependentLoadFlags { get; set; }

    public int Score => new[] { Aslr, HighEntropyAslr, Dep, Cfg, SafeSeh, ForceIntegrity, Authenticode }
        .Count(f => f);

    // LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800 — if set, this PE never loads DLLs from its own dir
    public bool ForcesSystem32Only => (DependentLoadFlags & 0x800u) != 0;
}
