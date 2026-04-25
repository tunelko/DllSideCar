namespace DllSidecar.Core.Models;

public enum SigningStatus
{
    Unknown,
    NotSigned,
    Valid,
    Invalid,        // signature present but verification failed (modified, chain broken, revoked, expired)
    Untrusted,      // chain does not terminate at a trusted root
}

public class SigningInfo
{
    public SigningStatus Status { get; set; } = SigningStatus.Unknown;
    public string? Subject { get; set; }               // full X.500 DN, e.g. "CN=Blizzard..., O=..., L=..."
    public string? SubjectCommonName { get; set; }     // just the CN (publisher-legal-name, e.g. "Blizzard Entertainment, Inc.")
    public string? Issuer { get; set; }                // issuing CA CN
    public string? ThumbprintSha1 { get; set; }
    public DateTime? NotBefore { get; set; }
    public DateTime? NotAfter { get; set; }
    public string? ErrorMessage { get; set; }
    public uint RawStatusCode { get; set; }            // WinVerifyTrust HRESULT

    public bool IsTrusted => Status == SigningStatus.Valid;
}
