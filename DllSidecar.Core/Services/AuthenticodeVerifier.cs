using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>
/// Verifies Authenticode signatures using native WinVerifyTrust (primary) with optional
/// sigcheck.exe fallback when configured.
/// </summary>
public static class AuthenticodeVerifier
{
    // GUID: WINTRUST_ACTION_GENERIC_VERIFY_V2
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;
    private const uint WTD_DISABLE_MD2_MD4 = 0x00002000;

    // HRESULT codes
    private const uint S_OK = 0;
    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    private const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
    private const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;
    private const uint CRYPT_E_SECURITY_SETTINGS = 0x80092026;
    private const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;
    private const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;
    private const uint CERT_E_CHAINING = 0x800B010A;
    private const uint CERT_E_EXPIRED = 0x800B0101;
    private const uint CERT_E_REVOKED = 0x800B010C;
    private const uint TRUST_E_BAD_DIGEST = 0x80096010;

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, [In] ref Guid pgActionID, [In] ref WINTRUST_DATA pWVTData);

    public static SigningInfo Verify(string filePath)
    {
        var info = new SigningInfo();
        if (!File.Exists(filePath))
        {
            info.Status = SigningStatus.Unknown;
            info.ErrorMessage = "File not found";
            return info;
        }

        IntPtr pFileInfo = IntPtr.Zero;
        IntPtr pFilePath = IntPtr.Zero;
        try
        {
            pFilePath = Marshal.StringToHGlobalUni(filePath);
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = pFilePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };
            pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFileInfo,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero,
            };

            var actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            uint result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);
            info.RawStatusCode = result;

            info.Status = result switch
            {
                S_OK => SigningStatus.Valid,
                TRUST_E_NOSIGNATURE => SigningStatus.NotSigned,
                TRUST_E_SUBJECT_FORM_UNKNOWN => SigningStatus.NotSigned,
                TRUST_E_PROVIDER_UNKNOWN => SigningStatus.NotSigned,
                CERT_E_UNTRUSTEDROOT => SigningStatus.Untrusted,
                CERT_E_CHAINING => SigningStatus.Untrusted,
                CERT_E_EXPIRED => SigningStatus.Invalid,
                CERT_E_REVOKED => SigningStatus.Invalid,
                TRUST_E_BAD_DIGEST => SigningStatus.Invalid,
                TRUST_E_EXPLICIT_DISTRUST => SigningStatus.Invalid,
                _ => SigningStatus.Invalid,
            };

            if (result != S_OK)
                info.ErrorMessage = $"0x{result:X8}";

            // Close state
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);

            // Pull cert details (independent of trust outcome)
            PopulateCertInfo(filePath, info);
        }
        catch (DllNotFoundException ex)
        {
            Log.Error("authenticode", "wintrust.dll not available — WinVerifyTrust P/Invoke failed", ex);
            info.Status = SigningStatus.Unknown;
            info.ErrorMessage = "wintrust.dll not available on this system";
        }
        catch (Exception ex)
        {
            Log.Warn("authenticode", $"Unexpected error verifying {filePath}", ex);
            info.Status = SigningStatus.Unknown;
            info.ErrorMessage = ex.Message;
        }
        finally
        {
            if (pFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pFileInfo);
            if (pFilePath != IntPtr.Zero) Marshal.FreeHGlobal(pFilePath);
        }

        return info;
    }

    private static void PopulateCertInfo(string filePath, SigningInfo info)
    {
        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is the Authenticode path; no direct replacement for signed-file extraction
            using var raw = X509Certificate.CreateFromSignedFile(filePath);
            var cert = new X509Certificate2(raw);
#pragma warning restore SYSLIB0057
            info.Subject = cert.SubjectName.Name;
            info.Issuer = cert.IssuerName.Name;
            info.ThumbprintSha1 = cert.Thumbprint;
            info.NotBefore = cert.NotBefore;
            info.NotAfter = cert.NotAfter;
            // CN feeds VendorResolver as the authoritative vendor source.
            info.SubjectCommonName = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        }
        catch (CryptographicException ex)
        {
            // Expected for unsigned files.
            Log.Debug("authenticode.cert", $"No extractable certificate from {filePath}: {ex.Message}");
        }
        catch (Exception ex)
        {
            Log.Warn("authenticode.cert", $"Unexpected cert extraction failure for {filePath}", ex);
        }
    }

    /// <summary>Optional sigcheck.exe cross-check if configured. Returns null if sigcheck unavailable.</summary>
    public static string? CrossCheckWithSigcheck(string filePath)
    {
        var sigcheck = ConfigManager.Current.Tools.SigcheckPath;
        if (string.IsNullOrWhiteSpace(sigcheck) || !File.Exists(sigcheck)) return null;
        if (!File.Exists(filePath))
        {
            Log.Warn("authenticode.sigcheck", $"Target file does not exist: {filePath}");
            return null;
        }

        var psi = new ProcessStartInfo
        {
            FileName = sigcheck,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        // ArgumentList escapes each arg individually.
        psi.ArgumentList.Add("-nobanner");
        psi.ArgumentList.Add("-accepteula");
        psi.ArgumentList.Add("-q");
        psi.ArgumentList.Add(filePath);

        Process? p = null;
        try
        {
            p = Process.Start(psi);
            if (p == null)
            {
                Log.Warn("authenticode.sigcheck", $"Failed to start sigcheck at {sigcheck}");
                return null;
            }
            var output = p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(5000))
            {
                Log.Warn("authenticode.sigcheck", "sigcheck timed out after 5s; killing");
                try { p.Kill(entireProcessTree: true); } catch (Exception kx) { Log.Warn("authenticode.sigcheck", "Failed to kill sigcheck", kx); }
                return null;
            }
            return output.Trim();
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Log.Warn("authenticode.sigcheck", $"sigcheck invocation failed", ex);
            return null;
        }
        finally
        {
            p?.Dispose();
        }
    }
}
