#include "antidebug.h"
#include "trust.h"

#if defined(_WIN32)

#include <windows.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

/* PEB.BeingDebugged is a BYTE at offset 0x02 -- identical on x86 and x64,
 * this is what IsDebuggerPresent() itself reads internally. Reading it
 * by hand here (instead of calling the API) means an IAT hook on
 * IsDebuggerPresent alone doesn't neutralize this particular sub-check. */
static unsigned long long read_peb_ptr(void) {
#if defined(_WIN64)
#if defined(_MSC_VER)
    return (unsigned long long)__readgsqword(0x60);
#else
    unsigned long long peb;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
#endif
#else
#if defined(_MSC_VER)
    return (unsigned long long)__readfsdword(0x30);
#else
    unsigned long peb;
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb));
    return (unsigned long long)peb;
#endif
#endif
}

static void check_peb_being_debugged(void) {
    unsigned long long peb = read_peb_ptr();
    unsigned char being_debugged = *(volatile unsigned char *)(peb + 0x02);
    if (being_debugged != 0) {
        trust_poison(AEGIS_POISON_ANTIDEBUG);
    }
}

/* NtGlobalFlag: DWORD at PEB+0x68 (x86) / PEB+0xBC (x64). Process
 * launched under a debugger commonly has FLG_HEAP_ENABLE_TAIL_CHECK
 * (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20) | FLG_HEAP_VALIDATE_PARAMETERS
 * (0x40) set, i.e. (NtGlobalFlag & 0x70) != 0. These offsets are the ones
 * consistently documented across public anti-debug references; this is a
 * redundant, best-effort sub-check (one of several), so an imprecise
 * offset on an unusual Windows build degrades this one sub-check rather
 * than breaking anything else. */
static void check_nt_global_flag(void) {
    unsigned long long peb = read_peb_ptr();
#if defined(_WIN64)
    unsigned long flags = *(volatile unsigned long *)(peb + 0xBC);
#else
    unsigned long flags = *(volatile unsigned long *)(peb + 0x68);
#endif
    if ((flags & 0x70u) != 0) {
        trust_poison(AEGIS_POISON_ANTIDEBUG);
    }
}

static void check_is_debugger_present(void) {
    if (IsDebuggerPresent()) {
        trust_poison(AEGIS_POISON_ANTIDEBUG);
    }
}

static void check_remote_debugger_present(void) {
    BOOL present = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present) && present) {
        trust_poison(AEGIS_POISON_ANTIDEBUG);
    }
}

/* Coarse timing check: a debugger single-stepping through or breakpointing
 * inside this stretch of code inflates elapsed time far past what native
 * execution costs. The threshold is deliberately generous (tens of
 * milliseconds) to avoid false positives on a loaded machine; it will NOT
 * reliably catch a DBI tool running the code at full speed with only
 * occasional callbacks (that's a different, harder problem -- see
 * README "what this challenge does not pretend to solve"). */
static void check_timing(void) {
    LARGE_INTEGER freq, t0, t1;
    volatile unsigned long sink = 0;
    unsigned i;

    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) return;
    QueryPerformanceCounter(&t0);
    for (i = 0; i < 200000u; i++) {
        sink += i * 2654435761u; /* cheap, unpredictable-to-the-compiler busywork */
    }
    QueryPerformanceCounter(&t1);
    (void)sink;

    {
        double ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;
        if (ms > 50.0) {
            trust_poison(AEGIS_POISON_ANTIDEBUG);
        }
    }
}

void antidebug_run_all(void) {
    check_is_debugger_present();
    check_remote_debugger_present();
    check_peb_being_debugged();
    check_nt_global_flag();
    check_timing();
}

#elif defined(__linux__)

#include <sys/ptrace.h>
#include <stdio.h>
#include <string.h>

/*
 * Best-effort Linux path, for convenience when building/testing off
 * Windows. Documented side effect: PTRACE_TRACEME makes this process
 * traced BY ITSELF for the rest of its life -- a second real tracer
 * (gdb, strace, a DBI tool attaching via ptrace) cannot attach afterwards,
 * since Linux only allows one tracer per process. Real protectors accept
 * the exact same trade-off for the same technique. If you need a
 * DBI/ptrace-based tool to attach to THIS build, skip this sub-check
 * (comment out the call in antidebug_run_all) and rely on the
 * /proc/self/status TracerPid check below instead, which is passive.
 */
static void check_ptrace_traceme(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        trust_poison(AEGIS_POISON_ANTIDEBUG);
    }
}

static void check_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = 0;
            if (sscanf(line + 10, "%d", &pid) == 1 && pid != 0) {
                trust_poison(AEGIS_POISON_ANTIDEBUG);
            }
            break;
        }
    }
    fclose(f);
}

void antidebug_run_all(void) {
    check_ptrace_traceme();
    check_tracer_pid();
}

#else

void antidebug_run_all(void) {
    /* No anti-debug on this platform: silent no-op, never poisons. */
}

#endif
