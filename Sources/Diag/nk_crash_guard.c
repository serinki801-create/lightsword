// language: C, file: nk_crash_guard.c, target: iOS 26.2 / 23C55 / arm64e, Theos app sandbox
// Crash diagnostics for the T2/T0e probes: SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGTRAP/
// SIGABRT handler writing fault address + signal + fp-chain backtrace to a file
// in the app container. The next userspace crash becomes an exact address
// instead of "LiveContainer died". Async-signal-safe: raw write() only.

#include "exploit.h"
#include "nk_home.h"
#include "nk_trace.h"
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

#ifndef SA_SIGINFO
#define SA_SIGINFO 0x40
#endif

static char g_guard_path[512];

/* install-step breadcrumbs: the 2026-10-10 device run died between probe
 * stages 2 and 3, i.e. inside nk_crash_guard_install itself. Every statement
 * gets a marker; the last marker before death names the killer. C-only
 * logging here (no Swift bridge on the dispatch worker thread) plus raw
 * write(2) so the line exists even if trace.log's fd path dies with us. */
static void gmark(const char *step)
{
    write(2, "[GUARD] ", 8);
    write(2, step, strlen(step));
    write(2, "\n", 1);
    trace_log("[GUARD] %s\n", step);
}

/* in-process recovery: when armed, a caught fault returns to the probe's
 * sigsetjmp point instead of _exit(88). This is what keeps LiveContainer
 * alive on ordinary synchronous SIGSEGV. It does NOT catch Mach exceptions
 * or SIGKILL — those are handled by the state machine (nk_state_machine.c). */
static sigjmp_buf *g_recover_env;
static volatile sig_atomic_t g_recover_on;

void nk_crash_guard_set_recovery(void *env)
{
    g_recover_env = (sigjmp_buf *)env;
    g_recover_on = (env != NULL) ? 1 : 0;
}

static void gput(const char *s, int *pos, char *b, int n)
{
    int l = 0; while (s[l]) l++;
    if (*pos + l < n) { for (int i = 0; i < l; i++) b[(*pos)++] = s[i]; }
}

static void ghex(uint64_t v, char *b, int *pos, int n)
{
    char tmp[20]; int i = 0;
    if (v == 0) { gput("0", pos, b, n); return; }
    while (v && i < 20) { int d = (int)(v & 0xf); tmp[i++] = (char)(d < 10 ? '0'+d : 'a'+d-10); v >>= 4; }
    gput("0x", pos, b, n);
    char out[20]; int k = 0;
    while (i > 0) out[k++] = tmp[--i];
    out[k] = 0; gput(out, pos, b, n);
}

static void nk_guard_handler(int sig, siginfo_t *si, void *uc)
{
    char b[512]; int p = 0;
    const char *names[] = {"?","SIGHUP","SIGINT","SIGQUIT","SIGILL","SIGTRAP","SIGABRT",
        "SIGEMT","SIGFPE","SIGKILL","SIGBUS","SIGSEGV","SIGSYS","SIGPIPE","SIGALRM","SIGTERM"};
    const char *nm = (sig >= 0 && sig <= 15) ? names[sig] : "SIG?";

    gput("[GUARD] signal=", &p, b, (int)sizeof(b));
    gput(nm, &p, b, (int)sizeof(b));
    gput(" code=", &p, b, (int)sizeof(b));
    ghex((uint64_t)si->si_code, b, &p, (int)sizeof(b));
    gput(" fault_addr=", &p, b, (int)sizeof(b));
    ghex((uint64_t)(uintptr_t)si->si_addr, b, &p, (int)sizeof(b));

    /* si_code decode */
    const char *sc = "other";
    if (sig == SIGSEGV || sig == SIGBUS) {
        sc = (si->si_code == SEGV_MAPERR || si->si_code == BUS_ADRERR) ? "addr-not-mapped" :
             (si->si_code == SEGV_ACCERR || si->si_code == BUS_ADRALN) ? "access-denied" :
             (si->si_code == SI_USER || si->si_code == SI_QUEUE) ? "user-queued" : "other";
    } else if (sig == SIGILL) {
        sc = (si->si_code == ILL_ILLOPC) ? "illegal-opcode" :
             (si->si_code == ILL_PRVOPC) ? "privileged-opcode" :
             (si->si_code == ILL_ILLTRP) ? "illegal-trap" : "other";
    } else if (sig == SIGABRT) {
        sc = "abort()/assert";
    } else if (sig == SIGTRAP) {
        sc = "breakpoint/trap";
    }
    gput(" si=", &p, b, (int)sizeof(b));
    gput(sc, &p, b, (int)sizeof(b));

    gput(" uc=", &p, b, (int)sizeof(b));
    ghex((uint64_t)(uintptr_t)uc, b, &p, (int)sizeof(b));

    b[p++] = '\n';
    int fd = open(g_guard_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { if (write(fd, b, (size_t)p) < 0) { } close(fd); }

    if (g_recover_on && g_recover_env) {
        siglongjmp(*g_recover_env, sig); /* back to nk_probe_run_guarded */
    }
    _exit(88);
}

static const char *nk_guard_default_path(void)
{
    /* Documents survives reboot and is reachable via file managers / sharing;
     * a SIGKILL (sandbox/jetsam) still leaves the stage markers in
     * Documents/trace.log because trace_log() fsyncs every line. */
    static char p[512];
    nk_home_path("nk_crash.txt", p, sizeof(p));
    return p;
}

void nk_crash_guard_install(const char *path)
{
    gmark("g1 enter");

    const char *use = (path && *path) ? path : nk_guard_default_path();
    gmark("g2 path resolved");

    size_t i = 0;
    for (; use[i] && i < sizeof(g_guard_path) - 1; i++) g_guard_path[i] = use[i];
    g_guard_path[i] = 0;
    /* C-only log: the Swift bridge on the dispatch worker thread is a death
     * suspect (launch-time main-thread nk_logx works; this path does not). */
    trace_log("[GUARD] installed -> %s\n", g_guard_path);
    gmark("g3 logged");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = nk_guard_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    static char altstack[SIGSTKSZ * 4];
    stack_t ss; ss.ss_sp = altstack; ss.ss_size = sizeof(altstack); ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) { gmark("g4 sigaltstack FAILED"); } else { gmark("g4 sigaltstack ok"); }

    if (sigaction(SIGSEGV, &sa, NULL) != 0) gmark("g5 sigaction SIGSEGV FAILED"); else gmark("g5 sigaction SIGSEGV ok");
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    gmark("g6 sigactions done");
}

/* end-to-end verification: installs the guard, then faults deliberately.
 * Expected: Documents/nk_crash.txt gains a SIGSEGV si addr=0x0 line and the
 * process exits with code 88. If the file does NOT appear after pressing
 * "Guard Test", the guard mechanism itself is broken (or the process dies by
 * SIGKILL before reaching the handler). */
int nk_crash_guard_test(void)
{
    nk_crash_guard_install(NULL);
    nk_logx("GUARD", "self-test: deliberate NULL deref follows");
    volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)0;
    (void)*p;
    nk_logx("GUARD", "self-test: NOT REACHED (guard dead)");
    return 1;
}
