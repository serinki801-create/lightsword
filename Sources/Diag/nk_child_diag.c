// language: C, file: nk_child_diag.c, target: iOS 26.2 / 23C55 / arm64e, LiveContainer guest
// Probe isolation WITHOUT fork(). LiveContainer runs the guest inside its host
// process and watches process exits: a forked child's death (even exit 42) is
// seen as the guest dying, and fork() inside the jetsam-tight host gets the
// whole app SIGKILLed. Isolation is therefore in-process:
//   sigsetjmp/siglongjmp + the crash guard.
// A SIGSEGV-class fault writes Documents/nk_crash.txt and RETURNS to the button
// handler — the container never dies. SIGKILL-class deaths cannot be caught;
// they are proven by the fsync'd breadcrumbs (stage file + trace.log BEGIN).
// POSIX-only from probe entry down: no ObjC, no Swift, no CoreFoundation.

#include "exploit.h"
#include "nk_home.h"
#include "nk_trace.h"
#include "nk_state_machine.h"
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef enum {
    NK_PROBE_GUARD = 0,
    NK_PROBE_T0E,
    NK_PROBE_DUMMYNET,
    NK_PROBE_FRAME50
} nk_probe_t;

static sigjmp_buf g_probe_env;
static int g_recovered;

#define NK_CRASH_FILE "nk_crash.txt"
#define NK_STAGE_FILE "nk_stage.txt"

/* ---- stage breadcrumbs: fsync'd, survive even SIGKILL -------------------
 * 1 = entered runner, 2 = logger armed, 3 = guard armed, 4 = inside probe,
 *     5 = finished. A stale 4 + no crash file + trace.log ending at BEGIN
 *     = SIGKILL-class death (sandbox/jetsam), not our SIGSEGV path. */
static void nk_stage_write(int stage)
{
    char path[560];
    nk_home_path(NK_STAGE_FILE, path, sizeof(path));

    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) return;

    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d\n", stage);
    if (n > 0) {
        if (write(fd, buf, (size_t)n) < 0) { }
        fsync(fd);
    }
    close(fd);
}

static int nk_stage_read(void)
{
    char path[560];
    nk_home_path(NK_STAGE_FILE, path, sizeof(path));

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    char buf[32];
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (r <= 0) return -2;
    buf[r] = '\0';

    char *end = NULL;
    long v = strtol(buf, &end, 10);
    if (end == buf || v < 0 || v > 99) return -2;
    return (int)v;
}

static bool nk_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static const char *sig_name(int s)
{
    switch (s) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS:  return "SIGBUS";
    case SIGILL:  return "SIGILL";
    case SIGFPE:  return "SIGFPE";
    case SIGABRT: return "SIGABRT";
    case SIGTRAP: return "SIGTRAP";
    case SIGKILL: return "SIGKILL";
    default:      return "SIG?";
    }
}

static const char *probe_name(int probe_id)
{
    switch (probe_id) {
    case NK_PROBE_GUARD:    return "GUARD";
    case NK_PROBE_T0E:      return "T0E";
    case NK_PROBE_DUMMYNET: return "DUMMYNET";
    case NK_PROBE_FRAME50:  return "FRAME";
    default:                return "?";
    }
}

/* ---- the runner --------------------------------------------------------- */

/* probe-finish callback (set from Swift on the main thread before dispatch):
 * keeps the UI verdict update off the background-thread logging path. */
static void (*g_probe_done)(int probe_id, int verdict);
void nk_set_probe_done(void (*fn)(int probe_id, int verdict)) { g_probe_done = fn; }

/* C-only log target during probes: the Swift bridge on a dispatch worker
 * thread is the leading death suspect, so the probe path never touches it.
 * Evidence stays in Documents/trace.log (fsync per line). */
static void diag_c_log(const char *s) { trace_log("%s\n", s); }

int nk_probe_run_guarded(int probe_id, int rounds)
{
    char crash[560];
    nk_home_path(NK_CRASH_FILE, crash, sizeof(crash));
    unlink(crash); /* fresh crash file per run */

    nk_set_log(diag_c_log); /* no Swift bridge on this thread (diag isolation) */

    /* crash-driven skip: a probe that died uncatchably (SIGKILL / Mach
     * exception) last session stays dead until its body is fixed */
    if (nk_state_should_skip(probe_id)) {
        trace_log("[RUNNER] SKIP probe=%s reason=marked_dead_last_session\n",
                  probe_name(probe_id));
        nk_stage_write(5);
        if (g_probe_done) g_probe_done(probe_id, -9);
        return -9;
    }

    nk_state_begin(probe_id);

    nk_stage_write(1); /* entered runner                     */
    nk_stage_write(2); /* logger = C-only file (diag)        */
    nk_crash_guard_install(NULL);
    nk_stage_write(3); /* guard armed, file path resolved    */

    trace_log("[RUNNER] BEGIN probe=%s rounds=%d\n", probe_name(probe_id), rounds);
    nk_logx("RUNNER", "probe=%s rounds=%d begin", probe_name(probe_id), rounds);

    g_recovered = 0;
    int sig = sigsetjmp(g_probe_env, 1);
    if (sig != 0) {
        /* came back through the crash guard: container still alive */
        if (g_recovered) _exit(88); /* fault inside the report path — last resort */
        g_recovered = 1;
        nk_crash_guard_set_recovery(NULL);
        int stage = nk_stage_read();
        int crash_present = nk_file_exists(crash) ? 1 : 0;
        nk_stage_write(5);
        nk_state_end(probe_id, NK_ST_RECOVERED);
        trace_log("[RUNNER] RECOVERED signal=%d (%s) last_stage=%d crash_file=%d\n",
                  sig, sig_name(sig), stage, crash_present);
        nk_logx("RUNNER", "RECOVERED signal=%d (%s) last_stage=%d crash_file=%d",
                sig, sig_name(sig), stage, crash_present);
        if (g_probe_done) g_probe_done(probe_id, -sig);
        return -sig;
    }

    nk_crash_guard_set_recovery(&g_probe_env);
    nk_stage_write(4); /* inside probe */

    int rc = 64;
    switch ((nk_probe_t)probe_id) {
    case NK_PROBE_GUARD:
        { volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)0; (void)*p; }
        rc = 0; /* not reached: the guard recovers first */
        break;
    case NK_PROBE_T0E:
        rc = nk_t0e_spike();
        break;
    case NK_PROBE_DUMMYNET:
        rc = nk_t2_dummynet_probe();
        break;
    case NK_PROBE_FRAME50:
        rc = nk_t2_frame_probe(rounds > 0 ? rounds : 50);
        break;
    default:
        rc = 64;
        break;
    }

    nk_crash_guard_set_recovery(NULL);
    int stage = nk_stage_read();
    nk_stage_write(5);
    int crash_present = nk_file_exists(crash) ? 1 : 0;
    nk_state_end(probe_id, NK_ST_OK);
    trace_log("[RUNNER] EXITED code=%d last_stage=%d crash_file=%d\n",
              rc, stage, crash_present);
    nk_logx("RUNNER", "EXITED code=%d last_stage=%d crash_file=%d",
            rc, stage, crash_present);
    if (g_probe_done) g_probe_done(probe_id, rc);
    return rc;
}

int nk_probe_guard_test(void) { return nk_probe_run_guarded(NK_PROBE_GUARD, 0); }
int nk_probe_t0e(void)        { return nk_probe_run_guarded(NK_PROBE_T0E, 0); }
int nk_probe_dummynet(void)   { return nk_probe_run_guarded(NK_PROBE_DUMMYNET, 0); }
int nk_probe_t2frame(int r)   { return nk_probe_run_guarded(NK_PROBE_FRAME50, r); }
