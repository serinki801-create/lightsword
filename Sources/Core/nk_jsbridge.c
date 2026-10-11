// language: C, file: nk_jsbridge.c, target: iOS 26.2 / 23C55 / LiveContainer guest / arm64
// JS<->native bridge sink for the WebKit stage + run/phase observability.
//
// F1/F2/F6 contract (2026-10-10):
//   - every bridge line carries run=<id>; the id is assigned HERE (C), not in
//     JS, so a page reload or a new WebContent process produces a NEW id and
//     the log itself answers "two runs in one press" vs "double evaluate".
//   - the last tag/msg and the last JS status line are retained so a
//     WebContent termination can name where the process died (JS state is
//     gone by then — this is why the memory lives in C).
//   - SELFTESTCLAIM is a C-side test-and-set keyed by run id: a JS boolean is
//     worthless across a reload.

#include "exploit.h"
#include "nk_home.h"
#include "nk_trace.h"
#include <fcntl.h>

static int g_run_id = 0;
static char g_last_tag[64] = "";
static char g_last_msg[512] = "";
static char g_status[256] = "matchIdx=- round=- observed=-";
static int g_claim_run = -1;

int nk_run_begin(const char *label)
{
    g_run_id++;
    g_claim_run = -1; /* a new run may claim the self-test again */
    if (!label) label = "?";
    nk_logx("RUN", "run=%d begin label=%s", g_run_id, label);
    trace_log("[RUN] run=%d begin label=%s\n", g_run_id, label);
    return g_run_id;
}

int nk_run_current(void)
{
    return g_run_id;
}

int nk_selftest_claim(int run)
{
    if (run <= 0) run = g_run_id;
    if (g_claim_run == run) {
        nk_logx("RUN", "claim DENIED run=%d already claimed by this run", run);
        trace_log("[RUN] claim DENIED run=%d\n", run);
        return 0;
    }
    g_claim_run = run;
    nk_logx("RUN", "claim GRANTED run=%d", run);
    trace_log("[RUN] claim GRANTED run=%d\n", run);
    return 1;
}

void nk_jsbridge_status(const char *kv)
{
    if (!kv) return;
    size_t i = 0;
    for (; kv[i] && i < sizeof(g_status) - 1; i++) g_status[i] = kv[i];
    g_status[i] = 0;
    trace_log("[RUN] status run=%d %s\n", g_run_id, g_status);
}

void nk_jsbridge_log(const char *tag, const char *msg)
{
    if (!msg) return;
    if (!tag || !tag[0]) tag = "JS";

    size_t i = 0;
    for (; tag[i] && i < sizeof(g_last_tag) - 1; i++) g_last_tag[i] = tag[i];
    g_last_tag[i] = 0;
    i = 0;
    for (; msg[i] && i < sizeof(g_last_msg) - 1; i++) g_last_msg[i] = msg[i];
    g_last_msg[i] = 0;

    /* FILE ONLY on this path: the coalesced UI tail is fed from
     * UIBridge.swift's NKBBridgeSink. Routing every line through nk_logx
     * (Swift bridge -> @Published) caused per-line UI churn which rebuilt the
     * sheet and reloaded the page mid-trigger. */
    trace_log("[%s] run=%d %s\n", tag, g_run_id, msg);
}

/* F1: WebContent process death. Called from the WKNavigationDelegate's
 * webContentProcessDidTerminate. NEVER reloads: a terminate is terminal for
 * the run; auto-reload turns one crash into an unbounded silent restart loop.
 * The FATAL line names the run, the last bridge line, and the last JS status. */
void nk_fatal_webcontent(void)
{
    nk_logx("WK", "FATAL run=%d webcontent-terminated at=[%s] %s",
            g_run_id, g_last_tag, g_last_msg);
    {
        /* dedicated file too: if the renderer death also takes the guest,
         * this file survives for the post-mortem read at next launch */
        char p[560];
        nk_home_path("wk_fatal.txt", p, sizeof(p));
        int fd = open(p, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            char b[512];
            int n = snprintf(b, sizeof(b),
                             "FATAL run=%d webcontent-terminated at=[%s] %s\nstatus: %s\n",
                             g_run_id, g_last_tag, g_last_msg, g_status);
            if (n > 0) { if (write(fd, b, (size_t)n) < 0) { } fsync(fd); }
            close(fd);
        }
    }
    nk_logx("WK", "FATAL run=%d snapshot status: %s", g_run_id, g_status);
    trace_log("[WK] FATAL run=%d webcontent-terminated at=[%s] %s\n",
              g_run_id, g_last_tag, g_last_msg);
    trace_log("[WK] FATAL run=%d snapshot status: %s\n", g_run_id, g_status);
}
