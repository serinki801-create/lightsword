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
/* probe-candidate tracking (W-T3 hunt convergence): a "try q=0x... src=L0
   idx=1/2" line opens a candidate walk, "miss q=0x..." (or a fingerprint hit)
   closes it. A walk still open at the next nk_run_begin (a fresh page) is the
   lethal one. The key is TIER:INDEX, never an address — every pointer is
   ASLR-randomized per page load, so an address blacklist would never match
   the next run; the tier+slot position is stable. The key is appended to
   Documents/wt3_dead.txt and the JS side skips that slot, so each reload
   advances past exactly the page that killed the last one. */
static char g_probe_key[32] = "";
static int g_probe_open = 0;

int nk_run_begin(const char *label)
{
    nk_probe_mark_dead();
    g_run_id++;
    g_claim_run = -1; /* a new run may claim the self-test again */
    if (!label) label = "?";
    nk_logx("RUN", "run=%d begin label=%s (prev ended at=[%s] %s)",
            g_run_id, label, g_last_tag, g_last_msg);
    trace_log("[RUN] run=%d begin label=%s\n", g_run_id, label);
    return g_run_id;
}

/* parse "wt3 try q=0x1234 src=L0 idx=1/2" -> key "L0:1". The search is
   strstr, not strncmp: every JS log line arrives with its own label prefix
   ("wt3 ..."), which the strncmp version silently missed (17:43 run: full
   idx instrumentation, zero probe tracking). */
static int probe_key_of(const char *msg, char *key, size_t cap)
{
    /* key = TIER:INDEX. sweepPages writes "wt3 sweep q=... src=W pg=0/4" and
       the near/walk tiers write "wt3 try q=... src=soft idx=3/17" — BOTH
       shapes must open a walk, or the dead-slot file silently stays empty
       (16:29 run: the sweep killed q=0x10d44a000 at pg=0 and nothing was
       recorded, because probe_track only knew "try q="). */
    const char *src = strstr(msg, " src=");
    const char *idx = strstr(msg, " idx=");
    char tier[16] = "?", ix[8] = "0";
    if (src) {
        src += 5;
        size_t i = 0;
        while (src[i] && src[i] != ' ' && i < sizeof(tier) - 1) { tier[i] = src[i]; i++; }
        tier[i] = 0;
    }
    if (idx) {
        idx += 5;
        size_t i = 0;
        while (idx[i] && idx[i] != '/' && idx[i] != ' ' && i < sizeof(ix) - 1) { ix[i] = idx[i]; i++; }
        ix[i] = 0;
    }
    if (!src && !idx) return 0;
    int n = snprintf(key, cap, "%s:%s", tier, ix);
    return n > 0;
}

static void probe_track(const char *msg)
{
    const char *tryp = strstr(msg, "try q=");
    if (tryp) {
        char key[32];
        if (probe_key_of(msg, key, sizeof(key))) {
            snprintf(g_probe_key, sizeof(g_probe_key), "%s", key);
            g_probe_open = 1;
        }
    } else if (strstr(msg, "sweep q=")) {
        /* page-major sweep: the walk stays open across the whole page read.
           The JS writes idx=N on the line (the candidate's slot in the tier),
           so probe_key_of yields TIER:SLOT directly — the same key the JS
           skip checks. A page read that dies leaves the walk open; the next
           run start appends it to wt3_dead.txt. */
        char key[32];
        if (probe_key_of(msg, key, sizeof(key))) {
            snprintf(g_probe_key, sizeof(g_probe_key), "%s", key);
            g_probe_open = 1;
        }
    } else if (strstr(msg, "miss q=") || strstr(msg, "FINGERPRINT")) {
        g_probe_open = 0;   /* the walk completed — safe or found */
    }
}

/* the page navigated/died with a candidate walk still open -> that slot killed it */
void nk_probe_mark_dead(void)
{
    if (g_probe_open && g_probe_key[0]) {
        char p[560];
        nk_home_path("wt3_dead.txt", p, sizeof(p));
        int fd = open(p, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            char b[96];
            int n = snprintf(b, sizeof(b), "%s\n", g_probe_key);
            if (n > 0) { if (write(fd, b, (size_t)n) < 0) { } fsync(fd); }
            close(fd);
        }
        nk_logx("SCAN", "probe-dead: %s (walk never closed — page died there)", g_probe_key);
        trace_log("[SCAN] probe-dead: %s\n", g_probe_key);
    }
    g_probe_open = 0;
    g_probe_key[0] = 0;
}

/* the dead-slot list for the JS side: "L0:1","Cpp:0" (quoted, comma-separated
   — drops straight into a JS array literal). Deduped: a slot already listed
   is not appended twice. */
int nk_probe_dead_list(char *out, int cap)
{
    if (!out || cap <= 0) return -1;
    out[0] = 0;
    char p[560];
    nk_home_path("wt3_dead.txt", p, sizeof(p));
    int fd = open(p, O_RDONLY);
    if (fd < 0) return 0;
    char buf[2048];
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) return 0;
    buf[r] = 0;
    int w = 0, first = 1;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line && w < cap - 12; line = strtok_r(NULL, "\n", &save)) {
        if (!line[0]) continue;
        char probe[40];
        if (snprintf(probe, sizeof(probe), "\"%s\"", line) <= 0) continue;
        if (strstr(out, probe) != NULL) continue;   /* already listed */
        int n = snprintf(out + w, (size_t)(cap - w), "%s%s", first ? "" : ",", probe);
        if (n <= 0 || n >= cap - w) break;
        w += n;
        first = 0;
    }
    return w;
}

void nk_probe_dead_clear(void)
{
    char p[560];
    nk_home_path("wt3_dead.txt", p, sizeof(p));
    unlink(p);
    g_probe_open = 0;
    g_probe_key[0] = 0;
    nk_logx("SCAN", "probe-dead list cleared");
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
    if (strcmp(tag, "SCAN") == 0) probe_track(msg);

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
