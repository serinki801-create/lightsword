// language: C, file: nk_state_machine.c, target: iOS 26.2 / 23C55 / arm64e, LiveContainer guest
// Crash-driven state machine. Probe ids match Diag/nk_child_diag.c:
// 0 GUARD, 1 T0E, 2 DUMMYNET, 3 FRAME. State file is one NAME=VERDICT line per
// probe, fsync'd on every transition; the previous boot left RUNNING =>
// uncatchable death => DEAD. No fork anywhere (R15/Link: LC reaps children).

#include "nk_state_machine.h"
#include "nk_home.h"
#include "nk_trace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#define NK_PROBE_COUNT 4

static const char *k_probe_name[NK_PROBE_COUNT] = {"GUARD", "T0E", "DUMMYNET", "FRAME"};

static int g_verdict[NK_PROBE_COUNT];
static int g_loaded;

static int probe_index(int probe_id)
{
    switch (probe_id) {
    case 0: return 0;
    case 1: return 1;
    case 2: return 2;
    case 3: return 3;
    default: return -1;
    }
}

static void state_save(void)
{
    char path[560];
    nk_home_path("nk_probe_state.json", path, sizeof(path));

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;

    char b[128];
    for (int i = 0; i < NK_PROBE_COUNT; i++) {
        int n = snprintf(b, sizeof(b), "%s=%d\n", k_probe_name[i], g_verdict[i]);
        if (n > 0) { if (write(fd, b, (size_t)n) < 0) { } }
    }
    fsync(fd);
    close(fd);
}

void nk_state_load(void)
{
    if (g_loaded) return;

    for (int i = 0; i < NK_PROBE_COUNT; i++) g_verdict[i] = NK_ST_OK;

    char path[560];
    nk_home_path("nk_probe_state.json", path, sizeof(path));

    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        char b[512];
        ssize_t r = read(fd, b, sizeof(b) - 1);
        close(fd);
        if (r > 0) {
            b[r] = 0;
            char *save = NULL;
            for (char *line = strtok_r(b, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
                for (int i = 0; i < NK_PROBE_COUNT; i++) {
                    size_t l = strlen(k_probe_name[i]);
                    if (!strncmp(line, k_probe_name[i], l) && line[l] == '=') {
                        g_verdict[i] = atoi(line + l + 1);
                        break;
                    }
                }
            }
        }
    }

    /* a probe left RUNNING died uncatchably last session */
    for (int i = 0; i < NK_PROBE_COUNT; i++) {
        if (g_verdict[i] == NK_ST_RUNNING) {
            g_verdict[i] = NK_ST_DEAD;
            trace_log("[STATE] %s died uncatchably last session -> marked DEAD\n",
                      k_probe_name[i]);
        }
    }

    state_save();
    g_loaded = 1;
}

int nk_state_should_skip(int probe_id)
{
    int i = probe_index(probe_id);
    if (i < 0) return 0;
    if (!g_loaded) nk_state_load();
    return g_verdict[i] == NK_ST_DEAD;
}

void nk_state_begin(int probe_id)
{
    int i = probe_index(probe_id);
    if (i < 0) return;
    if (!g_loaded) nk_state_load();
    g_verdict[i] = NK_ST_RUNNING;
    state_save();
}

void nk_state_end(int probe_id, int verdict)
{
    int i = probe_index(probe_id);
    if (i < 0) return;
    g_verdict[i] = verdict;
    state_save();
}

int nk_state_last_breadcrumb(char *out, int cap)
{
    if (!out || cap <= 0) return -1;
    out[0] = 0;

    char path[560];
    nk_home_path("trace.log", path, sizeof(path));

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1; /* NO_TRACE_LOG */

    off_t sz = lseek(fd, 0, SEEK_END);
    off_t start = sz > 4096 ? sz - 4096 : 0;
    lseek(fd, start, SEEK_SET);

    char b[4097];
    ssize_t r = read(fd, b, 4096);
    close(fd);
    if (r <= 0) return -2; /* EMPTY_TRACE */

    b[r] = 0;
    char *last = NULL;
    char *save = NULL;
    for (char *line = strtok_r(b, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (line[0]) last = line;
    }
    if (!last) return -2;

    int n = snprintf(out, (size_t)cap, "%s", last);
    return (n > 0) ? n : -2;
}

void nk_state_reset(void)
{
    char path[560];
    nk_home_path("nk_probe_state.json", path, sizeof(path));
    unlink(path);
    g_loaded = 0;
    nk_state_load();
    trace_log("[STATE] state reset by user; probes re-enabled\n");
}
