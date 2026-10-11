#include "nk_diag.h"
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>

static uint32_t g_epoch = 1;
static uint32_t g_boot_epoch = 0;
static uint64_t g_seq = 0;
static pthread_mutex_t g_ev_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_ev_ready = 0;
static char g_ev_path[512];
static uint32_t g_cls_counts[4] = { 0, 0, 0, 0 };
static uint32_t g_crash_epoch = 0;
static char g_crash_tag[128] = { 0 };
static char g_ring[NK_EVENT_RING][384];
static int g_ring_idx = 0;

static const uint32_t crc_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
    0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7B17CBD4, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
    0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
    0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x5A195E4B, 0xD7A2BAEE, 0x6889C418,
    0x4A8A9F47, 0x3D9B2FD1, 0xA4247B33, 0x665C3CA5, 0x4E1B7E7F, 0x390D3BE9,
    0xA045D0E9, 0x3658297F, 0x585B3295, 0x2F557803, 0x4C6C8AF9, 0x3B67BC6F,
    0xA24CD3D5, 0xD5430043, 0x6948276F, 0x1E5378F9, 0x33A97E43, 0x448B8DD5,
    0x2C8DA1F0, 0x5B8AE066, 0xC2987ADC, 0xB59B934A, 0x3588F77B, 0x429B7EED,
    0xDBE46659, 0xACE3BACF, 0x2F962A62, 0x58A3FEF4, 0xE06D314E, 0x97612FD8,
    0x236D30DB, 0x54695E4D, 0x0C2633F7, 0x7B453461, 0x0D723BB3, 0x7A4CE025,
    0xE34570EC, 0x94356E7A, 0x0A7CA5C0, 0x7D1BF556, 0x0E2633F7, 0x99443361,
    0x0CA3E91F, 0x7BBCB689, 0x14D96BE0, 0x63C2BC76, 0x1C97B0CC, 0x6BA2425A,
    0x18656F7A, 0x6F47ACEC, 0xF67A2B56, 0x81671EC0, 0x1B4D3DB2, 0x6C40C224,
    0xF53860A9, 0x82523F3F, 0x2A7B4185, 0x5D0D0613, 0x340473F1, 0x4310B867,
    0x2D5A94BD, 0x5A6A982B, 0x3E3B9591, 0x4931A007, 0x2B95C1D9, 0x5C0B0A4F,
    0x3F5D7395, 0x46792103, 0x3822A0C5, 0x4F3D4E53, 0x2E6D2B89, 0x591CCA1F,
    0x3A34C7E5, 0x4D31B473, 0x2FC34AC9, 0x58594F5F, 0x34D96BE0, 0x43C2BC76,
    0x1C97B0CC, 0x6BA2425A, 0x18656F7A, 0x6F47ACEC, 0xF67A2B56, 0x81671EC0,
    0x1B4D3DB2, 0x6C40C224, 0xF53860A9, 0x82523F3F, 0x2A7B4185, 0x5D0D0613,
    0x340473F1, 0x4310B867, 0x2D5A94BD, 0x5A6A982B, 0x3E3B9591, 0x4931A007,
    0x2B95C1D9, 0x5C0B0A4F, 0x3F5D7395, 0x46792103, 0x3822A0C5, 0x4F3D4E53,
    0x2E6D2B89, 0x591CCA1F, 0x3A34C7E5, 0x4D31B473, 0x2FC34AC9, 0x58594F5F,
    0x34D96BE0, 0x43C2BC76, 0x1C97B0CC, 0x6BA2425A, 0x2B95C1D9, 0x5C0B0A4F,
    0x3F5D7395, 0x46792103, 0x3822A0C5, 0x4F3D4E53, 0x2E6D2B89, 0x591CCA1F,
    0x3A34C7E5, 0x4D31B473, 0x2FC34AC9, 0x58594F5F, 0x2A7B4185, 0x5D0D0613,
    0x340473F1, 0x4310B867, 0x2D5A94BD, 0x5A6A982B, 0x3E3B9591, 0x4931A007,
    0x2B95C1D9, 0x5C0B0A4F, 0x3F5D7395, 0x46792103, 0x3822A0C5, 0x4F3D4E53,
    0x2E6D2B89, 0x591CCA1F, 0x3A34C7E5, 0x4D31B473, 0x2FC34AC9, 0x58594F5F
};

uint32_t nk_crc32(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = crc_table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

uint32_t nk_diag_boot_epoch(void) {
    struct timeval tv;
    size_t bl = sizeof(tv);
    if (sysctlbyname("kern.boottime", &tv, &bl, NULL, 0) != 0) return 0;
    return (uint32_t)tv.tv_sec;
}

uint32_t nk_diag_epoch(void) { return g_epoch; }

uint64_t nk_diag_seq_next(void) { return __sync_fetch_and_add(&g_seq, 1); }

static const char *nk_docs_dir(void) {
    const char *home = getenv("HOME");
    static char path[512];
    if (!home) return NULL;
    snprintf(path, sizeof(path), "%s/Documents", home);
    return path;
}

const char *nk_diag_log_path(void) {
    snprintf(g_ev_path, sizeof(g_ev_path), "%s/nk_events_%u.jsonl",
        nk_docs_dir() ? nk_docs_dir() : ".", g_epoch);
    return g_ev_path;
}

const char *nk_diag_report_path(void) {
    static char rp[512];
    snprintf(rp, sizeof(rp), "%s/nk_jb_report.md",
        nk_docs_dir() ? nk_docs_dir() : ".");
    return rp;
}

void nk_diag_epoch_start(const char *module) {
    g_boot_epoch = nk_diag_boot_epoch();
    g_epoch++;
    mkdir(nk_docs_dir() ? nk_docs_dir() : ".", 0755);

    const char *reason = NULL;
    if (nk_diag_crash_pending(&reason)) {
        nk_log("[diag %s] crash pending since previous run: %s (boot=%u -> %u)",
            module, reason ? reason : "unknown",
            g_crash_epoch, g_boot_epoch);
    }

    char marker[1024];
    snprintf(marker, sizeof(marker), "%s/nk_run_marker.json",
        nk_docs_dir() ? nk_docs_dir() : ".");
    int fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        char buf[256];
        int n = snprintf(buf, sizeof(buf),
            "{\"epoch\":%u,\"boot\":%u,\"module\":\"%s\"}\n",
            g_epoch, g_boot_epoch, module);
        if (write(fd, buf, (size_t)n) < 0) {}
        close(fd);
    }

    pthread_mutex_lock(&g_ev_lock);
    if (!g_ev_ready) {
        int fd = open(nk_diag_log_path(), O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) close(fd);
        g_ev_ready = 1;
    }
    pthread_mutex_unlock(&g_ev_lock);

    nk_log("[diag %s] epoch=%u boot=%u log=%s", module, g_epoch,
        g_boot_epoch, nk_diag_log_path());
}

int nk_diag_crash_pending(const char **reason) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/nk_run_marker.json",
        nk_docs_dir() ? nk_docs_dir() : ".");
    int fd = open(path, O_RDONLY);
    if (fd < 0) { if (reason) *reason = "no marker"; return 0; }
    char buf[256] = { 0 };
    if (read(fd, buf, sizeof(buf) - 1) < 0) { close(fd); return 0; }
    close(fd);

    uint32_t prev_boot = 0;
    char *b = strstr(buf, "\"boot\":");
    if (b) prev_boot = (uint32_t)strtoul(b + 7, NULL, 10);
    if (!prev_boot) return 0;

    uint32_t now = nk_diag_boot_epoch();
    if (now != prev_boot) {
        g_crash_epoch = prev_boot;
        snprintf(g_crash_tag, sizeof(g_crash_tag), "boot %u -> %u",
            prev_boot, now);
        if (reason) *reason = g_crash_tag;
        return 1;
    }
    return 0;
}

int nk_diag_panic_correlate(void) {
    static const char *panic_paths[] = {
        "/private/var/db/.panic-data",
        "/private/var/db/PanicData",
        "/Library/Logs/panic-full",
        "/var/db/.panic-data",
        NULL
    };
    int found = 0;
    for (int i = 0; panic_paths[i]; i++) {
        struct stat st;
        if (stat(panic_paths[i], &st) == 0) {
            nk_log("[diag panic] present: %s (size=%lld, mode=%o)",
                panic_paths[i], (long long)st.st_size, st.st_mode);
            found = 1;
        }
    }
    if (!found)
        nk_log("[diag panic] no panic artifacts accessible from app sandbox");
    return found;
}

void nk_canary_stamp(void *buf, size_t size) {
    if (!buf || size < sizeof(nk_canary_t) + 16) return;
    nk_canary_t *c = (nk_canary_t *)buf;
    uint64_t seq = nk_diag_seq_next();
    uintptr_t tid = (uintptr_t)pthread_self();
    c->magic = NK_CANARY_MAGIC;
    c->epoch = g_epoch;
    c->tid = (uint32_t)(tid ^ (tid >> 32));
    c->pad = 0;
    c->seq = seq;
    c->size = size;
    c->pattern = 0xA500000000000000ULL ^ (seq * 0x9E3779B97F4A7C15ULL);

    uint8_t *body = (uint8_t *)buf + sizeof(nk_canary_t);
    size_t body_len = size - sizeof(nk_canary_t);
    uint64_t *w = (uint64_t *)body;
    for (size_t i = 0; i + 8 <= body_len; i += 8)
        w[i / 8] = c->pattern ^ (uint64_t)i;
    for (size_t i = body_len & ~7ULL; i < body_len; i++)
        body[i] = (uint8_t)(c->pattern >> (8 * (i & 7)));

    c->crc = nk_crc32(body, body_len);
}

nk_canary_result_t nk_canary_check(const void *buf, size_t size,
    uint32_t *foreign_epoch, uint64_t *foreign_seq, uint32_t *foreign_tid) {
    if (!buf || size < sizeof(nk_canary_t) + 16) return NK_CAN_MISS;
    const nk_canary_t *c = (const nk_canary_t *)buf;
    if (c->magic != NK_CANARY_MAGIC) return NK_CAN_MISS;

    const uint8_t *body = (const uint8_t *)buf + sizeof(nk_canary_t);
    size_t body_len = size - sizeof(nk_canary_t);
    uint32_t crc = nk_crc32(body, body_len);

    if (c->crc != crc) {
        if (c->epoch != g_epoch) return NK_CAN_STALE;
        return NK_CAN_BADCRC;
    }
    if (c->epoch != g_epoch) {
        if (foreign_epoch) *foreign_epoch = c->epoch;
        if (foreign_seq) *foreign_seq = c->seq;
        if (foreign_tid) *foreign_tid = c->tid;
        return NK_CAN_FOREIGN;
    }
    return NK_CAN_OK;
}

void nk_diag_event(const char *module, const char *kind, const char *fmt, ...) {
    char detail[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    char line[512];
    int n = snprintf(line, sizeof(line),
        "{\"ts\":%ld.%06ld,\"epoch\":%u,\"boot\":%u,\"module\":\"%s\","
        "\"kind\":\"%s\",\"detail\":\"%s\"}\n",
        (long)tv.tv_sec, (long)tv.tv_usec, g_epoch, g_boot_epoch,
        module, kind, detail);
    if (n <= 0) return;

    pthread_mutex_lock(&g_ev_lock);
    if (g_ev_ready) {
        int fd = open(nk_diag_log_path(), O_WRONLY | O_APPEND);
        if (fd >= 0) {
            if (write(fd, line, (size_t)n) < 0) {}
            close(fd);
        }
    }
    snprintf(g_ring[g_ring_idx], sizeof(g_ring[0]), "%s", line);
    g_ring_idx = (g_ring_idx + 1) % NK_EVENT_RING;
    pthread_mutex_unlock(&g_ev_lock);

    nk_log("[jsonl %s/%s] %s", module, kind, detail);
}

void nk_diag_ring_dump(void) {
    pthread_mutex_lock(&g_ev_lock);
    nk_log("[diag] ring dump (last %d events)", NK_EVENT_RING);
    for (int i = 0; i < NK_EVENT_RING; i++) {
        int idx = (g_ring_idx + i) % NK_EVENT_RING;
        if (g_ring[idx][0]) nk_log("  %s", g_ring[idx]);
    }
    pthread_mutex_unlock(&g_ev_lock);
}

void nk_diag_counts(nk_triage_t cls) {
    if (cls <= NK_P3_NOISE) g_cls_counts[cls]++;
}

void nk_diag_anomaly(nk_triage_t cls, const char *module,
    const char *detail_fmt, ...) {
    char detail[256];
    va_list ap;
    va_start(ap, detail_fmt);
    vsnprintf(detail, sizeof(detail), detail_fmt, ap);
    va_end(ap);
    g_cls_counts[cls > NK_P3_NOISE ? NK_P3_NOISE : cls]++;
    nk_diag_event(module, cls == NK_P0_REPRO_CONTROLLED ? "P0"
        : cls == NK_P1_DEFECT_NO_CONTROL ? "P1"
        : cls == NK_P2_RARE_PANIC ? "P2" : "P3",
        "%s", detail);
}

int nk_diag_stop_after_same_crash(const char *tag) {
    uint32_t now = nk_diag_boot_epoch();
    if (g_crash_epoch == 0) g_crash_epoch = now;
    if (now != g_crash_epoch) {
        if (g_crash_tag[0] && strcmp(g_crash_tag, tag ? tag : "") == 0)
            return 1;
        snprintf(g_crash_tag, sizeof(g_crash_tag), "%s", tag ? tag : "");
        g_crash_epoch = now;
    }
    return 0;
}
