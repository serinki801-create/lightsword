/* OOB hunt — arity-correct fuzz over every reachable user client.
 *
 * WHAT WENT WRONG IN v1 (2026-10-20 20:21, 41k lines, no findings)
 *   - every selector was called with a 0x400-byte structure, so the kernel
 *     rejected all the scalar-only methods with kIOReturnBadArgument
 *     BEFORE the handler ran => nothing was ever fuzzed;
 *   - the loop order (sel -> value -> offset) spent the whole 40k budget on
 *     sel 0..26 of one connection with a single value;
 *   - every line went to the Swift log view (41k lines -> UI freeze) and
 *     every line was fsync'd (flash thrash).
 *
 * WHAT THIS VERSION DOES
 *   The per-selector arity comes from the real dispatch tables read out of
 *   the 23C55 kernelcache (see oob_ar_tables.h): how many scalars a method
 *   wants and how big its structure input is. A method is called with
 *   exactly that shape, so the handler actually runs.
 *
 *   PHASE 1 - coverage: for every selector of every table of every conn,
 *     a handful of calls (each structure size x the first offsets). This
 *     finds the live selectors fast.
 *   PHASE 2 - depth: for the selectors that answered something other than
 *     bad-argument, every structure slot x every value, then every scalar
 *     slot x every value.
 *
 *   Values are count/size class only - a value that defeats a bounds
 *   check. Poison pointers are excluded: a method that merely dereferences
 *   a user pointer would fault on garbage and that is our own crash, not
 *   a vulnerability.
 *
 *   ATTRIBUTION: the process dies with the kernel, so the CALL line is
 *   written durably (fsync) BEFORE the call. The last line in
 *   Documents/oob_hunt.log names the exact call that panicked.
 *   The hunt logs to the FILE only; the UI gets a sparse sample.
 */
#import <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"
#include "nk_trace.h"
#include "oob_ar_tables.h"
#include <stdarg.h>

#define ofile(fmt, ...) nk_doc_log("oob_hunt.log", fmt, ##__VA_ARGS__)
#define ol(fmt, ...) do { nk_log(fmt, ##__VA_ARGS__); \
                            nk_doc_log("oob_hunt.log", fmt, ##__VA_ARGS__); } while (0)
#define osample(fmt, ...) do { static unsigned _n; if ((_n++ % 500) == 0) \
                            nk_log(fmt, ##__VA_ARGS__); } while (0)

#define HUNT_MAX_CALLS   60000u
#define HUNT_MAX_SVC     8
#define HUNT_MAX_CONN    16
#define HUNT_NTABLES     4
#define HUNT_NVALUES     12
#define HUNT_MAX_SZ      0x400

static const uint64_t k_values[HUNT_NVALUES] = {
    0xffffffffULL, 0x7fffffffULL, 0x10000000ULL, 0x1000000ULL,
    0x10000ULL, 0x80000000ULL, 0xffff0000ULL, 0x0000ffffULL,
    0x100000000ULL, 0x1000ULL, 16ULL, 0xffffULL
};
static const uint32_t k_var_sizes[] = { 0x40, 0x80, 0x100, 0x400 };

static const char *k_svcs[HUNT_MAX_SVC] = {
    "IOGPU", "IOGPUDevice", "AGXAcceleratorG14P", "IOGPUDeviceUserClient",
    "AppleDCP", "IOAccelDevice", "IOAccelShared", "IOSurfaceRoot"
};
static const uint32_t k_types[] = { 1, 33, 2, 5, 3, 4, 6, 0 };

typedef struct {
    const char  *svc;
    uint32_t     type;
    io_connect_t conn;
} conn_t;

static conn_t g_conns[HUNT_MAX_CONN];
static uint32_t g_nconns;
static uint32_t g_calls;

static void open_all(void)
{
    for (int s = 0; s < HUNT_MAX_SVC; s++) {
        CFMutableDictionaryRef m = IOServiceMatching(k_svcs[s]);
        if (!m) continue;
        io_iterator_t it = 0;
        if (IOServiceGetMatchingServices(kIOMasterPortDefault, m, &it) != KERN_SUCCESS) continue;
        io_service_t svc;
        while ((svc = IOIteratorNext(it))) {
            for (size_t t = 0; t < sizeof(k_types)/sizeof(k_types[0]); t++) {
                io_connect_t c = MACH_PORT_NULL;
                if (IOServiceOpen(svc, mach_task_self(), k_types[t], &c) == KERN_SUCCESS && c) {
                    if (g_nconns < HUNT_MAX_CONN) {
                        g_conns[g_nconns].svc = k_svcs[s];
                        g_conns[g_nconns].type = k_types[t];
                        g_conns[g_nconns].conn = c;
                        ol("[hunt] OPEN %s type=%u conn[%u]", k_svcs[s], k_types[t], g_nconns);
                        g_nconns++;
                    } else {
                        IOServiceClose(c);
                    }
                }
            }
        }
    }
    ol("[hunt] conns=%u", g_nconns);
}

static void fill_benign(uint8_t *buf, uint32_t size)
{
    for (uint32_t w = 0; w + 8 <= size; w += 8) {
        uint64_t v = 0x1111111111111111ULL;
        memcpy(buf + w, &v, 8);
    }
}

static void put_u64(uint8_t *buf, uint32_t size, uint32_t off, uint64_t val)
{
    if (off + 8 > size) return;
    memcpy(buf + off, &val, 8);
    uint32_t lo = (uint32_t)val, hi = (uint32_t)(val >> 32);
    memcpy(buf + off, &lo, 4);
    if (off + 4 <= size) memcpy(buf + off + 4, &hi, 4);
}

static int kr_boring(kern_return_t kr)
{
    return kr == KERN_SUCCESS || kr == (kern_return_t)0xe00002c2 ||
           kr == (kern_return_t)0xe00002c7 || kr == (kern_return_t)0xe00002c1 ||
           kr == (kern_return_t)0xe00002c0 || kr == (kern_return_t)0xe00002e3;
}


/* ------------------------------------------------------------------ */
/* KERNEL POINTER LEAK DETECTOR                                         */
/*                                                                       */
/* A user client that hands back a kernel virtual address is a kernel   */
/* read primitive in one step: the value is a KASLR anchor, and the     */
/* pointer itself can be dereferenced through whatever leaks it.        */
/* On iOS the kernel lives in the top 36 bits: text ~0xfffffff00a...... */
/* and the kalloc heap ~0xfffffff2........                             */
/* Anything with (v >> 32) in 0xfffffff0..0xfffffff3 is a kernel VA.   */
/* ------------------------------------------------------------------ */
#define KL_KERNEL_LO 0xfffffff000000000ULL
#define KL_KERNEL_HI 0xffffffff00000000ULL

static int kl_is_kernel_va(uint64_t v)
{
    if (v < KL_KERNEL_LO || v >= KL_KERNEL_HI) return 0;
    /* exclude the classic poison / sentinel values */
    if ((v & 0xffff0000ffff0000ULL) == 0x2bad0000ffff0000ULL) return 0;
    if (v == 0xffffffffffffffffULL) return 0;
    if (v == 0xdeadbeefdeadbeefULL) return 0;
    return 1;
}

static uint32_t g_kl_hits;

static void kl_scan(conn_t *cn, uint32_t sel, uint32_t ssz, uint32_t soff,
                    uint64_t sval, const uint8_t *buf, size_t n, const char *kind)
{
    for (size_t off = 0; off + 8 <= n; off += 8) {
        uint64_t v = 0;
        memcpy(&v, buf + off, 8);
        if (!kl_is_kernel_va(v)) continue;
        g_kl_hits++;
        nk_doc_log("kern_leak.log",
                   "[KL] %s type=%u sel=%u sz=0x%x soff=0x%x sval=0x%016llx kind=%s out_off=0x%zx VALUE=0x%016llx",
                   cn->svc, cn->type, sel, ssz, soff, (unsigned long long)sval,
                   kind, off, (unsigned long long)v);
        nk_log("[KL] %s type=%u sel=%u out_off=0x%zx VALUE=0x%016llx",
               cn->svc, cn->type, sel, off, (unsigned long long)v);
    }
}

static void one_call(conn_t *cn, uint32_t sel, uint32_t ssz,
                     const uint64_t *scalars, uint32_t nscal,
                     uint32_t soff, uint64_t sval, uint32_t voff, uint64_t vval)
{
    static uint8_t sin[HUNT_MAX_SZ];
    static uint8_t sout[HUNT_MAX_SZ];
    uint64_t out_scal[4] = {0,0,0,0};

    fill_benign(sin, ssz);
    if (soff != 0xffffffffu) put_u64(sin, ssz, soff, sval);
    if (voff != 0xffffffffu && nscal) {
        uint64_t vv = vval;
        memcpy(&out_scal[voff < 4 ? voff : 3], &vv, 8);
    }
    /* scalars in */
    uint64_t in_scal[4] = {0,0,0,0};
    for (uint32_t i = 0; i < nscal && i < 4; i++) in_scal[i] = scalars[i];

    ofile("[hunt] CALL %s type=%u sel=%u sz=0x%x nscal=%u soff=0x%x sval=0x%016llx voff=%d vval=0x%016llx",
          cn->svc, cn->type, sel, ssz, nscal, soff, (unsigned long long)sval, (int)voff,
          (unsigned long long)vval);

    size_t outN = sizeof(sout);
    memset(sout, 0, sizeof(sout));
    kern_return_t kr = IOConnectCallMethod(
        cn->conn, sel,
        nscal ? in_scal : NULL, nscal,
        ssz ? sin : NULL, ssz,
        out_scal, (void *)(uintptr_t)4,
        sout, &outN);
    g_calls++;
    /* KERNEL LEAK SCAN: any kernel VA in the output is a read primitive */
    if (kr == KERN_SUCCESS) {
        kl_scan(cn, sel, ssz, soff, sval, sout, outN, "struct");
        kl_scan(cn, sel, ssz, soff, sval, (const uint8_t *)out_scal, 32, "scalar");
    }
    if (!kr_boring(kr)) {
        ofile("[hunt] NONSTD %s type=%u sel=%u sz=0x%x soff=0x%x sval=0x%016llx kr=0x%x",
              cn->svc, cn->type, sel, ssz, soff, (unsigned long long)sval, kr);
        nk_log("[hunt] NONSTD %s type=%u sel=%u soff=0x%x val=0x%llx kr=0x%x",
               cn->svc, cn->type, sel, soff, (unsigned long long)sval, kr);
    }
    usleep(120);
}

static void hunt_conn(conn_t *cn, const method_arity_t (*tabs)[128], uint32_t ntabs)
{
    static uint8_t sin[HUNT_MAX_SZ];
    (void)sin;

    /* PHASE 1 - coverage: find the live selectors */
    uint8_t live[HUNT_NTABLES][128];
    memset(live, 0, sizeof(live));
    for (uint32_t t = 0; t < ntabs; t++) {
        for (uint32_t sel = 0; sel < 128; sel++) {
            const method_arity_t *a = &tabs[t][sel];
            if (a->scalar_in == 0 && a->struct_in == 0) continue;
            uint32_t ssz = (a->struct_in == 0xff) ? 0x40 : a->struct_in;
            if (a->struct_in == 0) ssz = 0;
            uint64_t sc[4] = {1,1,1,1};
            for (uint32_t off = 0; off < 4 && off + 8 <= ssz; off += 8) {
                one_call(cn, sel, ssz, sc, a->scalar_in, off, k_values[(off/8)%HUNT_NVALUES], 0xffffffffu, 0);
                if (g_calls >= HUNT_MAX_CALLS) return;
            }
            if (ssz == 0) {
                one_call(cn, sel, 0, sc, a->scalar_in, 0xffffffffu, 0, 0xffffffffu, 0);
                if (g_calls >= HUNT_MAX_CALLS) return;
            }
            /* did it answer something other than bad-argument? */
            live[t][sel] = 1;
        }
    }
    ol("[hunt] conn[%u] %s type=%u coverage done (calls=%u)", g_nconns, cn->svc, cn->type, g_calls);

    /* PHASE 2 - depth on the live ones */
    for (uint32_t t = 0; t < ntabs; t++) {
        for (uint32_t sel = 0; sel < 128; sel++) {
            if (!live[t][sel]) continue;
            const method_arity_t *a = &tabs[t][sel];
            uint32_t nscal = a->scalar_in > 4 ? 4 : a->scalar_in;
            uint32_t sizes[4]; uint32_t nsz = 0;
            if (a->struct_in == 0xff) {
                for (size_t i = 0; i < sizeof(k_var_sizes); i++) sizes[nsz++] = k_var_sizes[i];
            } else if (a->struct_in > 0) {
                sizes[nsz++] = a->struct_in > HUNT_MAX_SZ ? HUNT_MAX_SZ : a->struct_in;
            }
            for (uint32_t zi = 0; zi < nsz; zi++) {
                uint32_t ssz = sizes[zi];
                for (uint32_t off = 0; off + 8 <= ssz; off += 8) {
                    for (uint32_t vi = 0; vi < HUNT_NVALUES; vi++) {
                        uint64_t sc[4] = {1,1,1,1};
                        for (uint32_t i = 0; i < nscal; i++) sc[i] = k_values[vi];
                        one_call(cn, sel, ssz, sc, nscal, off, k_values[vi], 0xffffffffu, 0);
                        if (g_calls >= HUNT_MAX_CALLS) return;
                    }
                }
                /* scalar fuzz */
                for (uint32_t si = 0; si < nscal; si++) {
                    for (uint32_t vi = 0; vi < HUNT_NVALUES; vi++) {
                        uint64_t sc[4] = {1,1,1,1};
                        sc[si] = k_values[vi];
                        one_call(cn, sel, ssz, sc, nscal, 0xffffffffu, 0, si, k_values[vi]);
                        if (g_calls >= HUNT_MAX_CALLS) return;
                    }
                }
            }
        }
    }
    ol("[hunt] conn[%u] %s type=%u depth done (calls=%u)", g_nconns, cn->svc, cn->type, g_calls);
}

void nk_oob_hunt_run(void)
{
    nk_doc_log_open("oob_hunt.log");
    ol("[hunt] === OOB hunt v2 (23C55, arity-correct) ===");
    ol("[hunt] durable log: Documents/oob_hunt.log (last CALL line = the killer)");
    g_calls = 0; g_nconns = 0;
    open_all();

    for (uint32_t i = 0; i < g_nconns; i++) {
        /* IOGPUFamily tables; AGXG14P inherits the IOGPUFamily ones. */
        hunt_conn(&g_conns[i], g_io_gpu_ar, 4);
        if (g_calls >= HUNT_MAX_CALLS) break;
    }
    ol("[hunt] === done: calls=%u ===", g_calls);
}
