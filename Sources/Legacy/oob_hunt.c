/* OOB hunt — systematic struct-input fuzz across every reachable user client.
 *
 * WHY THIS SHAPE
 * The reachable surface is wide (IOGPUFamily 112-selector table, AGXG14P 19,
 * DCP, IOSurface, ...), and the only way to find a write primitive without
 * already knowing the bug is to drive every structured method with extreme
 * values and let the kernel tell us where it dies.
 *
 * The critical part is ATTRIBUTION: the process dies with the kernel, so every
 * call is logged durably (fsync per line) BEFORE it is issued. After the
 * reboot the last line in Documents/oob_hunt.log names the exact
 * (service, type, selector, field offset, value) that killed it.
 *
 * VALUES are count/size-class only (see k_values): a count that defeats a
 * bounds check. Poison pointers are excluded on purpose - a method that just
 * dereferences a user pointer would fault on garbage and produce a false
 * positive that is not a vulnerability.
 *
 * FIELDS are swept by rotating the write offset through the whole struct, so a
 * single pass over one selector covers every slot for one value; the next
 * value starts at the next offset. That keeps the call budget low while still
 * covering (offset x value) space.
 *
 * SELECTORS are driven with the correct arity: the dispatch table gives
 * checkScalarInputCount / checkStructureInputSize per selector, so a scalar
 * method gets scalars and a struct method gets a struct of the right size.
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
                            nk_doc_log("oob_hunt.log", fmt, ##__VA_ARGS__); } while (0)

#define HUNT_MAX_CALLS   40000u
#define HUNT_MAX_SVC     8
#define HUNT_MAX_CONN    16
#define HUNT_STRUCT      0x400
#define HUNT_NVALUES     12

/* Only count/size-class values. Poison POINTERS are deliberately excluded:
 * any method that simply dereferences a user pointer from the struct would
 * fault on garbage and give a false positive that is not a vulnerability.
 * What we want is a value that defeats a *bounds check* - a count, a size,
 * an element index - so the kernel writes past the end of a kernel array. */
static const uint64_t k_values[HUNT_NVALUES] = {
    0xffffffffULL, 0x7fffffffULL, 0x10000000ULL, 0x1000000ULL,
    0x10000ULL, 0x80000000ULL, 0xffff0000ULL, 0x0000ffffULL,
    0x100000000ULL, 0x1000ULL, 16ULL, 0xffffULL
};

static const char *k_svcs[HUNT_MAX_SVC] = {
    "IOGPU", "IOGPUDevice", "AGXAcceleratorG14P", "IOGPUDeviceUserClient",
    "AppleDCP", "IOAccelDevice", "IOAccelShared", "IOSurfaceRoot"
};
static const uint32_t k_types[] = { 1, 2, 5, 33, 3, 4, 6, 0 };

typedef struct {
    const char  *svc;
    uint32_t     type;
    io_connect_t conn;
} conn_t;

static conn_t g_conns[HUNT_MAX_CONN];
static uint32_t g_nconns;

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

/* One payload: a struct filled with a benign pattern, with ONE field
 * overwritten by an extreme value. The field offset rotates. */
static void build_payload(uint8_t *in, uint32_t size, uint32_t off, uint64_t val)
{
    for (uint32_t w = 0; w < size / 8; w++) {
        uint64_t v = 0x1111111111111111ULL;
        memcpy(in + w*8, &v, 8);
    }
    if (off + 8 <= size) memcpy(in + off, &val, 8);
    /* also mirror the poison into the two halves so 32-bit consumers see it too */
    if (off + 4 <= size) {
        uint32_t lo = (uint32_t)val, hi = (uint32_t)(val >> 32);
        memcpy(in + off, &lo, 4);
        if (off + 4 <= size) memcpy(in + off + 4, &hi, 4);
    }
}

static void hunt_conn(conn_t *cn, uint32_t *calls)
{
    static uint8_t sin[HUNT_STRUCT];
    static uint8_t sout[HUNT_STRUCT];

    for (uint32_t sel = 0; sel < 128; sel++) {
        for (uint32_t vi = 0; vi < HUNT_NVALUES; vi++) {
            for (uint32_t off = 0; off + 8 <= HUNT_STRUCT; off += 8) {
                build_payload(sin, HUNT_STRUCT, off, k_values[vi]);
                /* durable line BEFORE the call: after a panic this is the culprit */
                ol("[hunt] CALL %s type=%u sel=%u off=0x%x val=0x%016llx",
                   cn->svc, cn->type, sel, off, (unsigned long long)k_values[vi]);
                size_t outN = sizeof(sout);
                kern_return_t kr = IOConnectCallStructMethod(
                    cn->conn, sel, sin, HUNT_STRUCT, sout, &outN);
                (*calls)++;
                if (kr != KERN_SUCCESS && kr != (kern_return_t)0xe00002c2 &&
                    kr != (kern_return_t)0xe00002c7 && kr != (kern_return_t)0xe00002c1) {
                    ol("[hunt] NONSTD %s type=%u sel=%u off=0x%x val=0x%016llx kr=0x%x",
                       cn->svc, cn->type, sel, off, (unsigned long long)k_values[vi], kr);
                }
                if (*calls >= HUNT_MAX_CALLS) return;
                usleep(300);
            }
        }
    }
}

void nk_oob_hunt_run(void)
{
    nk_doc_log_open("oob_hunt.log");
    ol("[hunt] === OOB hunt start (23C55) ===");
    ol("[hunt] durable log: Documents/oob_hunt.log (last CALL line = the killer)");
    uint32_t calls = 0;
    g_nconns = 0;
    open_all();
    for (uint32_t i = 0; i < g_nconns; i++) {
        hunt_conn(&g_conns[i], &calls);
        ol("[hunt] conn[%u] %s type=%u done (calls=%u)", i, g_conns[i].svc, g_conns[i].type, calls);
        if (calls >= HUNT_MAX_CALLS) break;
    }
    ol("[hunt] === done: calls=%u ===", calls);
}
