/* iogpu_probe2.m — IOGPUFamily 129.3.2 (iOS 26.2 / 23C55) targeted row-dispatch probe.
   Static ground truth (host disasm, hunt/):
     - structured path: sel24..59 with inStruct >= 88 escapes to
       bl 0xfffffff009f56df4 (IOGPUResource::newResourceGroup) at 0xfffffff009f542f0.
     - row-walker engine fn 0xfffffff009f56cc8 — cmp w1,#55 /
       cmp w2,#13 selector gates over 24-byte-strided method rows.
   Device plan (watchdog-safe, per iogpu_oob.m note):
     - IOGPU service only, types 1..33, per-conn ZERO sweep sel 0..127;
     - type-1 conn additionally: STRC 116B (sel 0..127), SCAL scalar 0..64
       (full sel 0..127 — covers row-walker w1 gate 0..55 via sel41/sel48),
       SCST scalar 0..15 + 116B struct (sel 24..59).
     - yields every ~256 calls so LiveContainer's watchdog stays quiet.
   A hit prints one log line: kind / type / sel / scal / kr / out0 / out1. */
#import <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"

#define ol(fmt, ...) nk_log(fmt, ##__VA_ARGS__)

static int known_fail(kern_return_t kr) {
    return kr == KERN_SUCCESS
        || kr == (kern_return_t)KERN_FAILURE
        || kr == (kern_return_t)0x10000003  /* MACH_SEND_INVALID_DEST */
        || kr == (kern_return_t)0x2c2       /* resource miss */
        || kr == (kern_return_t)0x2be;
}

static uint32_t s_ops = 0;

static inline void yield_now(void) {
    if (++s_ops % 256 == 0) usleep(50);
}

static void probe_io(io_connect_t conn, const char *name, uint32_t t) {
    uint32_t sel;
    uint32_t on;
    uint64_t sc[2];
    uint64_t out[8];
    uint8_t inp[116];
    kern_return_t kr;

    /* ZERO — plain zero-arg call, catches any plain create+return point */
    for (sel = 0; sel < 128; sel++) {
        on = 8; memset(out, 0, sizeof(out));
        kr = IOConnectCallMethod(conn, sel, NULL, 0, NULL, 0, out, &on, NULL, NULL);
        yield_now();
        if (!known_fail(kr)) {
            ol("[probe2] ZERO HIT type=%2u sel=%3u kr=0x%x out_n=%u out0=%llx out1=%llx",
               t, sel, kr, on,
               (unsigned long long)out[0], on > 1 ? (unsigned long long)out[1] : 0ULL);
        }
    }

    if (t != 1) return;   /* deep passes only on the device-userclient type */

    /* STRC — structured 116 B zero payload, covers the >=88 family */
    for (sel = 0; sel < 128; sel++) {
        size_t sz = 8;
        on = 8; memset(out, 0, sizeof(out)); memset(inp, 0, sizeof(inp));
        kr = IOConnectCallStructMethod(conn, sel, inp, sizeof(inp), out, &sz);
        yield_now();
        if (!known_fail(kr)) {
            ol("[probe2] STRC HIT type=%2u sel=%3u kr=0x%x out_n=%zu out0=%llx out1=%llx",
               t, sel, kr, sz,
               (unsigned long long)out[0], sz > 1 ? (unsigned long long)out[1] : 0ULL);
        }
    }

    /* SCAL — scalarInput[0] = row-walker sub-index w1 (gate cmp w1,#55).
       sel41 (0x9f54f8c) / sel48 (0x9f55864) are the openable type-1 rows
       feeding the walker: ldr w1,[x2,#32][0] — first scalar arg. w1 0..64
       covers the whole hidden 24-byte-strided row table incl. the row that
       reaches o2_s21 (0x9f56830) -> bl 0x9f60a84 newResourceGroup. */
    for (sel = 0; sel < 128; sel++) {
        for (uint64_t s = 0; s < 65; s++) {
            on = 8; memset(out, 0, sizeof(out)); sc[0] = s; sc[1] = 0;
            kr = IOConnectCallMethod(conn, sel, sc, 1, NULL, 0, out, &on, NULL, NULL);
            yield_now();
            if (!known_fail(kr)) {
                ol("[probe2] SCAL HIT type=%2u sel=%3u scal=%llu kr=0x%x out_n=%u out0=%llx out1=%llx",
                   t, sel, (unsigned long long)s, kr, on,
                   (unsigned long long)out[0], on > 1 ? (unsigned long long)out[1] : 0ULL);
            }
        }
    }

    /* SCST — scalar 0..15 + 116 B struct on sel 24..59 (structured family) */
    for (sel = 24; sel < 60; sel++) {
        for (uint64_t s = 0; s < 16; s++) {
            on = 8; memset(out, 0, sizeof(out)); memset(inp, 0, sizeof(inp));
            sc[0] = s; sc[1] = 0;
            kr = IOConnectCallMethod(conn, sel, sc, 1, inp, sizeof(inp), out, &on, NULL, NULL);
            yield_now();
            if (!known_fail(kr)) {
                ol("[probe2] SCST HIT type=%2u sel=%3u scal=%llu kr=0x%x out_n=%u out0=%llx out1=%llx",
                   t, sel, (unsigned long long)s, kr, on,
                   (unsigned long long)out[0], on > 1 ? (unsigned long long)out[1] : 0ULL);
            }
        }
    }
}

void nk_iogpu_probe2_run(void) {
    io_iterator_t it = 0;
    io_service_t svc;
    io_name_t name;
    kern_return_t kr;
    uint32_t opened = 0;

    kr = IOServiceGetMatchingServices(kIOMasterPortDefault,
                                      IOServiceMatching("IOGPU"), &it);
    if (kr != KERN_SUCCESS) {
        ol("[probe2] IOGPU enum failed kr=0x%x", kr);
        return;
    }
    ol("[probe2] IOGPU service found, probing types 1..33");

    while ((svc = IOIteratorNext(it))) {
        IORegistryEntryGetName(svc, name);
        for (uint32_t t = 1; t <= 33; t++) {
            io_connect_t conn = MACH_PORT_NULL;
            kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
            if (kr != KERN_SUCCESS || !conn) {
                if (t <= 6 || t == 33)
                    ol("[probe2] type=%u open kr=0x%x", t, kr);
                continue;
            }
            ol("[probe2] type=%u OPENED conn=0x%x", t, conn);
            opened++;
            probe_io(conn, name, t);
            IOServiceClose(conn);
        }
        IOObjectRelease(svc);
        svc = 0;
    }
    IOObjectRelease(it);
    ol("[probe2] done opened=%u ops=%u", opened, s_ops);
}
