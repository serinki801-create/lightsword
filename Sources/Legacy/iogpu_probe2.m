/* iogpu_probe2.m — IOGPUFamily 129.3.2 (iOS 26.2 / 23C55) targeted row-dispatch probe.
   Static ground truth (host disasm, hunt/):
     - structured path: sel24..59 with inStruct >= 88 escapes to
       bl 0xfffffff009f56df4 (IOGPUResource::newResourceGroup) at 0xfffffff009f542f0.
     - row-walker engine fn 0xfffffff009f56cc8 — cmp w1,#55 /
       cmp w2,#13 selector gates over 24-byte-strided method rows.
   Device plan (watchdog-safe):
     - families: IOGPU + AGXAccelerator/IOAccelerator/IOGraphicsControl/
       IOGPUDevice; every OPENED conn gets ZERO sweep, type-1 conns of
       any family get the full deep pass (STRC/SCAL/W12/SW2/SCST);
     - known_fail masks wire codes 0xe00002c2/0xe00002c7/0xe00002be,
       so ONLY true anomalies print;
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
        || kr == (kern_return_t)0xe00002c7  /* kIOReturnUnsupported (wire) */
        || kr == (kern_return_t)0xe00002c2  /* walker/misser 706 (wire) */
        || kr == (kern_return_t)0xe00002be
        || kr == (kern_return_t)0x2c2       /* legacy low forms */
        || kr == (kern_return_t)0x2be
        || kr == (kern_return_t)0x2c7;
}

static uint32_t s_ops = 0;

static inline void yield_now(void) {
    if (++s_ops % 256 == 0) usleep(50);
}

static void probe_io(io_connect_t conn, const char *name, uint32_t t, int deep) {
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

    if (!deep) return;   /* deep passes on the type-1 client of any family */

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

    /* W12 — two-scalar (w1,w2) combo across the row-walker callers.
       Gates statically: cmp w1,#55 / cmp w2,#13 (fn 0x9f56cc8).
       Covers the full hidden row space 56x14 that the single-scalar
       passes kept pinned at w2=0. sel41 / sel48 reach the engine from
       the openable type-1 table. */
    {
        const uint32_t wsel[2] = { 41, 48 };
        for (unsigned k = 0; k < 2; k++) {
            for (uint64_t w1 = 0; w1 < 56; w1++) {
                for (uint64_t w2 = 0; w2 < 14; w2++) {
                    on = 8; memset(out, 0, sizeof(out));
                    sc[0] = w1; sc[1] = w2;
                    kr = IOConnectCallMethod(conn, wsel[k], sc, 2, NULL, 0, out, &on, NULL, NULL);
                    yield_now();
                    if (!known_fail(kr)) {
                        ol("[probe2] W12 HIT type=%2u sel=%3u w1=%llu w2=%llu kr=0x%x out_n=%u out0=%llx out1=%llx",
                           t, wsel[k], (unsigned long long)w1, (unsigned long long)w2, kr, on,
                           (unsigned long long)out[0], on > 1 ? (unsigned long long)out[1] : 0ULL);
                    }
                }
            }
        }
    }

    /* SW2 — walker second index via structureInput[0].
       Statics only pin w1 = scalarInput[0]; w2's slot is unconfirmed
       (scalar[1] or struct head). Covers the struct-slot dimension
       the W12 pass cannot. inp[0..3] = LE u32 w2, rest zero. */
    {
        const uint32_t wsel[2] = { 41, 48 };
        for (unsigned k = 0; k < 2; k++) {
            for (uint64_t w1 = 0; w1 < 56; w1++) {
                for (uint64_t w2 = 0; w2 < 14; w2++) {
                    uint32_t wv = (uint32_t)w2;
                    size_t sz = 8;
                    memset(inp, 0, sizeof(inp));
                    memcpy(inp, &wv, sizeof(wv));
                    on = 8; memset(out, 0, sizeof(out)); sc[0] = w1; sc[1] = 0;
                    kr = IOConnectCallStructMethod(conn, wsel[k], inp, sizeof(inp), out, &sz);
                    yield_now();
                    if (!known_fail(kr)) {
                        ol("[probe2] SW2 HIT type=%2u sel=%3u w1=%llu w2=%llu kr=0x%x out0=%llx",
                           t, wsel[k], (unsigned long long)w1, (unsigned long long)w2, kr,
                           (unsigned long long)out[0]);
                    }
                }
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

/* Family sweep — the o2 (28-row) / engine-call surface may belong to a sibling
   driver class (AGX*), not the IOGPU entry point. Names of families with
   user-client tables on 23C55; unknown names cost one IOServiceGetMatchingServices
   call each and return 0 services — harmless. */
static const char *s_families[] = {
    "IOGPU",
    "AGXAccelerator",
    "IOAccelerator",
    "IOGraphicsControl",
    "IOGPUDevice"
};
#define NFAM ((int)(sizeof(s_families) / sizeof(s_families[0])))

void nk_iogpu_probe2_run(void) {
    io_iterator_t it = 0;
    io_service_t svc;
    io_name_t name;
    kern_return_t kr;
    uint32_t opened = 0;

    for (int fam = 0; fam < NFAM; fam++) {
        kr = IOServiceGetMatchingServices(kIOMasterPortDefault,
                                          IOServiceMatching(s_families[fam]), &it);
        if (kr != KERN_SUCCESS) {
            ol("[probe2] %s enum failed kr=0x%x", s_families[fam], kr);
            continue;
        }
        uint32_t found = 0;
        while ((svc = IOIteratorNext(it))) {
            IORegistryEntryGetName(svc, name);
            found++;
            /* IOGPU keeps its legacy deep passes; siblings get ZERO+W12 */
            int is_iogpu = (fam == 0);
            for (uint32_t t = (is_iogpu ? 1 : 0); t <= 40; t++) {
                io_connect_t conn = MACH_PORT_NULL;
                kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
                if (kr != KERN_SUCCESS || !conn) {
                    if (t == 0 || (is_iogpu && (t <= 6 || t == 33)))
                        ol("[probe2] %s type=%u open kr=0x%x", s_families[fam], t, kr);
                    continue;
                }
                ol("[probe2] %s type=%u OPENED conn=0x%x", s_families[fam], t, conn);
                opened++;
                probe_io(conn, name, t, t == 1);
                IOServiceClose(conn);
            }
            IOObjectRelease(svc);
            svc = 0;
        }
        IOObjectRelease(it);
        it = 0;
        ol("[probe2] family %s found=%u", s_families[fam], found);
    }
    ol("[probe2] done opened=%u ops=%u", opened, s_ops);
}
