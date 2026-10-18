/* iomfb_probe_v2.m — IOMFB UserClient per-selector shape profiler.
   (iOS 26.2 / 23C55, iPhone14,5-A15, non-WebKit lane.)
   Device map (iomfb_20261018-114122.log): IOMobileFramebuffer t0:
   SCAL s83 -> 0xe00002c1 (bad-arg, arg-validation handler),
   SCAL s93..s127 -> 0xe0000001 (kIOReturnError) = 35 consecutive live
   handlers that fail only on our dummy shapes; sels 0..82 + 84..92 noise.
   Goal of v2: recover each live selector's call shape from the INSIDE:
     - scalar arity: nIn {0,1,2,3,4,5,6,8} (out 8 scalars fixed);
     - structure size: {8,16,24,32,48,64,96,112,128,192,256}
       (buffer = 0xAA first half / zeros second half, fixed);
     - kr transition points fingerprint: shapeSize / arg-check.
   Type 0 gets the FULL profile (646 ops); types 1..15 triage-only
   (SCAL n2 + STRC sz64 on the live pool) to catch per-type variation. */
#import <IOKit/IOKitLib.h>
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include "exploit.h"

#define mlv2(fmt, ...) nk_log(fmt, ##__VA_ARGS__)

static const uint32_t LIVE_SELS[36] = {
    83, 93, 94, 95, 96, 97, 98, 99, 100,
    101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
    111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
    121, 122, 123, 124, 125, 126, 127
};
#define LIVE_N 36

static void yield2(void) { usleep(40000); }

static void buf_make(uint8_t *b, size_t sz) {
    memset(b, 0xAA, sz);
    if (sz >= 2) memset(b + sz/2, 0x00, sz - sz/2);
}

static void scal_profile(io_connect_t c, uint32_t sel, char *vec, size_t cap) {
    static const uint32_t counts[8] = { 0, 1, 2, 3, 4, 5, 6, 8 };
    vec[0] = 0;
    size_t used = 0;
    for (unsigned i = 0; i < 8; i++) {
        uint64_t in[8];
        uint32_t n = counts[i];
        for (uint32_t j = 0; j < n; j++) in[j] = 0x11 + j;
        uint64_t out[8]; uint32_t oc = 8;
        kern_return_t kr = IOConnectCallMethod(
            c, sel, n ? in : NULL, n, NULL, 0, out, &oc, NULL, NULL);
        int written = snprintf(vec + used, cap - used,
                               "%s%x", i ? "," : "0x", kr);
        if (written > 0 && (size_t)written < cap - used) used += written;
    }
}

static void strc_profile(io_connect_t c, uint32_t sel, char *vec, size_t cap) {
    static const size_t sizes[11] = {
        8, 16, 24, 32, 48, 64, 96, 112, 128, 192, 256
    };
    uint8_t inbuf[256], outbuf[256];
    vec[0] = 0;
    size_t used = 0;
    for (unsigned i = 0; i < 11; i++) {
        size_t sz = sizes[i];
        buf_make(inbuf, sz);
        size_t osz = sizeof(outbuf);
        bzero(outbuf, sizeof(outbuf));
        kern_return_t kr = IOConnectCallStructMethod(
            c, sel, inbuf, sz, outbuf, &osz);
        int written = snprintf(vec + used, cap - used,
                               "%s%x", i ? "," : "0x", kr);
        if (written > 0 && (size_t)written < cap - used) used += written;
    }
}

void nk_iomfb_v2_run(void) {
    nk_filelog_open("iomsel");
    nk_log("[iomsel] v2 session start (live-pool shape profiler)");
    CFMutableDictionaryRef md = IOServiceMatching("IOMobileFramebuffer");
    if (!md) { nk_log("[iomsel] no matching dict"); nk_filelog_close(); return; }
    io_iterator_t it = 0;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, md, &it);
    if (kr != KERN_SUCCESS) {
        nk_log("[iomsel] match kr=0x%x", kr);
        nk_filelog_close(); return;
    }
    io_object_t svc;
    int si = 0;
    uint32_t ops = 0;
    char vec[512];
    while ((svc = IOIteratorNext(it)) && si < 3) {
        si++;
        for (uint32_t ty = 0; ty < 16; ty++) {
            io_connect_t c = 0;
            kern_return_t okr = IOServiceOpen(svc, mach_task_self(), ty, &c);
            if (okr != KERN_SUCCESS) { yield2(); continue; }
            mlv2("[iomsel] open SVC%d t%u", si, ty);
            sleep(2);
            for (unsigned k = 0; k < LIVE_N; k++) {
                uint32_t sel = LIVE_SELS[k];
                if (ty == 0) {
                    scal_profile(c, sel, vec, sizeof(vec));
                    ops += 8;
                    mlv2("[iomsel] t%u s%u SCAL: %s", ty, sel, vec);
                    strc_profile(c, sel, vec, sizeof(vec));
                    ops += 11;
                    mlv2("[iomsel] t%u s%u STRC: %s", ty, sel, vec);
                } else {
                    uint64_t in[2] = { 0x11, 0x12 };
                    uint64_t out[8]; uint32_t oc = 8;
                    kern_return_t k1 = IOConnectCallMethod(
                        c, sel, in, 2, NULL, 0, out, &oc, NULL, NULL);
                    uint8_t inbuf[64], outbuf[256];
                    buf_make(inbuf, 64);
                    size_t osz = sizeof(outbuf);
                    bzero(outbuf, sizeof(outbuf));
                    kern_return_t k2 = IOConnectCallStructMethod(
                        c, sel, inbuf, 64, outbuf, &osz);
                    ops += 2;
                    mlv2("[iomsel] t%u s%u triage sc=0x%x st=0x%x",
                         ty, sel, k1, k2);
                }
                if ((ops & 0xff) == 0) yield2();
            }
            yield2();
            IOServiceClose(c);
            sleep(2);
        }
        IOObjectRelease(svc);
        sleep(3);
    }
    IOObjectRelease(it);
    nk_log("[iomsel] v2 end services=%d ops=%u crk-vecs per sel above", si, ops);
    nk_filelog_close();
}
