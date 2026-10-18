/* iomfb_probe.m — IOMobileFramebuffer service deep surface probe
   (iOS 26.2 / 23C55, iPhone14,5-A15, no-WebKit lane).
   Device fact (surface scan 11:28): IOMobileFramebuffer[1] opens ALL 16 user
   client types from the sandbox; 3072 shallow calls returned noise — the
   service lives past sel47. The kext is AppleMobileDispH14P-DCP (DCP display
   pipe on A15) whose rich user surface is structured-input driven.
   Plan (watchdog-safe):
     1) open types 0..15 of every IOMobileFramebuffer service;
     2) per conn: FULL scalar sweep sel 0..127 × v0..3;
     3) per conn: structured sweep sel 24..127 × sizes {8, 64, 112, 192}
        (fixed pattern body = 0xAA / zeros split by half);
     4) probe both va and vb call shapes; record every non-noise kr;
     5) classify known-noise like probe2.      */
#import <IOKit/IOKitLib.h>
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include "exploit.h"

#define mlg(fmt, ...) nk_log(fmt, ##__VA_ARGS__)

static int noise(kern_return_t kr) {
    return kr == KERN_SUCCESS
        || kr == (kern_return_t)KERN_FAILURE
        || kr == (kern_return_t)0x10000003
        || kr == (kern_return_t)0xe00002c7
        || kr == (kern_return_t)0xe00002c2
        || kr == (kern_return_t)0xe00002be
        || kr == (kern_return_t)0xe00002e2
        || kr == (kern_return_t)0x2c2
        || kr == (kern_return_t)0x2be;
}

static void yield_now(void) { usleep(40000); }

static void sweep_conn_scalar(io_connect_t c, int si, int ty, uint32_t *ops) {
    for (uint32_t sel = 0; sel < 128; sel++) {
        for (uint32_t v = 0; v < 4; v++) {
            uint64_t sc = v, rc = 0;
            uint32_t rcnt = 1;
            kern_return_t kr = IOConnectCallMethod(
                c, sel, &sc, 1, NULL, 0, &rc, &rcnt, NULL, NULL);
            (*ops)++;
            if (!noise(kr))
                mlg("[mfb] SVC%d t%d SCAL s%u v%u kr=0x%x out=%llx",
                    si, ty, sel, v, kr, (unsigned long long)rc);
            if (((*ops) & 0xff) == 0) yield_now();
        }
    }
}

static void sweep_conn_struct(io_connect_t c, int si, int ty, uint32_t *ops) {
    static const size_t sizes[4] = { 8, 64, 112, 192 };
    for (unsigned szi = 0; szi < 4; szi++) {
        size_t sz = sizes[szi];
        uint8_t in[192];
        memset(in, 0xAA, sizeof(in));
        memset(in + sz/2, 0x00, sz/2);
        for (uint32_t sel = 24; sel < 128; sel++) {
            uint8_t out[256];
            size_t osz = sizeof(out);
            bzero(out, sizeof(out));
            kern_return_t kr = IOConnectCallStructMethod(
                c, sel, in, sz, out, &osz);
            (*ops)++;
            if (!noise(kr))
                mlg("[mfb] SVC%d t%d STRC s%u sz%zu kr=0x%x osz=%zu",
                    si, ty, sel, sz, kr, osz);
            if (((*ops) & 0xff) == 0) yield_now();
        }
    }
}

void nk_iomfb_deep_run(void) {
    nk_filelog_open("iomfb");
    nk_log("[mfb] session start");
    CFMutableDictionaryRef md = IOServiceMatching("IOMobileFramebuffer");
    if (!md) { nk_log("[mfb] no matching dict"); nk_filelog_close(); return; }
    io_iterator_t it = 0;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, md, &it);
    if (kr != KERN_SUCCESS) { nk_log("[mfb] match kr=0x%x", kr); nk_filelog_close(); return; }
    io_object_t svc;
    int si = 0;
    uint32_t ops = 0, opens = 0;
    while ((svc = IOIteratorNext(it) ) && si < 6) {
        si++;
        for (uint32_t ty = 0; ty < 16; ty++) {
            io_connect_t c = 0;
            kern_return_t okr = IOServiceOpen(svc, mach_task_self(), ty, &c);
            if (okr != KERN_SUCCESS) { yield_now(); continue; }
            opens++;
            mlg("[mfb] open SVC%d t%u ok", si, ty);
            sleep(2);
            uint32_t before = ops;
            sweep_conn_scalar(c, si, ty, &ops);
            sleep(2);
            sweep_conn_struct(c, si, ty, &ops);
            mlg("[mfb] SVC%d t%u batch ops=%u (accum %u)", si, ty, ops - before, ops);
            IOServiceClose(c);
            sleep(2);
        }
        IOObjectRelease(svc);
        sleep(3);
    }
    IOObjectRelease(it);
    nk_log("[mfb] session end services=%d opens=%u ops=%u",
           si, opens, ops);
    nk_log("[mfb] NOTE: anomalies print per line ('[mfb] SCAL/STRC' rows)");
    nk_filelog_close();
}
