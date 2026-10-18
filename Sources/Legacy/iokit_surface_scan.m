/* iokit_surface_scan.m — no-WebKit kernel-surface scan (iOS 26.2 / 23C55, A15).
   Rationale: GPU lanes (24257 / probe2 / 64788) proved sterile from the app
   sandbox on this build — types 2..6 do not exist, type 1/33 trap space is
   id-insensitive, and the resource conn belongs to the GPU daemon's team.
   Remaining kernel surface reachable without WebKit to enumerate:
     A) IOSurface kext trap server (direct, per-process) — prop matrix
     B) IOHIDEventSystem user client — open + zero sweep
     C) IOMobileFramebuffer / IOAccessoryManager / IOHIDDevice /
        IOAESAccelerator — open + zero sweep
   Everything is sandbox-permission measurement: a denied open is a data
   point, an opened conn with a non-noise sel is the real signal.
   Entry: nk_surface_scan_run(void). */
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include "exploit.h"

#define smsg(fmt, ...) nk_log(fmt, ##__VA_ARGS__)

static int noise(kern_return_t kr) {
    return kr == KERN_SUCCESS
        || kr == (kern_return_t)KERN_FAILURE
        || kr == (kern_return_t)0x10000003
        || kr == (kern_return_t)0xe00002c7
        || kr == (kern_return_t)0xe00002c2
        || kr == (kern_return_t)0xe00002be
        || kr == (kern_return_t)0x2c2
        || kr == (kern_return_t)0x2be;
}

static void yield_now(void) { usleep(40000); }

/* ── A. IOSurface kext trap server — direct property matrix ───────────── */
static void probe_iosurface_matrix(void) {
    smsg("[surface] A. IOSurface direct matrix");
    struct { uint32_t w, h, bpe; uint32_t fmt; const char *tag; } cases[] = {
        {0xFFFFFFFF, 1,            4, 0x42475241, "w-max"},
        {1,          0xFFFFFFFF,   4, 0x42475241, "h-max"},
        {0x80000000, 0x80000001,   4, 0x42475241, "wh-ovf"},
        {0,          1,            4, 0x42475241, "w0"},
        {1,          0,            4, 0x42475241, "h0"},
        {0,          0,            4, 0x42475241, "wh00"},
        {1,          1,            0, 0x42475241, "bpe0"},
        {1,          1, 0xFFFFFFFF,   0x42475241, "bpe-max"},
        {1,          1,            4, 0, "fmt0"},
        {1,          1,            4, 0xFFFFFFFF, "fmt-max"},
    };
    int created = 0, refused = 0;
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        NSDictionary *props = @{
            (id)kIOSurfaceWidth:            @(cases[i].w),
            (id)kIOSurfaceHeight:           @(cases[i].h),
            (id)kIOSurfaceBytesPerElement:  @(cases[i].bpe),
            (id)kIOSurfacePixelFormat:      @(cases[i].fmt),
        };
        IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)props);
        if (s) {
            created++;
            smsg("[surface] A[%s] CREATED w=%u h=%u bpe=%u alloc=%llu",
                 cases[i].tag, cases[i].w, cases[i].h, cases[i].bpe,
                 (unsigned long long)IOSurfaceGetAllocSize(s));
            CFRelease(s);
        } else {
            refused++;
            smsg("[surface] A[%s] refused w=%u h=%u bpe=%u fmt=%x (no-create)",
                 cases[i].tag, cases[i].w, cases[i].h, cases[i].bpe, cases[i].fmt);
        }
        if ((i & 3) == 3) yield_now();
    }
    smsg("[surface] A done created=%d refused=%d", created, refused);
}

/* ── B/C. Family open + zero sweep ────────────────────────────────────── */
static void probe_family(const char *cls) {
    CFMutableDictionaryRef md = IOServiceMatching(cls);
    if (!md) { smsg("[surface] %s: no matching dict", cls); return; }
    io_iterator_t it = 0;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, md, &it);
    u_int32_t ops = 0, oktypes = 0, anoms = 0;
    if (kr != KERN_SUCCESS) { smsg("[surface] %s: match kr=0x%x", cls, kr); return; }
    io_object_t svc;
    int svcn = 0;
    while ((svc = IOIteratorNext(it))) {
        svcn++;
        for (uint32_t ty = 0; ty < 16; ty++) {
            io_connect_t c = 0;
            kern_return_t okr = IOServiceOpen(svc, mach_task_self(), ty, &c);
            if (okr == KERN_SUCCESS) {
                oktypes++;
                smsg("[surface] %s[%d] type=%u OPEN", cls, svcn, ty);
                for (uint32_t sel = 0; sel < 48; sel++) {
                    for (uint32_t v = 0; v < 4; v++) {
                        uint64_t sc = v, rc = 0;
                        uint32_t rcnt = 1;
                        kern_return_t mkr = IOConnectCallMethod(
                            c, sel, &sc, 1, NULL, 0, &rc, &rcnt, NULL, NULL);
                        ops++;
                        if (!noise(mkr) && anoms < 32) {
                            anoms++;
                            smsg("[surface] ANOM %s[%d] t%u s%u v%u kr=0x%x",
                                 cls, svcn, ty, sel, v, mkr);
                        }
                        if ((ops & 0xff) == 0) yield_now();
                    }
                }
                IOServiceClose(c);
            } else if (ty < 4) {
                smsg("[surface] %s[%d] type=%u denied kr=0x%x", cls, svcn, ty, okr);
            }
            yield_now();
        }
        IOObjectRelease(svc);
        yield_now();
    }
    IOObjectRelease(it);
    smsg("[surface] %s done services=%d oktypes=%u ops=%u anoms=%u",
         cls, svcn, oktypes, ops, anoms);
}

/* ── Entry ────────────────────────────────────────────────────────────── */
void nk_surface_scan_run(void) {
    nk_filelog_open("surface");
    nk_log("[surface] session start");
    probe_iosurface_matrix();
    const char *fams[] = {
        "IOHIDEventSystem",
        "IOMobileFramebuffer",
        "IOAccessoryManager",
        "IOHIDDevice",
        "IOAESAccelerator",
    };
    for (unsigned i = 0; i < sizeof(fams)/sizeof(fams[0]); i++)
        probe_family(fams[i]);
    nk_log("[surface] session end");
    nk_filelog_close();
}
