/* fuzz2.m — post-fuzz follow-up on the device's 18 openable families.
   (iOS 26.2 / 23C55, iPhone14,5-A15.)
   fuzz_20261018-124325.log proved: 746 services seen, 18 openable,
   and ONE kernel-VA candidate 0xfffffff007bac000 inside user region
   0x105218000 — exactly exploiting.h PRE_SLIDE_DATA_CONST.
   Two answers this run produces:
     A) is that kernel-VA a real slug (slid pointer / leak) or a baked
        unslid constant: log region descriptor (prot/share/depth),
        offset, bytes around the hit, sample repeats, delta vs the
        PRE_SLIDE constants;
     B) what else is reachable: per family, types 0..15 open test plus
        sel 0..63 scalar n2 and structured 16/64 sweeps.            */
#import <IOKit/IOKitLib.h>
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include "exploit.h"

#define fl2(fmt, ...) nk_log(fmt, ##__VA_ARGS__)

static void yieldf(void) { usleep(30000); }

static const char *FAMS[18] = {
    "ANEDriverRoot", "H11ANE", "AppleKeyStore", "IOCoreSurfaceRoot",
    "AppleEmbeddedNVMeTemperatureSensor", "AppleARMPMUTempSensor",
    "AppleARMPMUPowerSensor", "AppleM68Buttons", "AppleSPUHIDDriver",
    "AppleSPUVD6287", "AOPTouchHIDDriver", "IOHIDEventDriver",
    "AppleProxHIDEventDriver", "AHSTemperatureReporter",
    "AppleM2ScalerCSCDriver", "AppleJPEGDriver", "AppleCLCD2",
    "AGXAcceleratorG14P"
};

static void f2_read(mach_vm_address_t a, void *out, vm_size_t n) {
    vm_size_t got = n;
    kern_return_t r = vm_read_overwrite(
        mach_task_self(), a, n, (vm_address_t)(uintptr_t)out, &got);
    if (r != KERN_SUCCESS) memset(out, 0, n);
}

/* ---- PART A: kernel-VA candidate forensics (fast chunked) ---- */
static void part_a(void) {
    fl2("[f2] A: kernel-VA forensics (chunked)");
    static const uint64_t pres[5] = {
        PRE_SLIDE_TEXT, PRE_SLIDE_TEXT_EXEC, PRE_SLIDE_DATA_CONST,
        PRE_SLIDE_DATA_SPTM, PRE_SLIDE_DATA
    };
    static const char *presn[5] = { "TEXT", "TEXEC", "DCONST", "SPTM", "DATA" };
    /* only the real kernel-VA window counts: image base + kASLR span */
    static const uint64_t klo = 0xfffffff007000000ULL;
    static const uint64_t khi = 0xfffffff020000000ULL;
    static uint8_t chunk[65536];
    mach_vm_address_t addr = 0;
    int regions = 0, hits = 0;
    while (regions < 1024 && hits < 16) {
        mach_vm_size_t size = 0;
        uint32_t depth = 4096;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(),
            &addr, &size, &depth, (vm_region_recurse_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS) break;
        regions++;
        if (!(info.protection & VM_PROT_READ) || size < 8) { yieldf(); continue; }
        uint64_t base = addr;
        size_t span = size;
        if (span > (4ULL << 20)) span = (4ULL << 20);
        for (uint64_t off = 0; off + sizeof(chunk) <= span; off += sizeof(chunk)) {
            size_t got = sizeof(chunk);
            kern_return_t r = vm_read_overwrite(mach_task_self(),
                base + off, sizeof(chunk), (vm_address_t)(uintptr_t)chunk, &got);
            if (r != KERN_SUCCESS) break;
            for (size_t i = 0; i + 8 <= got; i += 8) {
                uint64_t v;
                memcpy(&v, chunk + i, 8);
                if (v < klo || v > khi) continue;
                uint64_t ho = off + i;
                fl2("[f2] kVA 0x%llx in region 0x%llx size 0x%llx off 0x%lx prot %u share %u",
                    (unsigned long long)v, (unsigned long long)base,
                    (unsigned long long)size, (unsigned long)ho,
                    info.protection, info.share_mode);
                for (int k = 0; k < 5; k++)
                    if (v >= pres[k] && v - pres[k] < 0x4000000)
                        fl2("[f2]   delta vs %s_pre = 0x%llx",
                            presn[k], (unsigned long long)(v - pres[k]));
                uint8_t buf[64];
                uint64_t lo = base + (ho > 24 ? ho - 24 : 0);
                f2_read(lo, buf, sizeof(buf));
                char hex[200];
                size_t p = 0;
                for (int q = 0; q < 16 && p < sizeof(hex) - 3; q++)
                    p += (size_t)snprintf(hex + p, 3, "%02x", buf[q]);
                fl2("[f2]   bytes: %s", hex);
                hits++;
                yieldf();
                if (hits >= 16) break;
            }
            if (hits >= 16) break;
            if ((off & 0xFFFFF) == 0) yieldf();
        }
        if (hits >= 16) break;
        yieldf();
        addr += size;
    }
    if (hits == 0)
        fl2("[f2] A VERDICT: no kernel-VA pointer in user-visible regions");
    fl2("[f2] A done regions=%d hits=%d", regions, hits);
}

/* ---- PART B: 18-family deep open + sweep ---- */
static int f2_noise(kern_return_t kr) {
    return kr == (kern_return_t)0xe00002c2
        || kr == (kern_return_t)0xe00002c7
        || kr == (kern_return_t)0xe00002e2
        || kr == (kern_return_t)0xe00002be;
}

/* big five: full logging incl. KERN_SUCCESS + out quad */
static int f2_big(const char *n) {
    return !strcmp(n, "AppleJPEGDriver") || !strcmp(n, "AppleM2ScalerCSCDriver")
        || !strcmp(n, "AppleCLCD2") || !strcmp(n, "AppleKeyStore")
        || !strcmp(n, "AGXAcceleratorG14P");
}

static int f2_log_scal(const char *n, uint32_t ty, uint32_t sel, kern_return_t kr, const uint64_t *out) {
    if (f2_big(n))
        fl2("[f2] %s t%u SCAL s%u kr=0x%x out=%llx,%llx,%llx,%llx",
            n, ty, sel, kr, (unsigned long long)out[0],
            (unsigned long long)out[1], (unsigned long long)out[2],
            (unsigned long long)out[3]);
    else if (!f2_noise(kr) && kr != KERN_SUCCESS)
        fl2("[f2] %s t%u SCAL s%u kr=0x%x", n, ty, sel, kr);
    return 0;
}

static int f2_log_strc(const char *n, uint32_t ty, uint32_t sel, size_t sz, kern_return_t kr) {
    if (f2_big(n))
        fl2("[f2] %s t%u STRC s%u sz%zu kr=0x%x", n, ty, sel, sz, kr);
    else if (!f2_noise(kr) && kr != KERN_SUCCESS)
        fl2("[f2] %s t%u STRC s%u sz%zu kr=0x%x", n, ty, sel, sz, kr);
    return 0;
}

/* boundary ladder for keystore s17/s35 */
static const size_t KS_SZ[12] = { 4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256 };
static const size_t BIG_SZ[6] = { 16, 64, 96, 192, 256, 384 };

static void part_b(void) {
    fl2("[f2] B: 18-family probe (full big-five logging)");
    for (int fi = 0; fi < 18; fi++) {
        CFMutableDictionaryRef md = IOServiceMatching(FAMS[fi]);
        if (!md) { fl2("[f2] %s no match", FAMS[fi]); continue; }
        io_iterator_t it = 0;
        if (IOServiceGetMatchingServices(kIOMasterPortDefault, md, &it)
            != KERN_SUCCESS) {
            fl2("[f2] %s iter fail", FAMS[fi]);
            continue;
        }
        io_object_t svc;
        int opened = 0, si = 0;
        while ((svc = IOIteratorNext(it)) && si < 2) {
            si++;
            for (uint32_t ty = 0; ty < 16; ty++) {
                io_connect_t c = 0;
                if (IOServiceOpen(svc, mach_task_self(), ty, &c) != KERN_SUCCESS) {
                    yieldf(); continue;
                }
                opened++;
                fl2("[f2] open %s[%d] t%u", FAMS[fi], si, ty);
                sleep(1);
                for (uint32_t sel = 0; sel < 64; sel++) {
                    uint64_t in2[2] = { sel, 0 };
                    uint64_t out[8]; uint32_t oc = 8;
                    memset(out, 0, sizeof(out));
                    kern_return_t ks = IOConnectCallMethod(
                        c, sel, in2, 2, NULL, 0, out, &oc, NULL, NULL);
                    f2_log_scal(FAMS[fi], ty, sel, ks, out);
                    if ((sel & 0x1f) == 0x1f) yieldf();
                }
                const size_t *szs = BIG_SZ;
                size_t nsz = 6;
                if (!strcmp(FAMS[fi], "AppleKeyStore")) {
                    /* single-shot ladder inside sel loop below */
                    for (uint32_t sel = 0; sel < 64; sel++) {
                        if (sel == 17 || sel == 35) {
                            for (int z = 0; z < 12; z++) {
                                size_t sz = KS_SZ[z];
                                uint8_t stb[256], outb[512];
                                for (size_t q = 0; q < sz; q++) stb[q] = 0xAA;
                                size_t osz = sizeof(outb);
                                kern_return_t kt = IOConnectCallStructMethod(
                                    c, sel, stb, sz, outb, &osz);
                                fl2("[f2] %s t%u KSD s%u sz%zu kr=0x%x osz%zu",
                                    FAMS[fi], ty, sel, sz, kt, osz);
                                if ((z & 7) == 7) yieldf();
                            }
                            continue;
                        }
                        for (int z = 0; z < 6; z++) {
                            size_t sz = BIG_SZ[z];
                            if (sz > 256) continue;
                            uint8_t stb[256], outb[512];
                            memset(stb, 0, sizeof(stb));
                            for (size_t q = 0; q < sz; q++) stb[q] = 0xAA;
                            memset(stb, 0, sizeof(stb) - sz);
                            size_t osz = sizeof(outb);
                            kern_return_t kt = IOConnectCallStructMethod(
                                c, sel, stb, sz, outb, &osz);
                            f2_log_strc(FAMS[fi], ty, sel, sz, kt);
                            if ((sel & 0x0f) == 0x0f) yieldf();
                        }
                    }
                    IOServiceClose(c);
                    sleep(1);
                    continue;
                }
                for (int z = 0; z < (int)nsz; z++) {
                    size_t sz = szs[z];
                    if (sz > 256) { /* 384 needs bigger stack buffer: skip for now */ continue; }
                    uint8_t stb[256], outb[512];
                    memset(stb, 0, sizeof(stb));
                    for (size_t q = 0; q < sz; q++) stb[q] = 0xAA;
                    memset(stb, 0, sizeof(stb) - sz);
                    for (uint32_t sel = 0; sel < 64; sel++) {
                        size_t osz = sizeof(outb);
                        kern_return_t kt = IOConnectCallStructMethod(
                            c, sel, stb, sz, outb, &osz);
                        f2_log_strc(FAMS[fi], ty, sel, sz, kt);
                        if ((sel & 0x0f) == 0x0f) yieldf();
                    }
                }
                IOServiceClose(c);
                sleep(1);
            }
            IOObjectRelease(svc);
            sleep(2);
        }
        IOObjectRelease(it);
        fl2("[f2] %s done opens=%d", FAMS[fi], opened);
        sleep(2);
    }
    fl2("[f2] B done");
}

void nk_fuzz2_run(void) {
    nk_filelog_open("fuzz2");
    nk_log("[f2] fuzz2 session start");
    part_a();
    part_b();
    nk_log("[f2] fuzz2 session end");
    nk_filelog_close();
}
