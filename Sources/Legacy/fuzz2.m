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

static int f2_is_kernel_va(uint64_t v) {
    uint32_t hi = (uint32_t)(v >> 32);
    return hi == 0xfffffff0 || hi == 0xffffffe0 ||
           hi == 0xfffffe00 || hi == 0xffffff80;
}
static int f2_is_poison(uint64_t v) {
    return v == 0x4141414141414141ULL ||
           v == 0x0000000000000000ULL ||
           v == 0xABABABABABABABABULL ||
           (v & 0xFFFFFFFF) == 0xDEADBEEFULL;
}

static const char *FAMS[18] = {
    "ANEDriverRoot", "H11ANE", "AppleKeyStore", "IOCoreSurfaceRoot",
    "AppleEmbeddedNVMeTemperatureSensor", "AppleARMPMUTempSensor",
    "AppleARMPMUPowerSensor", "AppleM68Buttons", "AppleSPUHIDDriver",
    "AppleSPUVD6287", "AOPTouchHIDDriver", "IOHIDEventDriver",
    "AppleProxHIDEventDriver", "AHSTemperatureReporter",
    "AppleM2ScalerCSCDriver", "AppleJPEGDriver", "AppleCLCD2",
    "AGXAcceleratorG14P"
};

static void f2_read(mach_vm_address_t a, void *out, mach_vm_size_t n) {
    mach_vm_size_t got = n;
    kern_return_t r = vm_read_overwrite(
        mach_task_self(), a, n, (vm_address_t)(uintptr_t)out, &got);
    if (r != KERN_SUCCESS) memset(out, 0, n);
}

/* ---- PART A: kernel-VA candidate forensics ---- */
static void part_a(void) {
    fl2("[f2] A: kernel-VA forensics");
    static const uint64_t pres[5] = {
        PRE_SLIDE_TEXT, PRE_SLIDE_TEXT_EXEC, PRE_SLIDE_DATA_CONST,
        PRE_SLIDE_DATA_SPTM, PRE_SLIDE_DATA
    };
    static const char *presn[5] = { "TEXT", "TEXEC", "DCONST", "SPTM", "DATA" };
    mach_vm_address_t addr = 0;
    int regions = 0, hits = 0;
    while (regions < 4096 && hits < 32) {
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
        if (span > (1ULL << 20)) span = (1ULL << 20);
        size_t words = span / 8;
        for (size_t w = 0; w < words; w++) {
            uint64_t v = 0;
            f2_read(base + w * 8, &v, 8);
            if (!f2_is_kernel_va(v) || f2_is_poison(v)) continue;
            uint64_t off = w * 8;
            fl2("[f2] VA 0x%llx region 0x%llx size 0x%llx off 0x%lx prot %u share %u depth %u",
                (unsigned long long)v, (unsigned long long)base,
                (unsigned long long)size, (unsigned long)off,
                info.protection, info.share_mode, depth);
            for (int k = 0; k < 5; k++) {
                if (v >= pres[k] && v - pres[k] < 0x4000000)
                    fl2("[f2]   delta vs %s_pre = 0x%llx",
                        presn[k], (unsigned long long)(v - pres[k]));
            }
            uint64_t lo = base + (off > 32 ? off - 32 : 0);
            uint8_t buf[96];
            f2_read(lo, buf, sizeof(buf));
            char hex[200];
            size_t p = 0;
            for (int i = 0; i < 16 && p < sizeof(hex) - 3; i++)
                p += (size_t)snprintf(hex + p, 3, "%02x", buf[i]);
            fl2("[f2]   bytes: %s", hex);
            int rep = 0;
            for (size_t q = 0; q + 8 <= words; q += 512) {
                uint64_t v2 = 0;
                f2_read(base + q * 8, &v2, 8);
                if (v2 == v) rep++;
            }
            fl2("[f2]   repeats(sampled): %d", rep);
            hits++;
            yieldf();
            if (hits >= 32) break;
        }
        if (hits >= 32) break;
        yieldf();
        addr += size;
    }
    fl2("[f2] A done regions=%d hits=%d", regions, hits);
}

/* ---- PART B: 18-family deep open + sweep ---- */
static int f2_noise(kern_return_t kr) {
    return kr == KERN_SUCCESS
        || kr == (kern_return_t)0xe00002c2
        || kr == (kern_return_t)0xe00002c7
        || kr == (kern_return_t)0xe00002e2
        || kr == (kern_return_t)0xe00002be
        || kr == (kern_return_t)0x2c2
        || kr == (kern_return_t)0x2be;
}

static void part_b(void) {
    fl2("[f2] B: 18-family probe");
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
                    kern_return_t ks = IOConnectCallMethod(
                        c, sel, in2, 2, NULL, 0, out, &oc, NULL, NULL);
                    if (!f2_noise(ks))
                        fl2("[f2] %s t%u SCAL s%u kr=0x%x out=%llx",
                            FAMS[fi], ty, sel, ks, (unsigned long long)out[0]);
                    if ((sel & 0x1f) == 0x1f) yieldf();
                }
                static const size_t SZS[2] = { 16, 64 };
                uint8_t stb[64], outb[256];
                for (int z = 0; z < 2; z++) {
                    size_t sz = SZS[z];
                    memset(stb, 0, sizeof(stb));
                    memset(stb, 0xAA, sz);
                    for (uint32_t sel = 0; sel < 64; sel++) {
                        size_t osz = sizeof(outb);
                        kern_return_t kt = IOConnectCallStructMethod(
                            c, sel, stb, sz, outb, &osz);
                        if (!f2_noise(kt))
                            fl2("[f2] %s t%u STRC s%u sz%zu kr=0x%x",
                                FAMS[fi], ty, sel, sz, kt);
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
