#include "exploit.h"
#include <IOKit/IOKitLib.h>

static const char *deep_targets[] = {
    "IOCoreSurfaceRoot",
    "AGXAcceleratorG14P",
    "ANEDriverRoot",
    "H11ANE",
    "AppleM2ScalerCSCDriver",
    "AppleCLCD2",
    "AppleJPEGDriver",
};
#define DEEP_NTARGETS 7

static int deep_count = 0;

static int deep_is_target(const char *name) {
    for (int i = 0; i < DEEP_NTARGETS; i++)
        if (strcmp(name, deep_targets[i]) == 0) return 1;
    return 0;
}

static void deep_map_service(io_service_t svc, const char *name) {
    static uint8_t zero_in[256];
    static uint8_t pat_in[256];
    static uint8_t out[4096];
    static const size_t sizes[] = {0, 16, 64, 256};
    memset(zero_in, 0, sizeof(zero_in));
    memset(pat_in, 0x41, sizeof(pat_in));

    nk_log("[deep] %s: mapping sel 0..47 x types 0..3 x inputs", name);
    for (int type = 0; type < 4; type++) {
        io_connect_t conn = 0;
        if (IOServiceOpen(svc, mach_task_self(), type, &conn) != KERN_SUCCESS)
            continue;

        for (int sel = 0; sel < 48; sel++) {
            for (int si = 0; si < 4; si++) {
                size_t out_sz = sizeof(out);
                memset(out, 0, sizeof(out));
                kern_return_t kr = IOConnectCallStructMethod(
                    conn, sel, zero_in, sizes[si], out, &out_sz);
                int nz = 0;
                for (size_t i = 0; i < out_sz && i < sizeof(out); i++)
                    if (out[i]) { nz = 1; break; }
                if (kr == KERN_SUCCESS && nz) {
                    deep_count++;
                    nk_log("[deep] %s t=%d sel=%d in=%zu kr=0 out=%zu head=%02x%02x%02x%02x%02x%02x%02x%02x",
                        name, type, sel, sizes[si], out_sz,
                        out[0],out[1],out[2],out[3],out[4],out[5],out[6],out[7]);
                }
            }
            size_t out_sz = sizeof(out);
            memset(out, 0, sizeof(out));
            kern_return_t kr = IOConnectCallStructMethod(
                conn, sel, pat_in, 64, out, &out_sz);
            int nz = 0;
            for (size_t i = 0; i < out_sz && i < sizeof(out); i++)
                if (out[i]) { nz = 1; break; }
            if (kr == KERN_SUCCESS && nz) {
                deep_count++;
                nk_log("[deep] %s t=%d sel=%d in=64pat kr=0 out=%zu head=%02x%02x%02x%02x%02x%02x%02x%02x",
                    name, type, sel, out_sz,
                    out[0],out[1],out[2],out[3],out[4],out[5],out[6],out[7]);
            }
        }
        IOServiceClose(conn);
    }
}

void nk_deep_run(void) {
    nk_rule();
    nk_log("[deep] high-value surface deep map v2 (read-only, expanded inputs)");
    deep_count = 0;

    CFMutableDictionaryRef matching = IOServiceMatching("IOService");
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &it) != KERN_SUCCESS) {
        nk_log("[deep] registry iterator failed");
        nk_rule();
        return;
    }
    io_service_t svc;
    while ((svc = IOIteratorNext(it))) {
        io_name_t name;
        if (IORegistryEntryGetName(svc, name) == KERN_SUCCESS) {
            if (deep_is_target(name))
                deep_map_service(svc, name);
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);

    nk_log("[deep] done: %d non-zero responses found", deep_count);
    nk_rule();
}
