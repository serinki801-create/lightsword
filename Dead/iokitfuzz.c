#include "exploit.h"
#include <IOKit/IOKitLib.h>

static int scan_kptrs(const uint8_t *buf, size_t n, const char *tag, uint32_t sel) {
    int found = 0;
    for (size_t off = 0; off + 8 <= n; off += 8) {
        uint64_t v;
        memcpy(&v, buf + off, 8);
        uint32_t hi = (uint32_t)(v >> 32);
        if (hi == 0xfffffff0 || hi == 0xfffffe00) {
            nk_log("[iok LEAK] %s sel=%u off=%zu ptr=0x%016llx%s",
                tag, sel, off, (unsigned long long)v,
                ((v & 0xFFFFULL) == 0) ? " (round)" : "");
            found++;
        }
    }
    return found;
}

void nk_iokit_fuzz(void) {
    static const char *svcs[] = {
        "IOSurfaceRoot", "IOAccelerator", "AGXAccelerator",
        "IOMobileFramebuffer", "IOTimeSyncClockManager", "IOHIDSystem"
    };
    static const size_t szs[2] = { 64, 256 };
    int mutations = 0, leaks = 0, opened = 0;

    for (size_t si = 0; si < sizeof(svcs)/sizeof(svcs[0]); si++) {
        io_service_t svc = IOServiceGetMatchingService(
            kIOMainPortDefault, IOServiceMatching(svcs[si]));
        if (svc == IO_OBJECT_NULL) {
            nk_log("[iok] %s: not present", svcs[si]);
            continue;
        }
        for (uint32_t type = 0; type < 2; type++) {
            io_connect_t conn = 0;
            if (IOServiceOpen(svc, mach_task_self(), type, &conn) != KERN_SUCCESS)
                continue;
            opened++;
            nk_log("[iok] %s opened type=%u", svcs[si], type);

            for (uint32_t sel = 0; sel < 32; sel++) {
                for (size_t zi = 0; zi < 2; zi++) {
                    static uint8_t out[512];
                    size_t osz = szs[zi];
                    memset(out, 0xBB, sizeof(out));
                    kern_return_t kr = IOConnectCallMethod(conn, sel,
                        NULL, 0, NULL, 0, NULL, NULL, out, &osz);
                    if (kr != KERN_SUCCESS) continue;
                    int mut = 0;
                    size_t lim = osz < szs[zi] ? osz : szs[zi];
                    for (size_t i = 0; i < lim; i++)
                        if (out[i] != 0xBB) mut++;
                    if (mut == 0) continue;
                    mutations++;
                    leaks += scan_kptrs(out, lim, svcs[si], sel);
                    nk_log("[iok MUT] %s type=%u sel=%u sz=%zu mut=%d head=%02x%02x%02x%02x%02x%02x%02x%02x",
                        svcs[si], type, sel, szs[zi], mut,
                        out[0], out[1], out[2], out[3],
                        out[4], out[5], out[6], out[7]);
                }
                for (size_t zi = 0; zi < 2; zi++) {
                    static uint8_t sout[512];
                    size_t osz = szs[zi];
                    memset(sout, 0xBB, sizeof(sout));
                    kern_return_t kr = IOConnectCallStructMethod(conn, sel,
                        NULL, 0, sout, &osz);
                    if (kr != KERN_SUCCESS) continue;
                    int mut = 0;
                    size_t lim = osz < szs[zi] ? osz : szs[zi];
                    for (size_t i = 0; i < lim; i++)
                        if (sout[i] != 0xBB) mut++;
                    if (mut == 0) continue;
                    mutations++;
                    leaks += scan_kptrs(sout, lim, svcs[si], sel);
                    nk_log("[iok MUTs] %s type=%u sel=%u sz=%zu mut=%d head=%02x%02x%02x%02x%02x%02x%02x%02x",
                        svcs[si], type, sel, szs[zi], mut,
                        sout[0], sout[1], sout[2], sout[3],
                        sout[4], sout[5], sout[6], sout[7]);
                }
            }
            IOServiceClose(conn);
        }
        IOObjectRelease(svc);
    }
    nk_log("[iok] done opened=%d mutations=%d leaks=%d", opened, mutations, leaks);
}
