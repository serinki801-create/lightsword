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
    nk_log("[iok] full registry sweep: all services, types 0-3, sel 0-7");
    io_iterator_t it = 0;
    kern_return_t kr = IOServiceGetMatchingServices(
        kIOMasterPortDefault, IOServiceMatching("IOService"), &it);
    if (kr != KERN_SUCCESS || it == 0) {
        nk_log("[-] iok: registry iterator failed kr=%d", kr);
        return;
    }

    static const size_t szs[3] = { 64, 256, 1024 };
    int services = 0, opened = 0, denied = 0, mutations = 0, leaks = 0;
    io_service_t svc;

    while ((svc = IOIteratorNext(it)) != IO_OBJECT_NULL) {
        services++;
        char name[128];
        io_name_t nm;
        if (IORegistryEntryGetName(svc, nm) == KERN_SUCCESS)
            snprintf(name, sizeof(name), "%s", nm);
        else
            snprintf(name, sizeof(name), "svc%d", services);

        for (uint32_t type = 0; type < 4; type++) {
            io_connect_t conn = 0;
            kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
            if (kr != KERN_SUCCESS) {
                if (type == 0) {
                    denied++;
                    nk_log("[iok DENY] %s kr=0x%x", name, kr);
                }
                continue;
            }
            opened++;
            nk_log("[iok OPEN] %s type=%u", name, type);

            for (uint32_t sel = 0; sel < 8; sel++) {
                for (int with_in = 0; with_in < 2; with_in++) {
                    static uint8_t in[64];
                    memset(in, 0, sizeof(in));
                    for (size_t zi = 0; zi < 3; zi++) {
                        static uint8_t out[1024];
                        size_t osz = szs[zi];
                        memset(out, 0xBB, sizeof(out));
                        kern_return_t k2;
                        if (with_in)
                            k2 = IOConnectCallStructMethod(conn, sel,
                                in, sizeof(in), out, &osz);
                        else
                            k2 = IOConnectCallMethod(conn, sel,
                                NULL, 0, NULL, 0, NULL, NULL, out, &osz);
                        if (k2 != KERN_SUCCESS) continue;

                        size_t lim = osz < szs[zi] ? osz : szs[zi];
                        int mut = 0;
                        for (size_t i = 0; i < lim; i++)
                            if (out[i] != 0xBB) mut++;
                        if (mut == 0) continue;

                        mutations++;
                        int kp = scan_kptrs(out, lim, name, sel);
                        if (kp) leaks += kp;
                        if (kp || mutations <= 24)
                            nk_log("[iok MUT] %s type=%u sel=%u in=%d sz=%zu mut=%d head=%02x%02x%02x%02x%02x%02x%02x%02x",
                                name, type, sel, with_in, szs[zi], mut,
                                out[0], out[1], out[2], out[3],
                                out[4], out[5], out[6], out[7]);
                    }
                }
            }
            IOServiceClose(conn);
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);

    nk_log("[iok] sweep done services=%d opened=%d denied=%d mutations=%d leaks=%d",
        services, opened, denied, mutations, leaks);
}
