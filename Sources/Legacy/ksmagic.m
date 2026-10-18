/* ksmagic.m — KeyStore UC verdict Cartesian probe (23C55).
   Device facts: s0/s1/s16 KERN_SUCCESS(0,0,0,0) on any sz;
                 s17/s35: all-zero struct=0xe00002f0, any nonzero=0xe00002c2,
                 same on all 16 types.
   Matrix: sel x {zero, lead-qw-1..4, qw1-nonzero, NULL struct} x sz64/256.
   Writes full verdict grid (no suppression). */
#import <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "exploit.h"

#define ol(...) nk_log(__VA_ARGS__)

static void ks_call(io_connect_t conn, uint32_t sel, const void *s,
                    size_t inSz, const char *tag) {
    uint64_t so[4] = {0};
    uint32_t oN = 4;
    kern_return_t kr = IOConnectCallMethod(conn, sel, NULL, 0, s, inSz,
                                           so, &oN, NULL, NULL);
    ol("[ksm] sel=%u tag=%s kr=0x%x out=%llx %llx %llx %llx",
       sel, tag, kr,
       (unsigned long long)so[0], (unsigned long long)so[1],
       (unsigned long long)so[2], (unsigned long long)so[3]);
}

void nk_ksmagic_run(void) {
    nk_filelog_open("ksmagic");
    ol("[ksm] verdict cartesian probe");
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
        static const uint32_t sels[5] = {0, 1, 16, 17, 35};
        static uint8_t b64[64], b256[256];
        memset(b64, 0, sizeof(b64)); memset(b256, 0, sizeof(b256));
        for (unsigned q = 0; q < 5; q++) {
            uint32_t sel = sels[q];
            ks_call(conn, sel, b64, 64, "zero64");
            ks_call(conn, sel, b256, 256, "zero256");
            for (uint32_t lead = 1; lead <= 4; lead++) {
                memcpy(b64, &lead, 4);
                char tg[16]; snprintf(tg, sizeof(tg), "lead%u64", lead);
                ks_call(conn, sel, b64, 64, tg);
                memset(b64, 0, sizeof(b64));
            }
            *((uint64_t *)b64) = 0; *((uint64_t *)b64 + 1) = 0xdeadc0de;
            ks_call(conn, sel, b64, 64, "qw1nn64");
            memset(b64, 0, sizeof(b64));
            ks_call(conn, sel, NULL, 0, "null0");
            ks_call(conn, sel, &b64, 1, "wrong-mbuf");
            memset(b64, 0, sizeof(b64));
        }
        IOServiceClose(conn);
        usleep(2000);
    }
    IOObjectRelease(svc); IOObjectRelease(it);
    ol("[ksm] done");
    nk_filelog_close();
}
