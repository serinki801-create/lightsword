/* ksmagic.m — AppleKeyStore UC s17/s35 content-gate probe (23C55).
   Fuzz evidence: all 16 types open; sels 0/1/16 KERN_SUCCESS silent;
   s17/s35 return e00002f0 irrespective of size -> content gate.
   Device statics: 20-byte magic blob lives at 0xfffffff007b12938
   (bytes +0x18..+0x2c nonzero). Probe places those bytes at struct
   offsets 0/0x18/0x19 across sizes {64,96,256} and logs any change from
   the e00002f0 verdict. */
#import <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "exploit.h"

#define ol(...) nk_log(__VA_ARGS__)

/* Device verdicts: all-zero struct -> 0x2f0; any nonzero -> 0x2c2.
   Verdict reads a leading word. Shotgun 16 u32 candidates at offset 0. */
static const uint32_t KMAG[16] = {
    0x00000001u, 0x00000116u, 0x31474142u /* BAG1 */,
    0x47414249u /* IBAG */, 0x42534b41u /* AKSB */,
    0x54534b41u /* AKST */, 0x0e000001u, 0x0e000002u,
    0x00000003u, 0x00000008u, 0x00000016u, 0x504b5341u /* ASKP */,
    0x534d4548u, 0x00000a2fu, 0xfffffffu, 0xfeabf00du
};

static int ks_noise(uint32_t kr) {
    switch (kr) {
    case 0x0: return 1;
    case 0xe00002c1: case 0xe00002c2: case 0xe00002c7:
    case 0xe00002e2: case 0xe00002be: case 0xe00002f0:
    case KERN_NOT_RECEIVER: case KERN_INVALID_CAPABILITY: case MACH_SEND_INVALID_DEST: return 1;
    }
    return 0;
}

static void ks_try(io_connect_t conn, uint32_t type, uint32_t sel,
                   size_t inSz, uint32_t mag) {
    static uint8_t sbuf[256];
    memset(sbuf, 0, sizeof(sbuf));
    memcpy(sbuf, &mag, 4);
    uint64_t so[4] = {0};
    uint32_t oN = 4;
    kern_return_t kr = IOConnectCallMethod(conn, sel, NULL, 0, sbuf, inSz,
                                           so, &oN, NULL, NULL);
    if (!ks_noise(kr))
        ol("[ksm] HIT type=%u sel=%u sz=%zu mag=0x%08x kr=0x%x out=%llx %llx %llx %llx",
           type, sel, inSz, mag, kr,
           (unsigned long long)so[0], (unsigned long long)so[1],
           (unsigned long long)so[2], (unsigned long long)so[3]);
    else if (kr != 0xe00002f0 && kr != 0x0)
        ol("[ksm] type=%u sel=%u sz=%zu mag=0x%08x kr=0x%x", type, sel, inSz, mag, kr);
}

void nk_ksmagic_run(void) {
    nk_filelog_open("ksmagic");
    ol("[ksm] AppleKeyStore s17/s35 magic probe");
    io_service_t svc = MACH_PORT_NULL;
    io_iterator_t it = 0;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault,
                          IOServiceMatching("AppleKeyStore"), &it);
    if (kr != KERN_SUCCESS) { ol("[ksm] no AppleKeyStore service kr=0x%x", kr); nk_filelog_close(); return; }
    while ((svc = IOIteratorNext(it))) {
        for (uint32_t type = 0; type <= 15; type++) {
            io_connect_t conn = MACH_PORT_NULL;
            kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
            if (kr != KERN_SUCCESS || !conn) { usleep(2000); continue; }
            static const uint32_t sels[2] = {17, 35};
              for (int a = 0; a < 2; a++)
              for (int c = 0; c < 16; c++)
                for (int b = 0; b < 2; b++)
                  ks_try(conn, type, sels[a], szs[b], KMAG[c]);
            IOServiceClose(conn);
            usleep(2000);
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    ol("[ksm] done");
    nk_filelog_close();
}
