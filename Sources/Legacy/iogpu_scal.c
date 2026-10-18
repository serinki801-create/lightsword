/* iogpu_scal.c — protocol Phase-1 decision point: widened SCAL grid.
   Device floor: AGXAcceleratorG14P type1 = only openable GPU UC.
   Grid: sel 0..127 x scal 0..64 = 8320 IOConnectCallMethod calls, zero
   structs, full out-quad capture. Baseline = known noise {2c2,2c7,fail}.
   Verdict line at end:
     STRC HIT sel=<n> scal=<m> kr=<x> — any non-baseline answer
     COLDA                            — otherwise                     */
#import <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"

#define ol(...) nk_log(__VA_ARGS__)

static int baseline(uint32_t kr) {
    return kr == 0xe00002c2 || kr == 0xe00002c7 || kr == KERN_FAILURE
        || kr == 0xe00002c1 || kr == MACH_SEND_INVALID_DEST;
}

void nk_iogpu_scal_run(void) {
    nk_filelog_open("scal");
    ol("[scal] grid start sel=0..127 scal=0..64 (8320 calls)");
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMasterPortDefault,
        IOServiceMatching("AGXAcceleratorG14P"), &it) != KERN_SUCCESS)
        { ol("[scal] no AGX service"); nk_filelog_close(); return; }
    io_service_t svc = IOIteratorNext(it);
    if (!svc) { ol("[scal] empty it"); nk_filelog_close(); return; }
    int hits = 0, n = 0;
    uint32_t types[2] = {1, 33};
    for (int ti = 0; ti < 2; ti++) {
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), types[ti], &conn);
        if (kr != KERN_SUCCESS || !conn) {
            ol("[scal] open type=%u kr=0x%x", types[ti], kr);
            continue;
        }
        for (uint32_t sel = 0; sel <= 127; sel++) {
            for (uint32_t sc = 0; sc <= 64; sc++) {
                uint64_t scr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
                for (uint32_t q = 0; q < 8 && q < sc; q++) {
                    scr[q] = (q == 0) ? (uint64_t)sc : 0x1234;
                }
                uint64_t out[8] = {0};
                uint32_t oN = 8;
                kr = IOConnectCallMethod(conn, sel, scr, sc,
                                         NULL, 0, out, &oN, NULL, NULL);
                n++;
                if (!baseline(kr)) {
                    hits++;
                    ol("[scal] HIT sel=%u scal=%u kr=0x%x outN=%u", sel, sc, kr, oN);
                    uint32_t idump = oN > 4 ? 4 : oN;
                    for (uint32_t q = 0; q < idump; q++)
                        ol("[scal] hit sel=%u out[%u]=0x%llx", sel, q,
                           (unsigned long long)out[q]);
                }
            }
            if ((sel & 7) == 7) usleep(2000);
        }
        IOServiceClose(conn);
        usleep(2000);
    }
    IOObjectRelease(svc); IOObjectRelease(it);
    if (hits) {
        ol("[scal] SCAL RESULT: STRC HIT n=%d", n);
    } else {
        ol("[scal] SCAL RESULT: COLDA — all %d calls baseline", n);
    }
    nk_filelog_close();
}
