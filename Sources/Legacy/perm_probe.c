/* PERMISSION PROBE: which Mach services can this sandboxed app reach?
 *
 * The sandbox kext LOST 20 service strings between 18.x and 26.2 - and the
 * sandbox is the component that decides which services an app may talk to.
 * If one of those is now reachable, the sandbox no longer filters it, and
 * that is exactly the shape of CVE-2026-43689 ("a permissions issue ... a
 * malicious app may be able to gain root privileges"): no kernel pointer,
 * no leak, no OOB - just a service the app should not have.
 *
 * The test is the sandbox's own: bootstrap_look_up() returns a Mach port
 * for a service only if the caller is allowed to use it. A successful
 * lookup is the proof.
 */
#include "exploit.h"
#include "nk_trace.h"
#include <mach/mach.h>
#include <mach/bootstrap.h>

/* Not declared in the iOS SDK headers, but the symbol is in libsystem_bootstrap. */
extern kern_return_t bootstrap_look_up(const char *name, mach_port_t *port);

static const char *k_perm_names[] = {
    /* the 20 the sandbox kext dropped between 18.x and 26.2 */
    "com.apple.AuthenticationServices.ASConfigurationSubscriber",
    "com.apple.BluetoothUIService",
    "com.apple.BTAudioHALPluginAccessories",
    "com.apple.carousel",
    "com.apple.cookied",
    "com.apple.corespotlight",
    "com.apple.EnergyKitService",
    "com.apple.erm.status",
    "com.apple.GameController.gamecontrollerd.haptics",
    "com.apple.GameOverlayUI",
    "com.apple.gms.TestClientExamplesAgentsXPCService",
    "com.apple.KeyboardFeedbackAssistant.ViewServiceExtension",
    "com.apple.MobileAsset",
    "com.apple.STExtractionService.privileged",
    "com.apple.suggestd",
    "com.apple.suggestd.reminders",
    "com.apple.UARPAssetManagerServiceMobileAsset",
    "com.apple.uikit.viewService.connectionRequest",
    "com.apple.WebKit.Model",
    "com.apple.WebPrivacy.Service",
    /* a few well-known privileged ones, as a control */
    "com.apple.system.notification_center",
    "com.apple.diagnostics_relay",
    "com.apple.CoreTelephonyAgent",
    "com.apple.mobile.diagnostics_relay",
    "com.apple.internal.dt.RemoteURL",
    "com.apple.security.sandbox.system-container",
    NULL
};

void nk_perm_probe(void)
{
    nk_doc_log_open("perm.log");
    nk_log("[PERM] === service reachability probe ===");
    uint32_t ok = 0;
    for (uint32_t i = 0; k_perm_names[i]; i++) {
        const char *n = k_perm_names[i];
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_look_up(n, &port);
        if (kr == KERN_SUCCESS && port) {
            ok++;
            nk_log("[PERM] REACHABLE  %s -> port=0x%x", n, port);
            nk_doc_log("perm.log", "[PERM] REACHABLE  %s -> port=0x%x", n, port);
            mach_port_deallocate(mach_task_self(), port);
        } else {
            nk_log("[PERM] denied     %s (kr=0x%x)", n, kr);
        }
    }
    nk_log("[PERM] reachable: %u", ok);
    nk_doc_log("perm.log", "[PERM] reachable: %u", ok);
}

void nk_perm_probe_id(const char *ident)
{
    nk_doc_log_open("perm.log");
    nk_log("[PERM] signed as identifier = %s", ident ? ident : "?");
    nk_doc_log("perm.log", "[PERM] signed as identifier = %s", ident ? ident : "?");
}
