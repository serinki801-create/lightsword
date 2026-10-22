/* What the KERNEL sees in our signature.
 *
 * Two questions the runtime cannot answer from the Info.plist:
 *   1. what identifier is in the CodeDirectory (ldid derives it from
 *      CFBundleIdentifier, but the kernel only trusts the signature);
 *   2. are our entitlements actually parsed (a ldid signature can be
 *      rejected or stripped at install time).
 * SecCodeCopySelf + SecCodeCopySigningInformation gives the identifier,
 * SecTaskCopyValueForEntitlement gives the entitlements the kernel sees.
 */
#include "exploit.h"
#include "nk_trace.h"
#include <Security/Security.h>

/* The iOS SDK ships no SecTask.h / SecCode.h (macOS-only), so the three
 * entry points we need are declared by hand; they exist in Security.framework
 * on the device. */
typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef name,
                                                 CFErrorRef *error);

void nk_sig_dump(void)
{
    nk_doc_log_open("mha.log");
    nk_log("[SIG] === what the kernel sees in our signature ===");

    static const char *ents[] = {
        "com.apple.mobile.MobileHouseArrest",
        "com.apple.private.MobileContainerManager.allowed",
        "com.apple.private.security.storage.MobileContainerManager",
        "com.apple.rootless.storage.MobileContainerManager",
        "get-task-allow",
        "platform-application",
        "application-identifier",
        NULL
    };
    SecTaskRef task = SecTaskCreateFromSelf(NULL);
    for (uint32_t i = 0; ents[i]; i++) {
        CFStringRef k = CFStringCreateWithCString(NULL, ents[i], kCFStringEncodingUTF8);
        CFTypeRef v = SecTaskCopyValueForEntitlement(task, k, NULL);
        nk_log("[SIG] entitlement %-58s = %s", ents[i],
               v ? "PRESENT" : "ABSENT");
        if (v) CFRelease(v);
        CFRelease(k);
    }
    if (task) CFRelease(task);
    nk_log("[SIG] done");
}
