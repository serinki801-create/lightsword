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
#include <dlfcn.h>

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
    /* the identifier the KERNEL has for us: SecCodeCopySigningInformation
     * is macOS-only in the headers, but the symbol may still exist in
     * libsystem_security on iOS - dlsym it and see. */
    {
        void *sec = dlopen("/usr/lib/system/libsystem_cdservices.dylib", RTLD_NOW);
        if (!sec) sec = dlopen("/usr/lib/system/securityd.dylib", RTLD_NOW);
        if (sec) {
            int (*copy_self)(uint32_t, void **) = dlsym(sec, "SecCodeCopySelf");
            int (*copy_info)(void *, uint32_t, CFTypeRef *) =
                dlsym(sec, "SecCodeCopySigningInformation");
            void *code = NULL;
            if (copy_self && copy_info && copy_self(0, &code) == 0 && code) {
                CFTypeRef info = NULL;
                if (copy_info(code, 0, &info) == 0 && info) {
                    if (CFGetTypeID(info) == CFStringGetTypeID()) {
                        char b[256] = {0};
                        CFStringGetCString((CFStringRef)info, b, sizeof(b), kCFStringEncodingUTF8);
                        nk_log("[SIG] SecCode identifier = %s", b);
                        nk_doc_log("mha.log", "[SIG] SecCode identifier = %s", b);
                    } else {
                        nk_log("[SIG] SecCode info is not a string (type %ld)", (long)CFGetTypeID(info));
                    }
                    CFRelease(info);
                } else {
                    nk_log("[SIG] SecCodeCopySigningInformation failed");
                }
            } else {
                nk_log("[SIG] SecCodeCopySelf unavailable");
            }
        } else {
            nk_log("[SIG] security libs not dlopen-able");
        }
    }

    SecTaskRef task = SecTaskCreateFromSelf(NULL);
    for (uint32_t i = 0; ents[i]; i++) {
        CFStringRef k = CFStringCreateWithCString(NULL, ents[i], kCFStringEncodingUTF8);
        CFTypeRef v = SecTaskCopyValueForEntitlement(task, k, NULL);
        char vb[256] = {0};
        if (v && CFGetTypeID(v) == CFBooleanGetTypeID())
            snprintf(vb, sizeof(vb), "true/false=%d",
                     CFBooleanGetValue((CFBooleanRef)v) ? 1 : 0);
        else if (v && CFGetTypeID(v) == CFStringGetTypeID())
            CFStringGetCString((CFStringRef)v, vb, sizeof(vb), kCFStringEncodingUTF8);
        else if (v && CFGetTypeID(v) == CFDataGetTypeID())
            snprintf(vb, sizeof(vb), "<CFData %ld bytes>",
                     (long)CFDataGetLength((CFDataRef)v));
        nk_log("[SIG] entitlement %-52s = %s%s%s%s", ents[i],
               v ? "PRESENT" : "ABSENT",
               vb[0] ? " value=" : "", vb[0] ? vb : "", vb[0] ? "" : "");
        if (v) CFRelease(v);
        CFRelease(k);
    }
    if (task) CFRelease(task);
    nk_log("[SIG] done");
}
