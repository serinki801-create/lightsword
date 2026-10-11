#include "exploit.h"
#include <IOKit/IOKitLib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#define MON_MAX_SERVICES 2048
#define MON_MAX_NAME     128

typedef struct {
    char name[MON_MAX_NAME];
    int  open_types;
} mon_service_t;

static mon_service_t mon_services[MON_MAX_SERVICES];
static int           mon_nservices = 0;

static int mon_is_poison(uint64_t v) {
    if (v == 0) return 1;
    uint8_t b0 = (uint8_t)(v & 0xff);
    int same = 1;
    for (int i = 1; i < 8; i++)
        if (((v >> (8*i)) & 0xff) != b0) { same = 0; break; }
    if (same) return 1;
    if (v == 0xDEADBEEFDEADBEEFULL) return 1;
    if (v == 0xAAAAAAAAAAAAAAAAULL) return 1;
    if (v == 0x5555555555555555ULL) return 1;
    if (v == 0xCDCDCDCDCDCDCDCDULL) return 1;
    if (v == 0xFDFDFDFDFDFDFDFDULL) return 1;
    if (v == 0xABABABABABABABABULL) return 1;
    if ((v & 0xFFFFFFFF) == 0xDEADBEEFULL) return 1;
    return 0;
}

static int mon_is_kernel_va(uint64_t v) {
    uint32_t hi = (uint32_t)(v >> 32);
    if (hi == 0xfffffff0) return 1;
    if (hi == 0xffffffe0) return 1;
    if (hi == 0xfffffe00) return 1;
    if (hi == 0xffffff80) return 1;
    return 0;
}

static const char *mon_outdir(void) {
    static char dir[512];
    const char *home = getenv("HOME");
    if (!home || !home[0]) home = "/var/mobile";
    snprintf(dir, sizeof(dir), "%s/Documents", home);
    if (mkdir(dir, 0755) != 0 && errno != EEXIST)
        snprintf(dir, sizeof(dir), "/tmp");
    return dir;
}

static int mon_find_or_add(const char *name) {
    for (int i = 0; i < mon_nservices; i++)
        if (strcmp(mon_services[i].name, name) == 0) return i;
    if (mon_nservices >= MON_MAX_SERVICES) return -1;
    snprintf(mon_services[mon_nservices].name, MON_MAX_NAME, "%s", name);
    mon_services[mon_nservices].open_types = 0;
    return mon_nservices++;
}

static int mon_enumerate_iokit(void) {
    mon_nservices = 0;
    CFMutableDictionaryRef matching = IOServiceMatching("IOService");
    if (!matching) return -1;
    io_iterator_t it = 0;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &it);
    if (kr != KERN_SUCCESS) return -1;
    io_service_t svc;
    int total_seen = 0;
    while ((svc = IOIteratorNext(it))) {
        total_seen++;
        io_name_t name;
        if (IORegistryEntryGetName(svc, name) == KERN_SUCCESS) {
            int idx = mon_find_or_add(name);
            if (idx >= 0) {
                for (int t = 0; t < 4; t++) {
                    io_connect_t conn = 0;
                    if (IOServiceOpen(svc, mach_task_self(), t, &conn) == KERN_SUCCESS) {
                        mon_services[idx].open_types |= (1 << t);
                        IOServiceClose(conn);
                    }
                }
            }
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    nk_log("[monitor] total IOKit services seen: %d (unique captured: %d)",
        total_seen, mon_nservices);
    return mon_nservices;
}

static int mon_scan_pointers(FILE *jf) {
    mach_vm_address_t addr = 0;
    int found = 0, regions = 0;
    while (regions < 4096 && found <= 64) {
        mach_vm_size_t size = 0;
        uint32_t depth = 4096;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(),
            &addr, &size, &depth, (vm_region_recurse_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS) break;
        regions++;
        if ((info.protection & VM_PROT_READ) && size >= 8) {
            size_t words = size / 8;
            if (words > 4096) words = 4096;
            volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)addr;
            for (size_t i = 0; i < words && found <= 64; i += 16) {
                uint64_t v = p[i];
                if (mon_is_kernel_va(v) && !mon_is_poison(v)) {
                    if (jf) fprintf(jf,
                        "    { \"va\": \"0x%llx\", \"region\": \"0x%llx\" },\n",
                        (unsigned long long)v, (unsigned long long)addr);
                    found++;
                }
            }
        }
        addr += size;
    }
    return found;
}

static void mon_diff(const char *old_path, const char *new_path) {
    static char old_lines[MON_MAX_SERVICES][MON_MAX_NAME + 16];
    static char new_lines[MON_MAX_SERVICES][MON_MAX_NAME + 16];
    char line[MON_MAX_NAME + 16];
    int n_old = 0, n_new = 0;

    FILE *of = fopen(old_path, "r");
    if (!of) {
        nk_log("[monitor] no previous snapshot — baseline saved");
        return;
    }
    while (fgets(line, sizeof(line), of) && n_old < MON_MAX_SERVICES) {
        line[strcspn(line, "\n")] = 0;
        snprintf(old_lines[n_old++], MON_MAX_NAME + 16, "%s", line);
    }
    fclose(of);

    FILE *nf = fopen(new_path, "r");
    if (nf) {
        while (fgets(line, sizeof(line), nf) && n_new < MON_MAX_SERVICES) {
            line[strcspn(line, "\n")] = 0;
            snprintf(new_lines[n_new++], MON_MAX_NAME + 16, "%s", line);
        }
        fclose(nf);
    }

    int added = 0, removed = 0;
    for (int i = 0; i < n_new; i++) {
        int hit = 0;
        for (int j = 0; j < n_old; j++)
            if (strcmp(new_lines[i], old_lines[j]) == 0) { hit = 1; break; }
        if (!hit) { nk_log("[monitor] ADDED:   %s", new_lines[i]); added++; }
    }
    for (int j = 0; j < n_old; j++) {
        int hit = 0;
        for (int i = 0; i < n_new; i++)
            if (strcmp(old_lines[j], new_lines[i]) == 0) { hit = 1; break; }
        if (!hit) { nk_log("[monitor] REMOVED: %s", old_lines[j]); removed++; }
    }
    nk_log("[monitor] diff vs previous: +%d / -%d unique openable services", added, removed);
}

void nk_monitor_run(void) {
    nk_rule();
    nk_log("[monitor] surface recon start (read-only, deduplicated)");

    struct timeval tv; gettimeofday(&tv, NULL);
    long long now = (long long)tv.tv_sec;
    nk_log("[monitor] timestamp=%lld", now);

    int n = mon_enumerate_iokit();
    int openable = 0;
    for (int i = 0; i < mon_nservices; i++)
        if (mon_services[i].open_types) openable++;
    nk_log("[monitor] unique IOKit services: %d", n);
    nk_log("[monitor] unique openable user clients: %d", openable);

    const char *dir = mon_outdir();
    char json_path[600], snap_path[600], latest_path[600];
    snprintf(json_path,   sizeof(json_path),   "%s/natsuk1_monitor_%lld.json", dir, now);
    snprintf(snap_path,   sizeof(snap_path),   "%s/natsuk1_surface_%lld.txt",  dir, now);
    snprintf(latest_path, sizeof(latest_path), "%s/natsuk1_surface_latest.txt", dir);

    FILE *jf = fopen(json_path, "w");
    FILE *sf = fopen(snap_path, "w");
    if (jf) {
        fprintf(jf, "{\n  \"timestamp\": %lld,\n  \"build\": \"23C55\",\n", now);
        fprintf(jf, "  \"device\": \"iPhone14,5\",\n");
        fprintf(jf, "  \"services_unique\": %d,\n  \"services_openable\": %d,\n", n, openable);
        fprintf(jf, "  \"openable_list\": [\n");
    }
    for (int i = 0; i < mon_nservices; i++) {
        if (mon_services[i].open_types) {
            if (jf) fprintf(jf, "    { \"name\": \"%s\", \"types\": %d },\n",
                mon_services[i].name, mon_services[i].open_types);
            if (sf) fprintf(sf, "%s|%d\n",
                mon_services[i].name, mon_services[i].open_types);
            nk_log("[monitor] openable: %s (types mask %d)",
                mon_services[i].name, mon_services[i].open_types);
        }
    }
    if (jf) fprintf(jf, "  ],\n  \"kernel_va_candidates\": [\n");

    int kvas = mon_scan_pointers(jf);
    if (jf) {
        fprintf(jf, "  ],\n  \"kernel_va_count\": %d\n}\n", kvas);
        fclose(jf);
    }
    if (sf) fclose(sf);

    nk_log("[monitor] kernel-VA candidates (poison-filtered): %d", kvas);
    nk_log("[monitor] report -> %s", json_path);

    mon_diff(latest_path, snap_path);

    FILE *lf = fopen(latest_path, "w");
    if (lf) {
        for (int i = 0; i < mon_nservices; i++)
            if (mon_services[i].open_types)
                fprintf(lf, "%s|%d\n", mon_services[i].name, mon_services[i].open_types);
        fclose(lf);
    }

    nk_log("[monitor] done");
    nk_rule();
}
