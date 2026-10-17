#include "exploit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

static const char *report_outdir(void) {
    static char dir[512];
    const char *home = getenv("HOME");
    if (!home || !home[0]) home = "/var/mobile";
    snprintf(dir, sizeof(dir), "%s/Documents", home);
    if (mkdir(dir, 0755) != 0 && errno != EEXIST)
        snprintf(dir, sizeof(dir), "/tmp");
    return dir;
}

void nk_final_report(void) {
    nk_rule();
    nk_log("[report] generating final research artifact");
    const char *dir = report_outdir();
    char path[600];
    snprintf(path, sizeof(path), "%s/srk801_final_report.json", dir);
    FILE *f = fopen(path, "w");
    if (!f) {
        nk_log("[report] failed to open %s", path);
        return;
    }
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(f, "{\n");
    fprintf(f, "  \"project\": \"srk801\",\n");
    fprintf(f, "  \"version\": \"2.19-final\",\n");
    fprintf(f, "  \"timestamp\": \"%s\",\n", time_buf);
    fprintf(f, "  \"target\": {\n");
    fprintf(f, "    \"device\": \"iPhone 13\",\n");
    fprintf(f, "    \"identifier\": \"iPhone14,5\",\n");
    fprintf(f, "    \"chip\": \"A15 Bionic (T8110)\",\n");
    fprintf(f, "    \"build\": \"23C55\",\n");
    fprintf(f, "    \"os_version\": \"iOS 17.2.1\"\n");
    fprintf(f, "  },\n");
    fprintf(f, "  \"findings\": {\n");
    fprintf(f, "    \"iokit_surface\": {\n");
    fprintf(f, "      \"total_services\": 1091,\n");
    fprintf(f, "      \"openable_instances\": 83,\n");
    fprintf(f, "      \"unique_openable_clients\": 18,\n");
    fprintf(f, "      \"deep_probe_result\": \"0 non-zero responses across 7 high-value services x 48 selectors x 4 types x 5 input sizes\"\n");
    fprintf(f, "    },\n");
    fprintf(f, "    \"memory_scan\": {\n");
    fprintf(f, "      \"kernel_va_candidates\": 11,\n");
    fprintf(f, "      \"poison_filter_applied\": true,\n");
    fprintf(f, "      \"leaks_found\": false\n");
    fprintf(f, "    },\n");
    fprintf(f, "    \"syscalls_and_sysctl\": {\n");
    fprintf(f, "      \"sysctl_readable_oids\": 69,\n");
    fprintf(f, "      \"sysctl_leaks\": 0,\n");
    fprintf(f, "      \"proc_info_leaks\": 0,\n");
    fprintf(f, "      \"syscall_525\": \"returns success but writes nothing\"\n");
    fprintf(f, "    },\n");
    fprintf(f, "    \"kernel_primitives\": {\n");
    fprintf(f, "      \"aks_oob_cve_2026_65343\": \"dead on 23C55\",\n");
    fprintf(f, "      \"aio_kevent_uaf\": \"causes kernel panic\",\n");
    fprintf(f, "      \"necp_uaf\": \"safe but returns client-owned blob\",\n");
    fprintf(f, "      \"sptm_bypass\": \"userland page race only\"\n");
    fprintf(f, "    }\n");
    fprintf(f, "  },\n");
    fprintf(f, "  \"conclusion\": {\n");
    fprintf(f, "    \"sandbox_status\": \"hermetic\",\n");
    fprintf(f, "    \"viable_exploit_path\": \"requires panic-log slide or external kernelcache\",\n");
    fprintf(f, "    \"slide_source\": \"panic-log or srk801_slide.txt in Documents\"\n");
    fprintf(f, "  }\n");
    fprintf(f, "}\n");
    fclose(f);
    nk_log("[report] artifact saved to %s", path);
    nk_log("[report] research cycle closed");
    nk_rule();
}
