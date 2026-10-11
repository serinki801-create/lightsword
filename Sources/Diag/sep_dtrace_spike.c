// language: C, file: sep_dtrace_spike.c, target: iOS 26.2 / 23C55 / arm64e, Theos app sandbox
// T0e — reachability spikes for CVE-2026-20637 (AppleSEPKeyStore UAF) and the
// kernel DTrace entry (CVE-2026-39868 macOS PoC driver).
//
// Gate logic (per T0e):
//   AppleSEPKeyStore IOServiceOpen -> kIOReturnNoAccess / kIOReturnDeviceError
//     from the app sandbox => [DEAD-FROM-SANDBOX], stop.
//   Any successful open (kr == KERN_SUCCESS) => candidate primitive; evaluate
//     reliability against B12 before making it the lead.
//   DTrace device opens: consistent EPERM/EACCES => [DEAD-FROM-SANDBOX].
//   Anything else (EINVAL/EACCES mix, ENOENT) is recorded and re-evaluated.
//
// Run from the "T0e Spike" button; every attempt logs pid/uid, the exact
// kern_return or errno, to Documents via nk_logx (survives reboot).

#include "exploit.h"
#include <IOKit/IOKitLib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/errno.h>

#define SYS_DTRACE 167   /* dtrace syscall on Darwin */

static const char *kr_str(kern_return_t kr)
{
    switch (kr) {
    case KERN_SUCCESS:            return "KERN_SUCCESS";
    case KERN_INVALID_ARGUMENT:   return "KERN_INVALID_ARGUMENT";
    case KERN_FAILURE:            return "KERN_FAILURE";
    case KERN_NO_ACCESS:          return "KERN_NO_ACCESS/kIOReturnNoAccess";
    case kIOReturnBadArgument:    return "kIOReturnBadArgument";
    case kIOReturnNoMemory:       return "kIOReturnNoMemory";
    case kIOReturnNoResources:    return "kIOReturnNoResources";
    case kIOReturnError:          return "kIOReturnError";
    case kIOReturnCannotLock:     return "kIOReturnCannotLock";
    default:                      return "OTHER(check)";
    }
}

/* ---------- AppleSEPKeyStore candidate classes (CVE-2026-20637 surface) --- */
static const char *sep_classes[] = {
    "AppleSEPKeyStore",        /* the CVE-2026-20637 driver, kext: com.apple.driver.AppleSEPKeyStore */
    "AppleSEPCredentialManager",
    "AppleSEPManager",
    "AppleSEPGenericTransfer",
    "ApplePearlSEPDriver",
};

static void sep_spike(void)
{
    int found = 0, reachable = 0;

    for (size_t i = 0; i < sizeof(sep_classes) / sizeof(sep_classes[0]); i++) {
        CFMutableDictionaryRef matching = IOServiceNameMatching(sep_classes[i]);
        if (!matching) {
            nk_logx("T0e", "SEP: IOServiceNameMatching(\"%s\") -> NULL", sep_classes[i]);
            continue;
        }
        io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
        if (!svc) {
            nk_logx("T0e", "SEP: %-24s GetMatchingService=0 (not registered/visible)", sep_classes[i]);
            continue;
        }
        found++;
        nk_logx("T0e", "SEP: %-24s service=0x%x — probing user-client types 0..5",
                sep_classes[i], svc);

        /* Apple SEP user clients use type 0 for the primary external method
         * dispatch; some drivers accept more. Probe 0..5; log every kr. */
        for (io_connect_t type = 0; type <= 5; type++) {
            io_connect_t conn = IO_OBJECT_NULL;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
            if (kr == KERN_SUCCESS) {
                nk_logx("T0e", "SEP: %-24s type=%u IOServiceOpen=KERN_SUCCESS conn=0x%x  <== REACHABLE",
                        sep_classes[i], type, conn);
                IOServiceClose(conn);
                reachable++;
            } else {
                nk_logx("T0e", "SEP: %-24s type=%u IOServiceOpen=0x%08x %s",
                        sep_classes[i], type, kr, kr_str(kr));
            }
        }
        IOObjectRelease(svc);
    }

    if (found == 0) {
        nk_logx("T0e", "SEP VERDICT: no AppleSEP* service visible from sandbox "
                "(matching returned nothing) — [DEAD-FROM-SANDBOX]");
    } else if (reachable == 0) {
        nk_logx("T0e", "SEP VERDICT: %d service(s) visible, 0 openable from "
                "sandbox — [DEAD-FROM-SANDBOX]");
    } else {
        nk_logx("T0e", "SEP VERDICT: %d service(s), %d openable — CANDIDATE, "
                "evaluate vs B12 before lead change", found, reachable);
    }
}

/* ---------- DTrace entry points (macOS PoC driver, CVE-2026-39868) ---------- */
static void dtrace_spike(void)
{
    static const char *dt_devs[] = {
        "/dev/dtrace",        /* dtrace device: ioctl-driven providers */
        "/dev/dtracehelper", /* helper used by unprivileged probes */
        "/dev/fbt",
        "/dev/profile",
        "/dev/systrace",
        "/dev/lockstat",
    };

    int opened = 0, eperm = 0, enoent = 0, other = 0;

    for (size_t i = 0; i < sizeof(dt_devs) / sizeof(dt_devs[0]); i++) {
        int fd = open(dt_devs[i], O_RDONLY);
        if (fd >= 0) {
            nk_logx("T0e", "DT: open(\"%s\", O_RDONLY)=%d  <== OPENED", dt_devs[i], fd);
            close(fd);
            opened++;
            continue;
        }
        int e = errno;
        const char *name = "OTHER";
        switch (e) {
        case ENOENT:   name = "ENOENT";  enoent++;  break;
        case EPERM:    name = "EPERM";   eperm++;   break;
        case EACCES:   name = "EACCES";  eperm++;   break;
        case EINVAL:   name = "EINVAL";  other++;   break;
        case EBUSY:    name = "EBUSY";   other++;   break;
        default:       name = "OTHER";   other++;   break;
        }
        nk_logx("T0e", "DT: open(\"%s\", O_RDONLY)=-1 errno=%d %s", dt_devs[i], e, name);
    }

    /* dtrace(2) syscall itself: cmd values from the macOS PoC are applied here
     * only if the device opens; a null-arg call first to classify the entry. */
    long r = syscall(SYS_DTRACE, 0, 0, 0, 0, 0, 0);
    nk_logx("T0e", "DT: syscall(%d /*dtrace*/, NULL...) = %ld errno=%d",
            SYS_DTRACE, r, errno);

    if (opened == 0 && enoent == (int)(sizeof(dt_devs) / sizeof(dt_devs[0]))) {
        nk_logx("T0e", "DT VERDICT: no dtrace devices present (all ENOENT) — [DEAD-FROM-SANDBOX]");
    } else if (opened == 0 && eperm > 0) {
        nk_logx("T0e", "DT VERDICT: devices present, consistently EPERM/EACCES — [DEAD-FROM-SANDBOX]");
    } else if (opened > 0) {
        nk_logx("T0e", "DT VERDICT: %d device(s) opened — CANDIDATE, run macOS PoC "
                "cmd sequence next", opened);
    } else {
        nk_logx("T0e", "DT VERDICT: mixed errors (EINVAL/EBUSY/OTHER=%d) — INCONCLUSIVE, re-run", other);
    }
}

int nk_t0e_spike(void)
{
    nk_crash_guard_install(NULL); /* app-launch guard already active; re-assert */
    nk_rule();
    nk_log("[T0e] SEP/DTrace reachability spike: pid=%d uid=%d", getpid(), getuid());
    sep_spike();
    dtrace_spike();
    nk_rule();
    return 0;
}
