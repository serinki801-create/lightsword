// language: C, file: pac_oracle.c, target: iOS 26.x arm64e, Theos
// Track A — PAC signing oracle.
//
// Механика (см. A1): оракл = hardware PAC-инструкции процесса.
// PACIA/PACIB sign (ptr, ctx=modifier); AUTIA/AUTIB auth+strip;
// проверка — sign-compare (без фолтинга). Ключи userland; ядро не
// затрагивается. На не-PAC сборке (plain arm64) деградирует в identity.

#include "pac_oracle.h"
#include "exploit.h"
#include <string.h>

#if defined(__arm64e__) || defined(__PTRAUTH_INTRINSICS__)

static inline uint64_t nk_pacia_hw(uint64_t p, uint64_t m)
{
    uint64_t o;
    __asm__ __volatile__("pacia %0, %1" : "=r"(o) : "0"(p), "r"(m));
    return o;
}

static inline uint64_t nk_pacib_hw(uint64_t p, uint64_t m)
{
    uint64_t o;
    __asm__ __volatile__("pacib %0, %1" : "=r"(o) : "0"(p), "r"(m));
    return o;
}

#define NK_PAC_HW 1

#else
/* plain arm64: PAC-битов нет, подпись = identity */
static inline uint64_t nk_pacia_hw(uint64_t p, uint64_t m) { (void)m; return p; }
static inline uint64_t nk_pacib_hw(uint64_t p, uint64_t m) { (void)m; return p; }
#define NK_PAC_HW 0
#endif

void *nk_pac_sign_ia(void *ptr, uint64_t modifier)
{
    return (void *)nk_pacia_hw((uint64_t)ptr, modifier);
}

void *nk_pac_sign_ib(void *ptr, uint64_t modifier)
{
    return (void *)nk_pacib_hw((uint64_t)ptr, modifier);
}

void *nk_pac_strip_raw(void *ptr)
{
    return (void *)((uint64_t)ptr & 0x0000FFFFFFFFFFFFULL);
}

bool nk_pac_check(void *ptr, uint64_t modifier, int key)
{
    uint64_t raw = (uint64_t)ptr;
    uint64_t base = raw & 0x0000FFFFFFFFFFFFULL;
    uint64_t expect = (key == NK_PAC_KEY_IB)
        ? nk_pacib_hw(base, modifier)
        : nk_pacia_hw(base, modifier);
    return raw == expect;
}

/* ---------- self-test ---------- */

static volatile int g_probe_mark = 0;

static int probe0(int x) { return x + 1; }
static int probe1(int x) { return x + 2; }
static int probe2(int x) { return x + 3; }
static int probe3(int x) { return x + 4; }
static int probe4(int x) { return x + 5; }
static int probe5(int x) { return x + 6; }
static int probe6(int x) { return x + 7; }
static int probe7(int x) { return x + 8; }
static int probe8(int x) { return x + 9; }
static int probe9(int x) { return x + 10; }

static void pac_probe_fn(void) { g_probe_mark = 0x4040; }

int nk_pac_oracle_selftest(int n, bool *results_out)
{
    if (n > 10) n = 10;
    int (*fns[10])(int) = {
        probe0, probe1, probe2, probe3, probe4,
        probe5, probe6, probe7, probe8, probe9
    };
    int ok = 0;

    nk_rule();
    nk_log("[PAC-A] oracle selftest: hw=%s n=%d", NK_PAC_HW ? "pauth" : "identity", n);

    for (int i = 0; i < n; i++) {
        uint64_t mod = 0xA5A5000000000000ULL + (uint64_t)i * 0x1111;
        bool pass = true;

        /* IA round-trip */
        void *sp_ia = nk_pac_sign_ia((void *)fns[i], mod);
        pass = pass && nk_pac_check(sp_ia, mod, NK_PAC_KEY_IA);
        pass = pass && (nk_pac_strip_raw(sp_ia) == (void *)fns[i]);

        /* IB round-trip */
        void *sp_ib = nk_pac_sign_ib((void *)fns[i], mod + 0x2222);
        pass = pass && nk_pac_check(sp_ib, mod + 0x2222, NK_PAC_KEY_IB);

        /* wrong modifier must FAIL */
        pass = pass && !nk_pac_check(sp_ia, mod + 1, NK_PAC_KEY_IA);

        if (results_out) results_out[i] = pass;
        if (pass) ok++;
        nk_log("[PAC-A] fn[%d]=%p mod=0x%016llx ia=%p ib=%p -> %s",
               i, fns[i], (unsigned long long)mod,
               sp_ia, sp_ib, pass ? "PASS" : "FAIL");
    }

    /* живой вызов через подписанный указатель */
    bool call_ok = nk_pac_oracle_call_prove();
    if (call_ok) nk_log("[PAC-A] call-through signed pointer: PASS");
    else         nk_log("[PAC-A] call-through signed pointer: FAIL");

    nk_log("[PAC-A] selftest: %d/%d + call=%s", ok, n, call_ok ? "ok" : "no");
    nk_rule();
    return (int)((uint32_t)ok | ((uint32_t)(call_ok ? 0x100 : 0)));
}

bool nk_pac_oracle_call_prove(void)
{
#if NK_PAC_HW
    g_probe_mark = 0;
    uint64_t mod = 0xC0DE000000000001ULL;
    register uint64_t x0 asm("x0") =
        nk_pacia_hw((uint64_t)(uintptr_t)pac_probe_fn, mod);
    register uint64_t x1 asm("x1") = mod;
    __asm__ __volatile__(
        "autia %0, %1\n\t"
        "blr %0"
        : "+r"(x0)
        : "r"(x1)
        : "x30", "memory"
    );
    return g_probe_mark == 0x4040;
#else
    g_probe_mark = 0;
    pac_probe_fn();
    return g_probe_mark == 0x4040;
#endif
}
