#include "exploit.h"

/* Слабые заглушки. Реальные модули, появившись, перекроют их без
   правок exploit.c. Без этого файла линковка падает на
   monitor/deep/deep2/sys_fuzz/mach/crafted/cve. */
__attribute__((weak)) void nk_monitor_run(void)     { nk_log("[stub] monitor"); }
__attribute__((weak)) void nk_deep_run(void)        { nk_log("[stub] deep"); }
__attribute__((weak)) void nk_deep2_run(void)       { nk_log("[stub] deep2"); }
__attribute__((weak)) void nk_sys_fuzz(void)        { nk_log("[stub] sys sweep"); }
__attribute__((weak)) void nk_mach_leak_hunt(void)  { nk_log("[stub] mach leak hunt"); }
__attribute__((weak)) void nk_crafted_io_hunt(void) { nk_log("[stub] crafted io hunt"); }
__attribute__((weak)) void nk_cve_2026_65343_kaslr(void)    { nk_log("[stub] AKS OOB"); }
__attribute__((weak)) void nk_cve_2026_aio_kevent_uaf(void) { nk_log("[stub] AIO UAF"); }
