#include "exploit.h"
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/host_info.h>
#include <mach/processor.h>
#include <mach/thread_info.h>

#define MACH_LEAK_MAXLOG 16

static int s_mach_leaks = 0;
static int s_mach_logs = 0;

static int ml_is_kernel_va(uint64_t v) {
    uint32_t hi = (uint32_t)(v >> 32);
    return (hi == 0xfffffff0 || hi == 0xffffffe0 ||
            hi == 0xfffffe00 || hi == 0xffffff80);
}

static int ml_is_poison(uint64_t v) {
    if (v == 0) return 1;
    uint8_t b0 = (uint8_t)(v & 0xff);
    int same = 1;
    for (int i = 1; i < 8; i++)
        if (((v >> (8 * i)) & 0xff) != b0) { same = 0; break; }
    if (same) return 1;
    if (v == 0xDEADBEEFDEADBEEFULL) return 1;
    if (v == 0xAAAAAAAAAAAAAAAAULL) return 1;
    if ((v & 0xFFFFFFFFULL) == 0xDEADBEEFULL) return 1;
    return 0;
}

static void ml_scan(const void *buf, size_t n, const char *tag) {
    if (!buf || n < 8) return;
    const uint8_t *p = buf;
    for (size_t off = 0; off + 8 <= n; off += 8) {
        uint64_t v;
        memcpy(&v, p + off, 8);
        if (ml_is_kernel_va(v) && !ml_is_poison(v)) {
            s_mach_leaks++;
            if (s_mach_logs < MACH_LEAK_MAXLOG) {
                s_mach_logs++;
                nk_log("[mach LEAK] %s off=0x%zx ptr=0x%016llx",
                       tag, off, (unsigned long long)v);
            }
        }
    }
}

void nk_mach_leak_hunt(void) {
    nk_log("[mach] sandbox-reachable Mach surface hunt (read-only)");
    s_mach_leaks = 0;
    s_mach_logs = 0;

    mach_port_t task = mach_task_self();
    mach_port_t host = mach_host_self();

    for (int i = 1; i <= 6; i++) {
        mach_port_t p = MACH_PORT_NULL;
        kern_return_t kr = host_get_special_port(host, HOST_LOCAL_NODE, i, &p);
        if (kr == KERN_SUCCESS && p != MACH_PORT_NULL) {
            nk_log("[mach ANOM] host special port %d GRANTED from sandbox", i);
            s_mach_leaks++;
            mach_port_deallocate(task, p);
        }
    }

    processor_set_t ps = MACH_PORT_NULL;
    kern_return_t kr = processor_set_default(host, &ps);
    if (kr == KERN_SUCCESS && ps != MACH_PORT_NULL) {
        task_array_t tasks = NULL;
        mach_msg_type_number_t cnt = 0;
        kern_return_t kr2 = processor_set_tasks(ps, &tasks, &cnt);
        nk_log("[mach] processor_set_tasks kr=%d cnt=%u", kr2, cnt);
        if (kr2 == KERN_SUCCESS && cnt > 0 && tasks) {
            nk_log("[mach ANOM] processor_set_tasks returned %u task ports", cnt);
            s_mach_leaks++;
            for (mach_msg_type_number_t i = 0; i < cnt; i++)
                mach_port_deallocate(task, tasks[i]);
            vm_deallocate(task, (vm_address_t)tasks, cnt * sizeof(task_t));
        }
        mach_port_deallocate(task, ps);
    }

    {
        struct task_dyld_info dyld_info;
        mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
        kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt);
        if (kr == KERN_SUCCESS)
            ml_scan(&dyld_info, sizeof(dyld_info), "task_dyld_info");

        struct task_basic_info_64 basic_info;
        cnt = TASK_BASIC_INFO_64_COUNT;
        kr = task_info(task, TASK_BASIC_INFO_64, (task_info_t)&basic_info, &cnt);
        if (kr == KERN_SUCCESS)
            ml_scan(&basic_info, sizeof(basic_info), "task_basic_info");
    }

    {
        struct host_basic_info hi;
        mach_msg_type_number_t cnt = HOST_BASIC_INFO_COUNT;
        kr = host_info(host, HOST_BASIC_INFO, (host_info_t)&hi, &cnt);
        if (kr == KERN_SUCCESS)
            ml_scan(&hi, sizeof(hi), "host_basic_info");
    }

    {
        struct thread_basic_info tbi;
        mach_msg_type_number_t cnt = THREAD_BASIC_INFO_COUNT;
        kr = thread_info(mach_thread_self(), THREAD_BASIC_INFO,
                         (thread_info_t)&tbi, &cnt);
        if (kr == KERN_SUCCESS)
            ml_scan(&tbi, sizeof(tbi), "thread_basic_info");
    }

    nk_log("[mach] hunt done leaks=%d", s_mach_leaks);
}
