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
        guard !running else { return }

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