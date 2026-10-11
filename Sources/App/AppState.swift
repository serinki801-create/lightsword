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

    func aioB12() {
        start {
            nk_spray_e1()
            nk_spray_iokit()
            return nk_aio_uaf_b12(10, nil) == 0
        }
    }

    func t0eSpike() {
        start {
            return nk_probe_t0e() == 0
        }
    }

    func t2FrameProbe() {
        start {
            return nk_probe_t2frame(50) == 0
        }
    }

    func t2Dummynet() {
        start {
            return nk_probe_dummynet() == 0
        }
    }

    func guardTest() {
        start {
            return nk_probe_guard_test() == 0
        }
    }

    func resetProbes() {
        nk_state_reset()
        nk_jsbridge_log("STATE", "probe state reset; Guard/T0e/Dummynet/Frame re-enabled")
    }

    func pacSelfTest() {
        start { return nk_pac_oracle_selftest(10, nil) != 0 }
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
}
