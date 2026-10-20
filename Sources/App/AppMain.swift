import SwiftUI

@main
struct NatsukApp: App {
    @StateObject private var state = AppState.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(state)
                .preferredColorScheme(.dark)
                .onAppear {
                    /* LC does not export HOME for its in-process guest: without
                     * this every C-side path (guard, stage, trace.log, state)
                     * resolves nowhere and all diagnostics vanish. Then the
                     * state machine adopts last session: probes that died
                     * uncatchably (SIGKILL/Mach) are marked DEAD, and the last
                     * breadcrumb line goes straight to the UI log. */
                    /* The authoritative Documents dir for this guest comes from
                       FileManager (it reflects the real LC guest container).
                       NSHomeDirectory() can point at the outer container or be
                       empty, which breaks every C-side path resolution. */
                    let fmDocs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
                    let realHome = (fmDocs?.deletingLastPathComponent().path) ?? NSHomeDirectory()
                    nk_set_home(realHome)
                    AppState.shared.append("HOME: \(realHome)")
                    nk_state_load()
                    nk_set_log(nkLogBridge)
                    /* Durable per-probe logs next to trace.log. Open them here
                     * so the paths are known before any probe runs, and show
                     * the absolute paths in the UI — the guest container UUID
                     * is not guessable from inside the app. */
                    nk_doc_log_open("srk801.log")
                    nk_doc_log_open("oob64.log")
                    /* Diagnostic: write a marker file to every candidate home
                       so we can see which path is actually writable. */
                    for nm in ["srk801.log", "oob64.log", "aio_uaf.log"] {
                        var p = [CChar](repeating: 0, count: 1024)
                        nk_doc_log_path(nm, &p, 1024)
                        AppState.shared.append("LOG: \(String(cString: p))")
                    }
                    /* FileManager-based diagnostic (Swift-native, no C) */
                    if let docsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
                        /* Ensure Documents exists */
                        try? FileManager.default.createDirectory(at: docsURL, withIntermediateDirectories: true)
                        let markerURL = docsURL.appendingPathComponent("swift_marker.txt")
                        do {
                            try "marker".write(to: markerURL, atomically: true, encoding: .utf8)
                            AppState.shared.append("SWIFT OK: \(markerURL.path)")
                        } catch {
                            AppState.shared.append("SWIFT FAIL: \(markerURL.path) err=\(error)")
                        }
                        /* Also write a C-style path index */
                        var idx = [CChar](repeating: 0, count: 1024)
                        nk_doc_log_path("srk801_paths.txt", &idx, 1024)
                        let idxPath = String(cString: idx)
                        var paths = "=== srk801 log paths ===\n"
                        for nm in ["srk801.log", "oob64.log", "aio_uaf.log", "trace.log"] {
                            var p = [CChar](repeating: 0, count: 1024)
                            nk_doc_log_path(nm, &p, 1024)
                            paths += String(cString: p) + "\n"
                        }
                        try? paths.write(to: URL(fileURLWithPath: idxPath), atomically: true, encoding: .utf8)
                        AppState.shared.append("IDX: \(idxPath)")
                    } else {
                        AppState.shared.append("NO DOCUMENTS DIR")
                    }
                    var lp = [CChar](repeating: 0, count: 1024)
                    for nm in ["srk801.log", "oob64.log", "trace.log"] {
                        nk_home_path(nm, &lp, 1024)
                        AppState.shared.append("LOG: \(String(cString: lp))")
                    }
                    var lb = [CChar](repeating: 0, count: 512)
                    let lb_len = lb.withUnsafeMutableBufferPointer {
                        nk_state_last_breadcrumb($0.baseAddress, 512)
                    }
                    let lb_text: String
                    switch lb_len {
                    case 1...:     lb_text = String(cString: lb)
                    case -1:       lb_text = "NO_TRACE_LOG"
                    default:       lb_text = "EMPTY_TRACE"
                    }
                    AppState.shared.append("LAST BEFORE DEATH: \(lb_text)")
                    if UserDefaults.standard.bool(forKey: "auto_run") {
                        nk_async_main_after(0.5) {
                            state.run()
                        }
                    }
                }
        }
    }
}
