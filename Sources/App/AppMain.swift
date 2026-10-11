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
                    nk_set_home(NSHomeDirectory())
                    nk_state_load()
                    nk_set_log(nkLogBridge)
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
