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
        switch payload.tag {
        case "RUNBEGIN":
            let id = nk_run_begin(payload.msg)
            message.webView?.evaluateJavaScript("window.__setRunId(\(id))")
        case "SELFTESTCLAIM":
            let ok = nk_selftest_claim(nk_run_current()) != 0
            message.webView?.evaluateJavaScript("window.__onClaim(\(ok ? 1 : 0))")
        case "STATUS":
            nk_jsbridge_status(payload.msg)
        default:
            /* durable line first (fsync'd), then the coalesced UI tail */
            nk_jsbridge_log(payload.tag, payload.msg)
            if payload.tag == "RESULT" || payload.tag == "WARN" || payload.tag == "PHASE" {
                NKBridgeSink.shared.post("[\(payload.tag)] \(payload.msg)")
            }
        }
    }
}
