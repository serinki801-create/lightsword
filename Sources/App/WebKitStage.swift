// language: Swift, file: WebKitStage.swift, target: iOS 26.2 / 23C55 / arm64e
// WebKit stage host. The WKWebView is a PROCESS SINGLETON (WebKitHolder):
// the bridge writes every line to Documents/trace.log (fsync) and the UI tail
// is coalesced at 10 Hz — but any per-line @Published churn still re-rendered
// the sheet and rebuilt the webView mid-trigger (observed: run ids increment
// every ~10 s inside PHASE 2/3 with no FATAL). A singleton cannot be rebuilt
// by SwiftUI: reloads are now only explicit (Reload button) or a real
// webContentProcessDidTerminate.
//
// RULES:
// 1. makeUIView NEVER writes @State/@Binding.
// 2. webContentProcessDidTerminate -> one FATAL line via C, NEVER auto-reload.
// 3. Dedicated WKProcessPool.

import SwiftUI
import WebKit
import Foundation

final class WebKitHolder {
    static let shared = WebKitHolder()

    let webView: WKWebView
    private let messageHandler = NKScriptMessageHandler()
    private let processPool = WKProcessPool()
    private var loaded = false
    var onState: ((String) -> Void)?

    private init() {
        nk_jsbridge_log("WK", "holder init (process singleton)")
        let config = WKWebViewConfiguration()
        config.processPool = processPool
        config.userContentController.add(messageHandler, name: NKBridge.handler)
        webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = WebKitCoordinator(holder: self)
        nk_jsbridge_log("WK", "WKWebView created")
    }

    func ensureLoaded() {
        guard !loaded else { return }
        loaded = true
        load()
    }

    func reload() {
        load()
    }

    private func load() {
        guard let url = Bundle.main.url(forResource: "exploit",
                                        withExtension: "html",
                                        subdirectory: "webkit") else {
            nk_jsbridge_log("WKERR", "bundle page Resources/webkit/exploit.html not found")
            onState?("page missing")
            return
        }
        nk_jsbridge_log("WKLOAD", url.path)
        webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
    }
}

final class WebKitCoordinator: NSObject, WKNavigationDelegate {
    let holder: WebKitHolder

    init(holder: WebKitHolder) {
        self.holder = holder
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        nk_jsbridge_log("WKLOAD", "main frame finished")
        holder.onState?("loaded")
    }

    func webView(_ webView: WKWebView, webContentProcessDidTerminate: WKWebView) {
        nk_fatal_webcontent()
        holder.onState?("terminated")
    }

    func webView(_ webView: WKWebView,
                 didFail navigation: WKNavigation!,
                 withError error: Error) {
        nk_jsbridge_log("WKERR", "nav failed: \(error.localizedDescription)")
        holder.onState?("failed")
    }

    func webView(_ webView: WKWebView,
                 didFailProvisionalNavigation navigation: WKNavigation!,
                 withError error: Error) {
        nk_jsbridge_log("WKERR", "provisional nav failed: \(error.localizedDescription)")
        holder.onState?("failed")
    }
}

struct WebKitStageView: View {
    @EnvironmentObject var state: AppState
    @State private var loadState: String = "idle"

    var body: some View {
        ZStack(alignment: .bottom) {
            WebKitStageRepresentable()
                .ignoresSafeArea(.container, edges: .bottom)
            VStack(spacing: 4) {
                Text(state.t("WebKit chassis", "Шасси WebKit"))
                    .font(.caption.bold())
                Text(loadState)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundColor(.secondary)
            }
            .padding(6)
            .frame(maxWidth: .infinity)
            .background(.ultraThinMaterial)
        }
        .navigationTitle(state.t("WebKit Stage", "Стейдж WebKit"))
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(state.t("Reload", "Перезагрузить")) { WebKitHolder.shared.reload() }
            }
        }
        .onAppear {
            WebKitHolder.shared.ensureLoaded()
            WebKitHolder.shared.onState = { s in nk_async_main { loadState = s } }
        }
        .onDisappear { WebKitHolder.shared.onState = nil }
    }
}

struct WebKitStageRepresentable: UIViewRepresentable {
    func makeUIView(context: Context) -> WKWebView {
        WebKitHolder.shared.ensureLoaded()
        return WebKitHolder.shared.webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}
}
