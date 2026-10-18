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
    private var watchdogTick: Int = 0
    /* Shared reload budget through the page's ?r=N query. The in-page JS
       watchdog reloads at 10 s (location.href = exploit.html?r=N+1), this one
       at 12 s. The 16:42 race fired both inside one silence window and
       produced 5 page-loads over milliseconds — and every load() reset r to 0
       because the query was never carried, so the budget lived only in the
       dying page's memory and every native reload handed the next page a clean
       counter. r now survives every navigation: load() advances it, the JS
       counts the same number, and both sides disarm at the same cap. */
    private var lastPageR: Int = -1
    private static let burstMax = 12   /* matches WD_BURST_MAX in exploit.js */

    private func currentPageR() -> Int {
        /* WKWebView loses the query from url after the first loadFileURL
           (device 14:40:41: live page was ?r=2&aar=1, webView.url reported
           ?r=1 — the burst budget reset to zero). The authoritative r is the
           one WE put on the last navigation: lastPageR. webView.url is only
           the fallback for the very first load. */
        if let q = webView.url?.query {
            for part in q.split(separator: "&") {
                if part.hasPrefix("r=") { return Int(part.dropFirst(2)) ?? 0 }
            }
        }
        return max(lastPageR, 0)
    }

    /* AAR sticky: the W-T2 renderer primitives as a session product. The flag
       rides the page query (?aar=1) across every reload, so the JS side keeps
       the sweep-killer auto-pivot OFF and runs a keepalive echo instead —
       see aarKeepaliveStart in exploit.js.
       The truth lives IN-MEMORY: the 14:40 device pass showed the LiveContainer
       guest's UserDefaults suite not serving back a set() from seconds earlier
       (toggle ON twice in a row). UserDefaults is best-effort write-through
       for the next app launch only. */
    private var aarStickyMem: Bool = UserDefaults.standard.bool(forKey: "aarSticky")
    var aarSticky: Bool {
        get { aarStickyMem }
        set {
            aarStickyMem = newValue
            UserDefaults.standard.set(newValue, forKey: "aarSticky")
        }
    }

    func toggleAarSticky() {
        let v = !aarSticky
        aarSticky = v
        nk_jsbridge_log("WK", "aar-sticky \(v ? "ON" : "OFF") — reloading page")
        reload()
    }

    private init() {
        nk_jsbridge_log("WK", "holder init (process singleton)")
        let config = WKWebViewConfiguration()
        config.processPool = processPool
        config.userContentController.add(messageHandler, name: NKBridge.handler)
        webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = WebKitCoordinator(holder: self)
        /* native watchdog: the 18:23 device pass died silently after a clean
           walk — no next candidate, no new run for 49 s, no FATAL (the
           LiveContainer guest never fires webContentProcessDidTerminate). The
           JS-side watchdog covers hangs; this one — running in the APP
           process — survives a hard renderer death: scan activity within the
           last 90 s plus >6 s of total bridge silence = reload. Idle pages are
           left alone (their last SCAN is stale). Heartbeat every tick: the
           19:14 pass died at Cpp idx=2 and the watchdog never FIRED and never
           logged — this line answers "timer alive?" from the log alone. */
        watchdogTick = 0
        Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            let any = NKBridge.lastAnyAt.timeIntervalSinceNow
            let scan = NKBridge.lastScanAt.timeIntervalSinceNow
            let hunt = NKBridge.huntAt.timeIntervalSinceNow
            self.watchdogTick += 1
            if self.watchdogTick % 15 == 1 {
                /* .distantPast is the "never spoke" sentinel — print it as such
                   instead of a 6.4e10 s reading (the 15:16 dead run) */
                func since(_ d: Date) -> String {
                    if d == .distantPast { return "never" }
                    return String(format: "%.1fs", -d.timeIntervalSinceNow)
                }
                nk_jsbridge_log("WK", String(format: "watchdog tick=%ld anySilence=%@ scanSilence=%@ huntSilence=%@",
                                             self.watchdogTick, since(NKBridge.lastAnyAt),
                                             since(NKBridge.lastScanAt), since(NKBridge.huntAt)))
            }
            /* Two separated rules (the 20:45 pass falsely reloaded a live
               PHASE-0 run at 6.7 s — a legit phase):
               - hunt in flight ("W-T3 pivot begin" seen) and >12 s of total
                 silence: the in-page JS watchdog fires at 10 s if the thread
                 is alive, so 12 s means a hard renderer death (payload /
                 GC-window kills);
               - pre-arm total silence >300 s: PHASE 0 legitimately grinds up
                 to ~180 s (600 rounds), the detector logs every ~5.3 s — only
                 a real death hangs this long. */
            let huntDead = hunt > -180 && any < -12
            let preArmDead = any < -300
            /* RAPID-RELOAD BREAKER: the 16:30 pass entered the restart loop and
               the 16:42 race fired the JS watchdog and this one inside the same
               silence window — 5 page-loads over milliseconds, each cycle
               burning ~12 s of the session. A dead renderer is normal; a dozen
               lives is a broken install or a poisoned heap. The budget is now
               the shared ?r counter: every navigation (either watchdog or the
               Reload button) advances it, and at r >= burstMax both sides stop
               reloading and say so, so the state is visible instead of a loop. */
            if huntDead || preArmDead {
                let pageR = currentPageR()
                if lastPageR >= 0 && pageR != lastPageR {
                    /* the page navigated since the last tick: the in-page JS
                       watchdog (10 s) already owns this cycle and a fresh run
                       just began — give it its full silence budget */
                    nk_jsbridge_log("WK", String(format: "native watchdog: page r=%ld since last tick %ld — JS reload owns the cycle, standing down",
                                                 pageR, lastPageR))
                    lastPageR = pageR
                } else if pageR >= WebKitHolder.burstMax {
                    nk_jsbridge_log("WK", String(format: "native watchdog: r=%ld >= %ld — DISARMED. Restart the app (fresh process) before more runs.",
                                                 pageR, WebKitHolder.burstMax))
                } else {
                    lastPageR = pageR
                    nk_jsbridge_log("WK", String(format: "native watchdog: silence %.1fs hunt=%.1fs — reload (huntDead=%d preArm=%d, r=%ld/%ld)",
                                                 -any, -hunt, huntDead ? 1 : 0, preArmDead ? 1 : 0,
                                                 pageR, WebKitHolder.burstMax))
                    NKBridge.lastScanAt = .distantPast
                    NKBridge.huntAt = .distantPast
                    NKBridge.lastAnyAt = Date()   /* the reload itself is activity */
                    self.reload()
                }
            }
        }
        nk_jsbridge_log("WK", "WKWebView created + watchdog armed")
    }

    func ensureLoaded() {
        guard !loaded else { return }
        loaded = true
        load()
    }

    func reload() {
        load()
    }

    /* The JS watchdog navigates itself (location.href = exploit.html?r=N+1)
       without asking native — and webView.url never carries the query, so the
       native budget only learns the true r from the page itself. */
    func notePageR(_ n: Int) {
        if n > lastPageR { lastPageR = n }
    }

    /* W-T3: fire the pivot straight into the page. The HTML buttons scroll
       away under the log growth (the page keeps its scroll pinned at the
       bottom), so a native entry point is the reliable path — evaluate on
       the singleton's webView, which exists whether or not the sheet is
       presented. */
    func firePivot() {
        ensureLoaded()
        webView.evaluateJavaScript("window.nkNativePivot && window.nkNativePivot()")
        nk_jsbridge_log("WK", "native pivot dispatched to page")
    }

    /* B12 -> WebKit handoff: the kernel read channel (aio-kevent read ->
       renderer task mappings) supplies the wasm code mapping base. The pivot
       then skips unitRwxHunt's pointer chase and scans this region for the
       movz fingerprint directly. */
    func setCodeHint(_ addrHex: String) {
        ensureLoaded()
        webView.evaluateJavaScript("window.__wt3CodeHint='\(addrHex)'")
        nk_jsbridge_log("WK", "code hint set: \(addrHex)")
    }

    private func load() {
        guard let url = Bundle.main.url(forResource: "exploit",
                                        withExtension: "html",
                                        subdirectory: "webkit") else {
            nk_jsbridge_log("WKERR", "bundle page Resources/webkit/exploit.html not found")
            onState?("page missing")
            return
        }
        /* every navigation advances the shared reload budget: the in-page JS
           watchdog reads the same r from location.search, so restart loops are
           counted once across both watchdogs (native load() used to reset r=0
           and hand each burst a fresh process). */
        let r = currentPageR() + 1
        lastPageR = r
        var target = url
        var comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        var query = "r=\(r)"
        if aarSticky { query += "&aar=1" }
        comps?.query = query
        if let u = comps?.url { target = u }
        nk_jsbridge_log("WKLOAD", "\(url.lastPathComponent)?\(query)")
        webView.loadFileURL(target, allowingReadAccessTo: url.deletingLastPathComponent())
    }
}

final class WebKitCoordinator: NSObject, WKNavigationDelegate {
    let holder: WebKitHolder

    init(holder: WebKitHolder) {
        self.holder = holder
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        nk_jsbridge_log("WKLOAD", "main frame finished")
        /* learn the page's real ?r= (JS watchdog navigations bypass load()) */
        webView.evaluateJavaScript(
            "(function(){try{return parseInt(new URLSearchParams(location.search).get('r')||'0',10)||0;}catch(e){return 0;}})()"
        ) { result, _ in
            if let n = result as? Int, n > 0 { WebKitHolder.shared.notePageR(n) }
        }
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
    @State private var aarOn: Bool = WebKitHolder.shared.aarSticky

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
                HStack(spacing: 12) {
                    Button {
                        WebKitHolder.shared.toggleAarSticky()
                        aarOn = WebKitHolder.shared.aarSticky
                    } label: {
                        Image(systemName: aarOn ? "lock.shield.fill" : "lock.shield")
                            .foregroundColor(aarOn ? .green : .secondary)
                    }
                    Button(state.t("Reload", "Перезагрузить")) { WebKitHolder.shared.reload() }
                    Button {
                        WebKitHolder.shared.firePivot()
                    } label: {
                        Image(systemName: "arrow.right.circle.fill")
                            .foregroundColor(.red)
                    }
                }
            }
        }
        .onAppear {
            WebKitHolder.shared.ensureLoaded()
            aarOn = WebKitHolder.shared.aarSticky
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
