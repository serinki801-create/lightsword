# WebKit map — CVE-2026-43709 / CVE-2026-43701 (W-T1)

Target: iOS 26.2 / build 23C55 / iPhone14,5. Both CVEs were fixed in the
Safari/iOS **26.5.2** wave (advisory 2026-06-29; WSA-2026-0004 dated 2026-07-10;
upstream fixes 2026-07-01 / 2026-07-06). iOS 26.2 predates that wave by ~7
months → both bugs are inside the version window (see §3).

## 1. Source inventory (public)

| CVE | WebKit Bugzilla | rdar | Upstream fix commit | Fix date | Credit |
|---|---|---|---|---|---|
| CVE-2026-43709 | 314398 | 176201738 | `9d2cc8c989` | 2026-07-06 | (none listed in APPLE-SA-06-29-2026-3) |
| CVE-2026-43701 | 315004 | 177019828 | `f23ffb5a84` | 2026-07-01 | Aaron Grattafiori — NVIDIA AI Red Team |

Sources pulled: APPLE-SA-06-29-2026-3 (fulldisclosure archive, PGP-signed),
WSA-2026-0004 (webkitgtk.org), upstream commits via GitHub API
(github.com/WebKit/WebKit/commit/{9d2cc8c989,f23ffb5a84}). Bugzilla bugs
314398/315004 are access-restricted; commits are the public surface.

## 2. CVE-2026-43709 — ANGLE Metal occlusion-query UAF (bug 314398)

- **Class:** use-after-free — dangling raw GL-object pointer on an
  allocation-failure path.
- **Component:** `Source/ThirdParty/ANGLE/src/libANGLE/renderer/metal/` —
  ANGLE Metal backend, GPU process. NOT JSC, NOT the WebContent renderer.
- **Mechanism** (commit message, verbatim):

      ContextMtl would populate QueryMtl *ContextMtl::mOcclusionQuery before
      visibility buffer allocation:
        mOcclusionQuery = query;
        ANGLE_TRY(startOcclusionQueryInRenderPass(...));
      If the allocation failed, frontend would not keep the Query instance
      alive.

- **Fix shape:** the `QueryMtl *mOcclusionQuery` member of `ContextMtl` is
  deleted outright; occlusion-query state moves into `OcclusionQueryPool`,
  callbacks take `QueryMtl &` instead of raw pointers. Key hunks:

      ContextMtl.h: - QueryMtl *mOcclusionQuery = nullptr;   (member deleted)
      ContextMtl.h: - startOcclusionQueryInRenderPass(QueryMtl *query, bool clearOldValue);
      mtl_command_buffer.mm: - if (mOcclusionQueryPool.getNumRenderPassAllocatedQueries())
                             + if (mOcclusionQueryPool.hasPendingVisibilityResults())

  Files: ContextMtl.h/.mm, QueryMtl.h/.mm, mtl_command_buffer.mm,
  mtl_occlusion_query_pool.h/.mm, mtl_render_utils.h/.mm (+ gl_tests).
- **Trigger surface:** WebGL occlusion query
  (`glBeginQuery(GL_ANY_SAMPLES_PASSED/GL_ANY_SAMPLES_PASSED_CONSERVATIVE, …)`)
  while the visibility-buffer allocation fails — i.e. an OOM/memory-pressure
  path. Determinism is weak; Apple impact text says "unexpected process crash".
- **Verdict:** crash-class GPU-process UAF. No stable allocation/reuse control
  documented publicly → NOT an RCE-grade primitive. Off the critical path;
  carry as GPU DoS only.

## 3. CVE-2026-43701 — data: URL download-policy sandbox escape (bug 315004)

- **Class:** sandbox escape — compromised WebContent (CWC) drives the UIProcess
  to write attacker-chosen bytes to disk with no user interaction.
- **Component:** UIProcess navigation policy
  (`WebPageProxy::receivedNavigationResponsePolicyDecision`) + WebCore
  `DocumentLoader::continueAfterContentPolicy`. Not JSC.
- **Mechanism** (commit message, verbatim):

      The renderer opens a popup navigation to a data:application/octet-stream;
      base64,<payload> URL; because the MIME type is not showable, the
      navigation delegate's stock policy returns
      WKNavigationResponsePolicyDownload.
      WebPageProxy::receivedNavigationResponsePolicyDecision unconditionally
      mints a real DownloadProxy for the data: URL ... and the data: URL bytes
      land on disk. The renderer-supplied user-gesture token is forged to
      bypass the popup blocker.

- **Fix hunks (exact, 3 files, +24/-0):**

  1. `Source/WebKit/UIProcess/WebPageProxy.cpp` (+13) — primary fix:

      +    if (action == PolicyAction::Download && request.url().protocolIsData()
      +        && (!navigation || !navigation->isFromAPIClientRequest())) {
      +        WEBPAGEPROXY_RELEASE_LOG(Loading, "... refusing to download data: URL ...");
      +        action = PolicyAction::Ignore;
      +    }

  2. `Source/WebKit/UIProcess/API/APINavigation.h` (+1):

      +    bool isFromAPIClientRequest() const { return m_requestIsFromClientInput; }

     — `m_requestIsFromClientInput` is set only by UIProcess paths
     (`-loadRequest:`), NOT by the renderer-supplied
     `isRequestFromClientOrUserInput` flag. That distinction is the fix.
  3. `Source/WebCore/loader/DocumentLoader.cpp` (+10) — defense-in-depth:

      +        if (disallowDataRequest()) {
      +            protect(frameLoader())->policyChecker().cannotShowMIMEType(m_response);
      +            stopLoadingForPolicyChange();
      +            return;
      +        }

- **Exploit surface:** requires a prior renderer RCE (this is the escape that
  *follows* it). On the stock `WKNavigationDelegate` path
  (`decidePolicyFor navigationResponse`) returning
  `.download` is the default for unshowable MIME types, so the same flow runs
  inside an embedded WKWebView. Result: arbitrary attacker-chosen bytes written
  to a fixed path (Downloads/Unknown) in the UI process — no gesture, no
  `download` attribute, no Content-Disposition.
- **Verdict:** real UIProcess-side arbitrary-bytes-to-fixed-path write. Fixed
  destination limits direct abuse (no path control), but it is a genuine
  post-RCE pivot: plant bytes another component later reads (e.g. a file the
  app itself loads). Secondary pivot, not the exec primitive.

## 4. Presence in the 23C55 build

- Both upstream fixes (2026-07-01, 2026-07-06) shipped in the 26.5.2 wave:
  Safari 26.5.2 / iOS 26.5.2 / iPadOS 26.5.2 / macOS Tahoe 26.5.2 /
  WebKitGTK 2.52.5 (WSA-2026-0004). Our device runs iOS 26.2 (23C55) —
  **inside the vulnerable window**.
- **[UNVERIFIED]** on-device items — exact commands to close:
  1. In the in-app WKWebView run JS `navigator.userAgent` → the AppleWebKit
     build token must predate the 26.5.2 WebKit line.
  2. JS `document.createElement('canvas').getContext('webgl2')` +
     `gl.getExtension('WEBGL_debug_renderer_info').UNMASKED_RENDERER_WEBGL`
     → expect `ANGLE (Metal)` to confirm the ANGLE Metal backend (the 43709
     surface) is active.
  3. Trigger check for 43701: load a local page that fetches
     `data:application/octet-stream;base64,…` in a popup-shaped navigation
     with unshowable MIME → pre-patch the file lands in
     `NSDownloadsDirectory`/Unknown of the app container (post-patch it is
     refused).

## 5. Chain read for Stage W

- Neither bug is a JSC renderer-RCE primitive: 43709 is a GPU-process crash;
  43701 is a post-RCE escape. If Stage W needs renderer code execution, the
  scope must widen to JSC/WebCore memory-corruption bugs unfixed at 23C55 —
  that is W-T1b (next inventory task), NOT derivable from this pair.
- Stage W bootstrap order that still holds: local page → renderer RCE
  (W-T1b bug) → 43701 pivot (UIProcess file write) → native exec in host →
  B12 kernel path. Do not spend critical-path time on 43709.

## 6. W-T1b — JSC primitive for 23C55: FOUND, kill gate NOT tripped (2026-10-10)

Public, complete, version-matched PoC: **`github.com/retX0/safari-26.2-dfg-type-confusion`**
(pushed 2026-03-26). This is a renderer-side RCE primitive for EXACTLY our build.

### The bug [VB from PoC + upstream fix commit 3f6f7836068]

`Source/JavaScriptCore/dfg/DFGNodeType.h` (line 592 in the affected tree):

    macro(MapIterationEntryKey,   NodeResultInt32)   // BUG
    macro(MapIterationEntryValue, NodeResultJS)      // correct

`MapIterationEntryKey` — the node extracting the key inside a `Map.forEach()`
callback — is declared as producing a 32-bit int. Its runtime op returns an
arbitrary NaN-boxed `JSValue` which MAY hold a heap pointer.

Fix commit `3f6f7836068` (commits.webkit.org/308853@main, authored
2026-03-07), the exact hunk:

    -    macro(MapIterationEntryKey, NodeResultInt32) \
    +    macro(MapIterationEntryKey, NodeResultJS) \

plus regression test `JSTests/stress/map-forEach.js` (store-key-into-tenured +
Eden scan + spray; asserts `object.key[0] === 2.2` never holds).

### Chain, verbatim from the PoC README

    StoreBarrierInsertionPhase::Fast: child->result() == NodeResultInt32
      -> FencedStoreBarrier skipped for the key stored into a tenured object
      -> Eden GC frees the key object, dangling pointer remains in the holder
    Spray JSArray: cells -> IsoSubspace (no reuse); butterflies -> Gigacage
      (reused) -> DoubleShape cell reads NaN-boxed pointer as raw float64
      (addrof); JSArray reads written raw bits as JSValue (fakeobj)
    Phase 3: WebAssembly Portable globals (i64 g0 / i32 g1), two instances
      (Navigator/Executor), redirect Navigator.g0 value slot -> Executor.g1
      -> read32/write32/read64/write64
    iPhone adaptations: cell sled (64x {0:0.0} after storeKey),
      deepClobber(300), await sleep(50), 3000-5000 iteration DFG warmup.
    End-to-end success ~80% (tested iPhone iOS 26.1, macOS 26.2).

### Version window for 23C55

- PoC affected table: "Safari <= 26.2 (WebKit 21623.1.14.11.9)" — our OS build.
- Fix landed 2026-03-07, i.e. AFTER the 26.2 wave (Dec 2025) -> present on 23C55.
  This is a fix-date argument; [UNVERIFIED] device-side check remains the same
  two commands as W-T1 §4 (userAgent + the PoC's own AAR/AAW demo inside WKWebView).

### Verdict

- Stage W now has its renderer primitive: local page (exploit.html/js) loads
  `wasm_rw.js` logic in WKWebView -> AAR/AAW in the WebContent process.
- Combined with CVE-2026-43701 the pivot to the UIProcess (arbitrary bytes to a
  fixed path) is public. dyld CVE-2026-20700 (patched 26.3, so PRESENT on 26.2)
  remains the standby PAC/TPRO lever if native exec needs it — NOT on the
  critical path.
- Track status: ALIVE, bounded. Per R13 it consumes no critical-path time:
  native B12 work (T2 frame probe on device, T3 field RE) outranks it.

## 7. W-T0 device verdict [VP-DEVICE] — 2026-10-10 18:27, build 181624/183906

- Fingerprint (chassis unitFingerprint, native-bridged to trace.log):
  `ua=Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15
  (KHTML, like Gecko) Mobile/15E148`, `gl=Apple GPU/Apple Inc.`,
  `glsl=WebGL GLSL ES 3.00`, `hasResizableArrayBuffer=true`,
  `hasAtomicsWaitAsync=true`, `hasBigIntMap=true`. The UA OS token (18_7) is a
  guest anomaly on a 26.2 device and the AppleWebKit token is frozen Safari
  legacy — UA is NOT a version signal; GL confirms ANGLE/Metal active.
- **W-T0=PRESENT [VP-DEVICE]** via the strengthened detector (600-round groom,
  5000-iteration DFG warmup, cell sled, deepClobber x2): the marker check
  `object.key[0] != 100.1+r` fired at round 10 — the MapIterationEntryKey
  type confusion is live on 23C55. Apple's own 100-round regression test alone
  had returned ABSENT (weak detector, not a negative — keep the strong groom).
- R20 VERDICT **[REACHABLE]** by option matrix on device: control option 250 ->
  ENOPROTOOPT(42) generic rejection (matches 61.12 ip_ctloutput); IP_FW3(21) ->
  EINVAL(22) at both len32 and len4, and getsockopt(IP_FW3) returns r=0 — the
  option is distinguished and validated by a handler. dn_flow_queue stays SILVER.
  Note: our hand-built dn_sess cookie still fails struct validation (EINVAL);
  the exact 62.10 dn_sess/flow_mask layout is the next static item if the T2
  fingerprint needs a real pipe to exist.
