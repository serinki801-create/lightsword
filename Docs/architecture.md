# chain architecture

    LiveContainer guest (native arm64 app)
      |
      +-- AppMain.onAppear
      |     nk_set_home(NSHomeDirectory())   # LC does not export HOME
      |     nk_state_load()                  # adopt last boot: dead probes marked
      |     LAST BEFORE DEATH -> UI log      # tail of Documents/trace.log
      |
      +-- probe buttons -> nk_probe_run_guarded (Diag/nk_child_diag.c)
      |     stages 1..5 -> Documents/nk_stage.txt (fsync)
      |     nk_crash_guard_install + sigsetjmp/siglongjmp
      |       ordinary SIGSEGV  -> nk_crash.txt + RECOVERED (container lives)
      |       SIGKILL/Mach exc  -> not catchable; state machine sees RUNNING
      |                            with no verdict next launch -> SKIP (DEAD)
      |
      +-- T0e / Dummynet / T2 frame -> micro-breadcrumb SUB/RET lines (D1)
      |
      +-- B12 track (settled): aio_workq_entry 184B on device, slot 192B vp,
            UAF -> kevent reap -> filt_aioprocess on stale kn_hook -> controlled
            reclaim (dn_flow_queue SILVER) -> value writes -> proc_ro->p_ucred
            -> cr_posix uid/gid = 0. Data-only, no kcall, SMR-safe fallback.
      |
      +-- Stage W: embedded WKWebView loads Resources/webkit/exploit.html
      |     (file://, no network). JS bridge (nk_jsbridge.c -> nk_trace +
      |     UI log). Chassis units (fakeHeader, gigacage scan, cell sled,
      |     deepClobber, WASM portable globals commutation, teardown) shipped
      |     and self-tested; DFG trigger gated by W-T0 [VP-DEVICE].
      |     WebContent is a second sandbox: W-T5 is a second chance at the
      |     dummynet gate for dn_flow_queue (R22). Docs: webkit_map.md,
      |     webkit_poc_review.md.

Docs: write_mechanism.md (B12 proof), neighbour_score.md (C1-C4), panic_symbolization.md.

## Logging contract [VB-DEVICE]

All UI logging funnels through nk_logx (Core/exploit.c) and nk_jsbridge_log
(Core/nk_jsbridge.c). 2026-10-10: every button death since Guard v9 was ONE
bug — nk_logx called vsnprintf with the prefix STRING as the va_list argument
(`vsnprintf(buf, sizeof(buf), "%s: ", tagbuf)`): the format's %s dereferenced
the string bytes as a va_list and faulted on them. Device crash file:
`signal=SIGSEGV fault_addr=0x5d52454e4e555250` = ASCII "PRUNNER]" = tagbuf
content used as the pointer. Fix: single pass — snprintf the prefix, then one
vsnprintf(buf+t, ..., fmt, ap). Never chain two vsnprintf calls over one
va_list, and never pass anything but a va_list as vsnprintf's 4th argument.
