# ⚔️ Lightsword

> iOS **26.2 (build 23C55)** exploit research toolkit — WebKit renderer pivot chassis,
> IOKit/IOGPU probes and UAF/OOB PoCs, on-device logging, all built from Linux with Theos.

**Built for interest.** This is a personal research project — a playground for
understanding how iOS 26 internals work (WebKit/JavaScriptCore, IOKit, the GPU stack,
the kernel). Nothing here is a finished jailbreak; it is best treated as a
documented expedition log with working probes.

**All testing was done on the author's own device: iPhone 13 (A15, arm64e, T8110),
iOS 26.2 / 23C55 (xnu-12377.62.10), IOGPUFamily 129.3.2, AGXG14P 342.3.**

---

## Why it exists

Sent from curiosity, not for harm: every routine runs inside a **sandboxed,
entitlement-less, ad-hoc signed app** delivered via LiveContainer. Everything
logged on-screen (`[W-T0]`, `[oob]`, `[uaf]`, `[probe2]` tags) — no persistence in the
host environment, no infrastructure hits, no distribution.

## What's inside

| Component | Path | Role |
|---|---|---|
| WebKit pivot chassis | `Sources/WebKit`, `Sources/App/WebKitStage.swift` | DFG/JS-run instrumentation, **W-T0/T2 renderer primitive verification** |
| State machine / home | `Sources/Core/nk_home.*`, `nk_state_machine.*` | run sequencing, phase gates, log transport |
| IOKit probes | `Sources/Legacy/iogpu_oob.m`, `iogpu_probe2.m` | IOGPU registry sweep: types 1..33, sel 0..127, zero/struct/scalar passes |
| UAF PoC | `Sources/Legacy/iogpu_uaf64788.m` | CVE-2026-64788 (iOS 26.6 shape) probe, Metal/IOSurface-driven |
| Kernel slide / KASLR | `Sources/Kernel/kslide.c` | live KASLR base detection from device logs |
| Diagnostics | `Sources/Diag/*` | crash-guard, symbols, dtrace spikes |
| Fuzzer surface | `Sources/Legacy/*fuzz*.c` | IOKit / mach message fuzzers |

Everything routes back into the in-app log console — every phase, hit, and
verdict lands in `LogView` for iteration.

## Vulnerability surface under research

The toolkit compiles probes for **publicly documented** vulnerability shapes and
their 23C55 field verification status:

| CVE / bug | Family | Status on 26.2 (23C55) |
|---|---|---|
| **CVE-2025-24257** — IOGPU `IOGPUGroupMemory::init` bitmap underflow (`(capacity>>6)-1` unchecked) | IOGPUFamily OOB | **ALIVE — primary route.** Kernel bug present at 23C55 and reachable on device. Zero-arg gate (`sel 11`) is dead; the structured path (`InStruct` ≥88, handlers `0x9f5415c`/`0x9f541ec` → `newResourceGroup`) and the scalar row-dispatch path (`cmp w1,#55` walker @`0x9f56cc8`, rows via `sel41`/`sel48`) survive — sweep continues with `iogpu_probe2.m` |
| **CVE-2026-64788** — `create_resource_iosurface` invalid-release UAF | IOGPUFamily UAF | PoC integrated and swept — **not vulnerable** at 23C55 (dims validator precedes resource insertion); vulnerable shape lives in 26.6 / 23G71 |
| **CVE-2026-43743** — IOGPUFamily race | IOGPUFamily | earlier build only; **closed** as a vector here (no sandbox entry point) |
| **WebKit DFG type confusion** (MapIterationEntryKey-shaped node, per public writeups) | JavaScriptCore / WebKit | renderer start-chain — **works on device**: 9+ verified W-T0 runs, AAR/AAW echo confirmed (W-T2) |
| **B12** — `aio_workq_entry` × `kevent64` blind `TAILQ_REMOVE` UAF | xnu bsd/kern | **DEAD.** Write frame proven statically + on-device panic trace (69EDA62B), but value control is impossible: iOS 26 shares the aio zone across 21 types — route retired, kept only as an expedition log |

_The named CVEs above are already patched in current iOS builds and were checked
against this binary set for mapping purposes. One additional source-level find:
a `vm_fault_copy` (re)type race — present in xnu-61.12 source, closed upstream in
xnu-12377.81.4; on-device verification pending._

## Further fate

The roadmap (subject to device verification):

1. **Lightsword Probe2** (`iogpu_probe2.m`) — sweep the IOGPU row-dispatch surface on-device
   (zero / structured / scalar passes across types 1..33).
2. If a reachable row lands: pivot `IOServiceOpen` access toward the hidden
   row-dispatch family inside `IOGPUFamily` (the public CVE-2025-24257 shape),
   enabling the OOB primitive's dispatch.
3. From that primitive: kernel read/write journey — read pivots first, write
   pivots second, all in a data-only fashion (no PAC bypass attempted).
4. Keep the WebKit pivot chassis as a secondary route while the direct IOKit
   path is being explored.

## Build

Linux + Theos (no Xcode needed):

```sh
export THEOS=$HOME/theos
./package_ipa.sh                       # builds the app → .ipa (ad-hoc signed)
```

Artifact: `packages/srk801_*.ipa` — ad-hoc (`ldid -S`). Install via
LiveContainer / Sideloadly / AltStore with the app-group sacrifice, then press
**WebKit Stage / IOGPU Probe2 / OOB (24257)** on the Actions page.

## Notes

* Targeted specifically at **iOS 26.2 build 23C55, iPhone 13 (A15)**.
* LiveContainer guest delivery means zero entitlements and a strict call budget
  per run — every probe is written watchdog-safe by design.
* Everything was verified by reading the **kernel binary statically** first
  (llvm-objdump on `~/theos` toolchain on Linux), then confirmed on-device.

## License

[Apache License 2.0](LICENSE) — © 2026 Lightsword contributors.

Use wisely. Research-only; the authors take no responsibility for any misuse
of this codebase.
