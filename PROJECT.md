# PROJECT srk801 / lightsword — полный технический дамп

Дата: 2026-10-12. Устройство: iPhone14,5 (iPhone 13, A15 T8110, arm64e), iOS 26.2 build 23C55.
Kernel: xnu-12377.62.10 (источник не опубликован). Delivery: LiveContainer guest, native arm64 IPA.
Репозиторий: github.com/serinki801-create/lightsword (PRIVATE).

---

## 1. ДЛЯ ЧТО СДЕЛАН

Цепочка полного компромитирования устройства с sideloaded-приложения внутри LiveContainer,
БЕЗ веба, БЕЗ Safari, БЕЗ entitlements, БЕЗ серверов:

  WebKit-стейдж (renderer RCE)  ──►  нативный мост  ──►  B12 (kernel UAF)  ──►  data-only root  ──►  semi-untethered jb

Две линии, одна критерий:
- **B12 (нативная, критический путь)** — эксплойт AIO/kevent в ядре → kernel r/w → root.
- **WebKit (доставка, co-primary)** — renderer-экзек в WebContent → нативный пивот → подаёт тот же B12.

---

## 2. СТАТУС ЛИНИЙ

| Линия | Статус |
|---|---|
| LiveContainer delivery | ✅ живой (guest грузится, bundle-ресурсы, мост JS↔C) |
| Crash-обсервабилити (нативная) | ✅ guard RECOVERED, run/phase/HB телеметрия, state-machine |
| B12 — каркас (T1) | ✅ PROVEN (source): aio_return → aio_entry_unref → aio_free_request → zfree; kevent64 reap → filt_aioprocess on stale kn_hook |
| B12 — смещения [VB] | ✅ таблица ниже; p_aio_total_count @ proc+0x47C [VB-DISASM]; p_aio_doneq @ proc+0x5E0 |
| B12 — канал чтения | ✅ PROVEN (каждый выстрел течёт slot VA + ext[1]/ext[0]) |
| B12 — канал ЗАПИСИ | ❌ **МЁРТВ** (док-во 4.4.4: 21 зонный сосед, ни один не даёт controlled +0x10/+0x18; blind-remove = list surgery) |
| IOKit-соседи по 192-бакету | ❌ ВСЕ МЁРТВЫ + zone-seqr док-зано (kc.bin дизасм, реестр Artifacts/kalloc_type_registry.json) |
| B12 — T5 root | ⏸ data-only plan готов (proc_ro->p_ucred → cr_posix uid/gid), ptrauth не мешает |
| WebKit W-T0 (fingerprint) | ✅ [VP-DEVICE] баг ПРИСУТСТВУЕТ на 23C55 (round 9–17, 6 независимых прогонов) |
| WebKit W-T1c | ✅ PoC разобран, порт проверен |
| WebKit W-T2 (renderer AAR/AAW) | ✅✅ [VP-DEVICE] + РЕТРАЙ v128-leak (device 17:49: две неудачи взвода — v128-leak-failed (hb4) и wt0=ABSENT (детектор 550 раундов); авто-релоад отработал штатно (run3 через 3с); 17:54 build: leak-скан 3 пасса со свежими container/structArr) |
| WebKit W-T3 (native pivot) | ✅✅ FINGERPRINT НА УСТРОЙСТВЕ + page-major sweep + dead-slot петля (device 21:59: run1 умер посреди plan-строки (5 списков, ~1.5KB одним bridge-message — C-буферы 512B); 22:02 фикс: план построчно с дренажем, run2 прошёл sweep целым; 22:10 аудит: GETDEAD никто не слал — dead-list всегда пуст; 22:12 roundtrip по образцу claim; 14:58 PHASE 2 mprotect: stage-1 на сайте делает mprotect(RWX)+br, payload живёт в scratch-странице — потолок 256B снят, юнит native-pivot-mprotect) |
| WebKit W-T5 (aio из renderer) | ⏳ второй шанс на dummynet-гейт (R22) |
| T2 frame probe (1000 раундов) | ⏸ устройство, ПОСЛЕ ребута (R9); 50x паникует ядро (механизм огня живой — PAC/TRASHIT подтверждены) |
| **SPTM-прошивка 23C55** | ✅ **ДОСТУПНА ОФФЛАЙН** — `Firmware/sptm.t8110.release.im4p` в IPSW НЕ зашифрован → Mach-O arm64e 1 064 992 B (`Artifacts/sptm/sptm.macho`). Полный статический анализ SPTM теперь возможен (Docs/sptm_23c55.md) |
| SPTM race bypass (stale frame type) | 🆕 **КАНДИДАТ S1** — TOCTOU в `pmap_recycle_page` (3 неатомарных SPTM-раунд-трипа, retype-возврат игнорится, SPTM отклоняет retype при несовпадении типа) → кадр уходит в free-list с типом ≠ XNU_DEFAULT |
| T4 benign fire | ⛔ НЕ начинать: не закрыты предусловия (occupancy-map, fingerprint, TRASHIT-пропагейшн) |

---

## 3. ИСПОЛЬЗУЕМЫЕ УЯЗВИМОСТИ

### 3.1 JSC: MapIterationEntryKey type confusion (WebKit renderer RCE) — АКТИВНА, работает
- Дефект: `Source/JavaScriptCore/dfg/DFGNodeType.h:592` — `macro(MapIterationEntryKey, NodeResultInt32)` — узел доступа к ключу в Map.forEach объявлен 32-битным int'ом; фактически возвращает произвольный NaN-boxed JSValue (может быть heap-указателем).
- Следствие: DFG Store Barrier пропускается для ключа, записанного в tenured-объект → Eden GC собирает объект ключа → UAF → addrof/fakeobj → AAR/AAW.
- Фикс: `3f6f7836068` (commits.webkit.org/308853@main, 2026-03-07) — one-token `NodeResultInt32 → NodeResultJS` + JSTests/stress/map-forEach.js.
- Окно: 23C55 (дек. 2025) старше волны 26.5.2 (июль 2026) → баг ПРИСУТСТВУЕТ, подтверждено на устройстве.
- Публичный PoC: github.com/retX0/safari-26.2-dfg-type-confusion (W-T1c разбор — Docs/webkit_poc_review.md).

### 3.2 CVE-2026-43701 (bug 315004, rdar 177019828, credit Aaron Grattafiori/NVIDIA) — ПОСТ-ЭКСПЛОЙТ ПИВОТ, не реализован
- Sandbox escape: скомпрометированный WebContent заставляет UIProcess скачать data:-URL (байты атакера на диск, без жеста).
- Фикс f23ffb5a84 (2026-07-01): WebPageProxy.cpp +13, APINavigation.h +1, DocumentLoader.cpp +10.
- Статус: зарезервирован как путь записи файла ПОСЛЕ renderer-RCE (не для получения RCE).

### 3.3 CVE-2026-43709 (bug 314398) — GPU-process UAF, ЗАКРЫТА как источник
- ANGLE Metal occlusion query dangling pointer. Фикс 9d2cc8c989 (2026-07-06). Не renderer → не применимо.

### 3.4 B12 kernel UAF (aio_workq_entry × kevent64) — АКТИВНАЯ ОСНОВА
- Frame: aio_return → aio_entry_unref → aio_free_request → zfree, затем kevent64-reap → filt_aioprocess на протухшем kn_hook. Component (iv) активен; (i)(ii)(iii) — не эксплойт-путь; free-list assert не сработал ни разу → double-free steering НЕ канал.
- Симптом на устройстве: слепой remove доводит TRASHIT (-1) в link'и слота; далее poisoned LR → PAC-auth fail → instruction abort (esr 0x96000006, EC=0x25, far=0). x23=-1 sourced to `mov w9,#-1` @ carve 0x146c09c.

### 3.5 Хеджи (не блокируют, однонедельные исследования)
- CVE-2026-43743 IOGPUFamily race — ЗАКРЫТА как источник (нет точки входа из sandbox).
- CVE-2026-20637 AppleSEPKeyStore — gated on T0e.
- CVE-2026-20700 dyld PAC oracle — HEDGE ONLY (T5 proven data-only).

---

## 4. СМЕЩЕНИЯ (B12, устройство xnu-12377.62.10)

struct aio_workq_entry = 184 B [VB on-device] / slot 192 B [VP]; slack = qword 23 only (0xB8-0xBF); "176B" — dead claim.

  +0x00/+0x08  aio_workq_link
  +0x10/+0x18  aio_proc_link tqe_next/tqe_prev    ← WWW операторы
  +0x20        returnval → kev.ext[1] (64-bit)
  +0x28        errorval  → kev.ext[0] (32-bit)
  +0x2C        aio_refcount
  +0x30        flags (AIO_COMPLETED=0x100, re-arm gate)
  +0x40        procp
  +0x48        uaiocbp
  proc+0x58    p_mlock
  proc+0x47C   p_aio_total_count   [VB-DISASM: ldr w8,[x0,#1148]; sub; str; b.le → panic accounting mismatch kern_aio.c:479]
  proc+0x5E0   p_aio_doneq          [VB-DISASM: 3 независимых сайта]
  lst2 @ proc+0x5D0, panic "Negative total AIO count!" kern_aio.c:476, глобальный счётчик @ vm 0x7a65128
  [AS]: +0x50/+0x58 aiocb copy, +0xA0/+0xA8 vfs_context, +0xA8/+0xB0 aio_map

Важно (R16): ДВА счётчика — per-proc @0x47C И глобальный @0x7a65128; бюджет AIO учитывает ОБА.

---

## 5. КАНАЛ ЗАПИСИ — ЕДИНСТВЕННЫЙ КАНДИДАТ

dn_flow_queue (kalloc.type.192, 184B): C1 +0x10 dst_ip6 (value), C2 +0x18 dst_ip6 (target), C3 +0x30 flow label (AIO_COMPLETED bit), C4 +0x40 = mbuf head (natural, survival через крафт mbuf+0x58=0 и mbuf+0x47C>0; бюджет пакета ≥ 0x480 B).
- Гейт: device option matrix — control opt=250 → ENOPROTOOPT(42); IP_FW3=21 → EINVAL(22) на len32 и len4; getsockopt(IP_FW3) r=0. Итог: **[REACHABLE]** (handler опции 21 существует). Полный pipe-config в силами ещё нет (dn_sess layout НЕ сверен с 62.10).
- IOKit 4 (IOCPU/IOCPUInterruptController/IODTNVRAM/IOPowerConnection): все мёртвы — +0x10/+0x18/+0x30/+0x40 не пишутся (Docs/iokit_field_map.md).
- BRONZE: dn_flow_set, necp_client_flow_reg, nxctl_traffic_rule_inet, nxprov_params — не ведём.

---

## 6. КАК ИСПОЛЬЗОВАТЬ (команды)

    # сборка (всегда через symlink — Theos не ест пути с пробелами)
    cd "/home/abzal/jailbreak 26/Test-main" && bash package_ipa.sh
    # актуальный ipa → Packages/srk801_*.ipa, ставить в LiveContainer (удалять гостя!)

    # нативные кнопки: Run Exploit · Slide Only · AIO UAF B1/B2 (10x) · T0e Spike (SEP/dtrace, внутри AppleSEPKeyStore) ·
    # T2 Frame Probe (50x) · T2 Dummynet Probe · Guard Test · Reset Probe State · PAC Oracle A2 · WebKit Stage

    # WebKit: WebKit Stage → страница сама гоняет self-test; кнопки на странице: KILL RENDERER (F1 acceptance), TEARDOWN,
    # Reload (в тулбаре). JS-API: addrof/fakeobj/read64/write64, nk.trigger(), nk.teardown(), nk.killRenderer()

    # ядро-карve: bash Tools/carve_kernelcache.sh  → Artifacts/carve/kernel.carve.macho (VMA==file offset after rebase)
    # panic triage: bash Tools/panic_triage.sh <ips>
    # bucket map: python3 Tools/bucket_map.py <kernelcache> --json

Телеметрия WebKit (что смотреть в Documents/trace.log):
- `[RUN] run=N begin label=...` — релоад/новый контекст = новый N;
- `[HB] hbNN` — heartbeat критической секции (последний перед смертью = место смерти);
- `PHASE=n ENTER/OK/FAIL` — скобки фаз с err+stекфрейм;
- `[WK] FATAL ... webcontent-terminated` + Documents/wk_fatal.txt — смерть рендерера;
- `[DN] ...` — dummynet probe; `RESULT W-T0=` — вердикт DFG-бага; `W-T2 echo` — гейт AAR/AAW.

---

## 7. АРХИТЕКТУРА ПРОЕКТА

    Sources/App/      SwiftUI (AppMain/WebKitStage/UIBridge) — нативный вход + WKWebView-хост (singleton)
    Sources/Core/     exploit core: home, trace, state machine, jsbridge (run/phase телеметрия)
    Sources/Diag/     crash guard (siglongjmp), probe runner (стадии 1-5), T0e spike
    Sources/Probes/   aio_spray (T2 frame), dummynet probe (option matrix)
    Sources/Kernel/   b12_offsets.h, kslide.c (KASLR), write_mechanism.md
    Sources/Legacy/   невычеркнутые, но нев списке: fuzz/hunt
    Docs/             webkit_map.md, webkit_poc_review.md, iokit_field_map.md, fire_log.md, panic_symbolization.md, write_mechanism.md, neighbour_score.md
    Tools/            carve_kc.py, bucket_map.py, panic_triage.sh, recon.py
    Dead/             retired: nk_probe_runner.c.bak (fork — мёртв в LC), Makefile.bak
    Packages/         ipas   Artifacts/ — кернелкеш + carve (см. .gitignore, в репо не идут)

Ключевые уроки (все — операционные):
- FORK в LC-госте мёртв (дочерняя смерть = смерть гостя). Изоляция = sigsetjmp/siglongjmp.
- HOME в LC не экспортится — nk_set_home(NSHomeDirectory()) в onAppear, всё в Documents/.
- WKWebView должен быть singleton'ом; построчный @Published = пересоздание representable = релоад страницы посреди эксплойта.
- WebContent-смерть через fallback-чтение вне живой области = SEGV: любой «произвольный» read требует guard'а диапазона [device-observed JS cage].

---

## 8. ЧТО ДАЛЬШЕ (план)

1. **W-T3 native pivot** — СОБРАН 2026-10-12, АВТО-ЦЕПОЧКА на арм-состоянии триггера (`nkAutoPivot` в exploit.js: кнопка больше не нужна, `window.__wt3Auto=false` выключает, защёлка на один арм): magic-модуль (i64-цепочка, 192 пара, MAGIC=0xB1C2D3E4F5A607B8) → hunt v3 ищет movz-иммидиат ИЛИ литерал MAGIC в кодовом маппинге (без фикс-офсетов) → byte write-test → inline-hook 256B → shellcode: marker + open/write/close trace.log (путь из C-моста GETPATH) + трамплин на site+256. Гейт: строка SHELLCODE в trace.log; вторичный: marker-qword в scratch. Device 21:44 + 21:57: armed оба раза, ECHO OK, hunt пока мимо — v3 вводит BFS L0/L1/L2 (module/fn/magic-instance приоритет, второй уровень косвенности module→Code→jumpTable, интерьер-указатели из C++-тел) и литерал-фингерпринт. Re-call экспорта ре-ранит шеллкод (хук однонаправленный, без self-restore). Риски на устройстве: icache-когерентность JIT-страниц (retry x3), детали — Docs/webkit_map.md §8.
2. **W-T5**: из renderer-контекста зонд aio_read + kevent64(EVFILT_AIO) — [CONFIRMED]/[BLOCKED] с errno (R22: второй шанс на dn_flow_queue-гейт).
3. **T2 after reboot**: frame probe 50x → 1000x, occupancy map (24 qword, qword 23 = slack), aiocb +0x50 vs +0x58 [VB].
4. **dummynet**: сверка dn_sess layout на 62.10 (дизасм carve) → полноценный pipe-config → подтвердить C1-C3 readback по ext[1]/ext[0] перед любым огнём.
5. **T4 first benign fire**: целевой скретч-объект, сентинел-запись, ≤2 benign / ≤5 live; оба счётчика в бюджете (R16).
6. **T5 cred substitution**: value-write cr_posix (uid/gid=0) → getuid()==0 + denied-op succeeds.

### 4.1 B12 — прямой дизассемблер device KC + зоны kalloc_type (2026-10-14 18:54)
kc.bin декомпрессирован (ipsw, bvx2 -> 64.5MB Mach-O); из __DATA_CONST вытащен
реестр kalloc_type (2525 view). Канал записи подтверждён в прямом дизассемблере
62.10 (aio_proc_remove_done_locked @ 0xFFFFFFF008478060: `str x8,[x9]` — слепой
write B, `str xzr,[x10]` — TRASHIT; procp+0x47C p_aio_total_count и
p_aio_doneq.tqh_last @ procp+0x5E8 — по immediates). T3 закрыт с доказательством:
21 тип делит зону aio_workq_entry (сигнатура 11112221122222222222111), ни один
не даёт user-controlled +0x10/+0x18, из песочницы спамmable только сам aio =>
канал записи через blind TAILQ_REMOVE value-control НЕ имеет. Детали и таблица
соседей — Docs/b12_t3_zones.md, реестр — Artifacts/kalloc_type_registry.json.

### 4.2 B+ — CVE-2026-64788 PoC интегрирован; реестр kalloc.256 для cross-type (2026-10-14 20:29)
Шаг 1 (интеграция PoC): `Sources/Legacy/iogpu_uaf64788.m` — полный PoC
bytev0rtex (Metal newTextureWithDescriptor:iosurface:, 1x65535 overflow,
KDALLOC.256 spray 0x300 x MTLBuffer(0x100), return-code oracle
0xe00002c2 -> 0xe0002be) + обёртка `nk_iogpu_uaf_run()`, кнопка
**IOGPU UAF 64788**, Metal/IOSurface в Makefile. Билд
srk801_20261014-202911.ipa.
Шаг 2 (статический реестр): kalloc.256-class = 33 types. Кандидаты
cross-type под zone-seqr: `AppleBasebandPCIControlUserClient (256)`,
`IONetworkUserClient (248)`, `IOStreamUserClient (248)`, `IOUserUserClient (248)`,
`struct socket_filter (248)` — userclient-классы с callback-указателями,
reachable из sandbox. Дампинг указателей — по 23C55-коду каждого.

### 4.3 CVE-2026-64788 НЕ уязвим на 23C55 — доказано (2026-10-14 21:10)
PoC интегрирован и прогнан на iPhone 13 / iOS 26.2 / A15:
conn открыт (IOServiceOpen type=1 из песочницы — entitlement не нужен),
Metal-триггер создал текстуру 1x65535, но stale-ID нет (sweep 1..4096:
processed=0). Статика объяснила: валидатор dimensions в 129.3.2 стоит
ДО вставки ресурса — @ 0xfffffff009f4e5c0: `cmn w2,w4; b.cs → error`
+ `adds w24,w3,w4; b.cs → error` → error-ветка = log + retab(0xe00002c2),
без аллокации и без табличной записи. Уязвимая форма (вставка, потом
проверка без release) есть в 26.6/23G71, куда писался PoC.
Похоже, 129.3.2 уже содержит раннюю форму этого fix'а.
Вывод: CVE-2026-64788 закрыт на 23C55. Возврат к WebKit-линии
(pivot armed) как единственному рабочему вектору + hold на
IOGPU 130.13/130.14 (26.4/26.5) как на версии без этого порядковаый fix'а.

---

## 4.4 СТАТУС НА 2026-10-15 17:55 — после IOGPU-исследования и возврата в веб

### 4.4.1 ЦЕЛЬ И ОСЬ
- Устройство: iPhone13 (iPhone14,5, A15 T8110, arm64e), **iOS 26.2 build 23C55**.
- Kernel: xnu-12377.62.10, IOGPUFamily **129.3.2**, AGXG14P 342.3.
- Delivery: LiveContainer guest, IPA. Entitlements: **НЕТ** (sandbox app).
- Конечная цель: kernel read/write → data-only root (proc_ro->p_ucred).

### 4.4.2 КАКИЕ БАГИ ИСПОЛЬЗУЮТСЯ
| Баг | Где | Статус на 23C55 |
|---|---|---|
| JSC MapIterationEntryKey type confusion | DFG-узел объявлен Int32, возвращает JSValue → UAF → addrof/AAR/AAW | ✅ **РАБОТАЕТ** [VP-DEVICE], W-T0 confirmed 9+ прогонов |
| B12 aio_workq_entry × kevent64 | ядерный UAF aio/proc link | ⚠️ frame PROVEN, запись **МЁРТВА** (док-во ниже) |
| CVE-2026-64788 IOGPUFamily UAF (dimensions) | create_resource_iosurface без release при overflow | ❌ **НЕ УЯЗВИМ**: валидатор стоит ДО вставки (@0xfffffff009f4e5c0) |
| CVE-2025-24257 IOGPUFamily bitmap underflow | obj+40=(capacity>>6)-1, capacity<64 ⇒ 0xffffffff; unchecked-путь grow @0x9f64910 (capacity=2*count, count<32) | 🟢 **ДОСТИЖИМ ИЗ SANDBOX** — sel **64**, type 1 (`0x7e67c58`, 112 сел.) — см. 4.4.9 |
| CVE-2026-43743 IOGPUFamily race | — | ❌ закрыта как источник (нет точки входа) |

### 4.4.3 ЧТО РАБОТАЕТ (доказано на устройстве)
1. **WebKit W-T0** — DFG-баг присутствует,round 9–17, 6 независимых прогонов.
2. **WebKit W-T2** — renderer AAR/AAW: `read64/write64` через wasm-global commutation, двойная верификация JS↔native. ECHO OK на устройстве.
3. **WebKit W-T3 цепочка** — собрана полностью: magic-module (192 пара) → hunt (page-major sweep) → byte write-test → inline-hook 256B → shellcode (marker + open/write/close trace.log). **Armed=yes дважды** (device 21:59 / 16:40), hunt доходит до sweep.
4. **Статический инструментарий** — kc.bin декомпрессирован (ipsw bvx2 → 64.5MB Mach-O), реестр kalloc_type (2525 view) извлечён, дизассемблер настроен (aarch64-linux-gnu-objdump / llvm-objdump-18), патентован обход chained-pointer'ов (top16 0x8011/0x8021 + low32 = parent __TEXT_EXEC file offset).

### 4.4.4 ЧТО МЁРТВО (с док-вами)
**B12 канал записи — МЁРТВ.** Прямой дизассемблер device KC:
- `aio_proc_remove_done_locked` @ 0xFFFFFFF008478060: `str x8,[x9]` (слепой write B) + `str xzr,[x10]` (TRASHIT) — frame живой.
- Но value-control невозможен: **21 тип делит зону aio_workq_entry** (сигнатура `11112221122222222222111` = kalloc_type zone-sharing key). Ни у одного нет user-controlled +0x10/+0x18.
- `dn_flow_queue`: +0x18 = `mbuf*` (kernel), не выбранный адрес; +0x10 = proto byte. Из песочницы не аллоцируется (нужен ipfw).
- Единственный sandbox-reachable зонный сосед = сам aio_workq_entry, чьи +0x10/+0x18 = kernel list pointers.
- Итог: blind TAILQ_REMOVE даёт **list surgery, не arbitrary write**.
- Реестр: `Artifacts/kalloc_type_registry.json`, таблица: `Docs/b12_t3_zones.md`.

**CVE-2026-64788 — НЕ уязвим на 23C55.** PoC прогнан: conn open OK, Metal texture 1×65535 created, но stale-ID=0 на sweep 1..4096. Статика: валидатор dimensions стоит ДО вставки ресурса (error-ветка = log + retab без аллокации). Уязвимая форма — в 26.6/23G71.

### 4.4.5 CVE-2025-24257 — БАГ ЕСТЬ, ДОСТУПА НЕТ
Полная цепочка создания группы (всё дизассемблером):
```
dispatch@0xfffffff007e669b8  (24B: {fn, fn2, inScalar, inStruct, outScalar})
  fn = 0xfffffff009f541ec    ← хендлер создания группы, inScalar=0 inStruct=0 outScalar=0
   └─ 0xfffffff009f56df4 ── 0xfffffff009f7314c ── 0xfffffff009f60a84
        = IOGPUResource::newResourceGroup(dev, ?, capacity)
        · проверка ТОЛЬКО "степень двойки" (0x9f61028) — 1,2,4,8,16,32 проходят
        └─ 0xfffffff009f611ec = IOGPUGroupMemory::init
             0x9f612a4: lsr w9,w21,#6 ; sub w9,w9,#1 ; str [obj+40]   ← БАГ: cap<64 → 0xFFFFFFFF
cleanup (vtable slot[1]) @ 0xfffffff009f5f084
     bound = [obj+40]; for group_idx 0..bound:
         arrayC[(group_idx<<6)+bucket] → ldr + str xzr                  ← OOB read/write ×32GB
```
**Почему не достижимо:** dispatch-запись с этим хендлером принадлежит user-client классу,
который **не открывается** из sandbox: `IOServiceOpen("IOGPU", task, 1)` и `33` — единственные
живые типы; селекторный свип 0..95 на обоих даёт одинаковый `0xe00002c2`. Запись с
`inScalar=0/inStruct=0` означает, что движок отсекает любой scalar/struct ДО хендлера.
PoC Wang Yu'я использовал `init_type=5` — на 23C55 type 5 **не открывается**.

### 4.4.6 ЧТО ОСТАЛОСЬ ДО KERNEL R/W
Порядок по réalisme:
1. **W-T5 (aio из renderer)** — если pivot добьёт сайт, aio_read + kevent64(EVFILT_AIO)
   из WebContent даёт второй шанс на dn_flow_queue-гейт. Статус: ⏳.
2. **IOGPU из WebContent** — WebContent GPU-entitled (WebGL/ANGLE active per fingerprint).
   Если pivot работает, `IOServiceOpen(IOGPU, type 5)` из рендерера должен ПРОХОДИТЬ →
   dispatch@0xfffffff007e669b8 достижим → CVE-2025-24257 стреляет OOB. **Это самый
   прямой путь к kernel r/w, но он заперт за W-T3.**
3. **Свой user client** — найти класс, владеющий 1-entry таблицей @0xfffffff007e669b8.
   Требует: парсинг __mod_init_func kext'а + metaclass-строк. Не начато.

### 4.4.7 БЛИЖАЙШИЙ ШАГ
Один чистый device-прогон, где hunt ловит код-сайт → W-T3 shellcode-гейт (`SHELLCODE` в
trace.log / `WT3-PHASE2 SHELLCODE PASS marker=0x5a5aa15a5a5aa15a canary=0x4d50525850`).
После этого — W-T5 и/или IOGPU-from-WebContent. Всё остальное (B12, 64788) закрыто.

### 4.4.8 ДОБАВЛЕННЫЕ УЯЗВИМОСТИ (2026-10-14/15)
- CVE-2026-64788 (IOGPUFamily UAF, bytev0rtex PoC) — интегрирован, прогнан, **НЕ уязвим на 23C55**.
- CVE-2025-24257 (IOGPUFamily bitmap underflow, wh1te4ever PoC + Wang Yu разбор) — статически подтверждён в 129.3.2 и **reachable из sandbox** через sel 64 / type 1 (см. 4.4.9 — прежний вывод «не reachable» был из-за неверной таблицы и неверного селектора).
- CVE-2026-28992 IOHIDFamily race / CVE-2026-43668/43684/43686 / CVE-2026-43810 — отслеживаются, PoC публично недоступен.

### 4.4.9 CVE-2025-24257 — ОПРОВЕРГНУТО: ПУТЬ ЕСТЬ, И БЕЗ WEBKIT-ПИВОТА (2026-10-19 20:20)

**Прежний вывод «тупик из sandbox» был ОШИБОЧНЫМ.** Ошибка — в адресе dispatch-таблицы
и в номере селектора. Ниже — как получено и как проверяется.

#### 1. Настоящая dispatch-таблица

`hunt/dispatch_23c55.txt` / `hunt/blocks/23c55_IOGPUFamily.tsv` дают:

```
com.apple.iokit.IOGPUFamily | type=1 | stride=0x18 | n=112 | таблица @ 0xfffffff007e67c58
```

Прежняя таблица `@0xfffffff007e668b0` — **не** IOGPUFamily (это vtable
IOGPUVirtualMemory, §4.4.10 это уже отметил). Настоящая таблица — 112 селекторов
на type 1, а не 12.

#### 2. Групповой создатель = селектор 64, а не 11

Обратные ссылки в `hunt/dis/23c55_IOGPUFamily.dis` (единственный caller каждого):

```
0x9f7396c: bl 0x9f60a84   IOGPUResource::newResourceGroup   (единственный caller)
0x9f56e48: bl 0x9f7314c   group creator                       (caller из 0x9f56df4)
0x9f542f0: bl 0x9f56df4                                      (caller из 0x9f541ec)
```

`hunt/blocks/23c55_IOGPUFamily.tsv:9` →
`com.apple.iokit.IOGPUFamily|1|0x18|112|64|0xfffffff009f541ec`
→ **селектор 64**, обработчик `0xfffffff009f541ec`.

Полный путь:
`sel 64 → 0x9f541ec → 0x9f56df4 → 0x9f7314c → 0x9f60a84 → 0x9f611ec (IOGPUGroupMemory::init)`.

**Селектор 64 живёт на type 1** — а type 1 по §4.4.9 (п.3) **уже открывается из
sandbox** (`IOServiceOpen(IOGPU, 1)` → успех). Прежняя эмпирика «sel11-hits=0»
остаётся верной для sel 11, но sel 11 — это другой метод; **sel 64 не пробовали
вообще**, и никогда не передавали валидный struct ≥ 88 байт.

#### 3. Уточнённый корень CVE-2025-24257

`IOGPUGroupMemory::init` @ `0xfffffff009f61200`:

```
0x9f61220: str   w1, [x0, #32]      ; obj+32 = capacity
0x9f612a4: lsr   w9, w21, #6
0x9f612a8: sub   w9, w9, #1
0x9f612ac: stp   w8, w9, [x19, #36] ; obj+36 = capacity-1, obj+40 = (capacity>>6)-1
```

`obj+40` — и счётчик бакетов, и маска индекса бакета
(`0x9f63148: ldr w11,[x23,#40]; and w11,w11,x26,lsr #6` → bucket = index>>6).
При `capacity < 64` → `(capacity>>6)-1 = 0xffffffff` → маска «все единицы» →
bucket = index>>6 без ограничения → OOB по `arrayC[]` (obj+16 = kalloc(capacity*4)).

**Проверка `capacity > 63` есть НЕ везде:**
* `newResourceGroup` (0x9f60a84) — проверяет: `0x9f60fe4 cmp w2,#63; b.hi` +
  `0x9f61028..34` (степень двойки). Этот путь безопасен.
* **unchecked-путь** — `0x9f64910` (grow/resize): `0x9f64938 ldr w8,[x0,#32]`,
  `0x9f64940 mov x21,w8` → `capacity = 2*count`, **без нижней границы**,
  вызов init @ `0x9f649ac`. `count < 32` ⇒ `capacity < 64` ⇒ `obj+40 = 0xffffffff`.

#### 4. Форма struct'а (0x9f7314c)

```
0x9f73178: cmp  x3, #88 ; b.lo error    ; structure input >= 88 байт
0x9f731a8: ldr  w8, [x1] ; tst w8,#0xf  ; первый u32 = команда
0x9f731b8: cmp  w8, #130               ; команда 130 -> групповой путь
0x9f731c0: ldr  w1, [x24, #56]         ; поле +56
0x9f731dc: ldr  w8, [x24, #60]         ; поле +60
```

#### 5. Что сделано

* `Sources/Legacy/iogpu_oob64.m` — новый PoC `nk_iogpu_oob64_run()`:
  IOServiceOpen(type 1/2/33) → `IOConnectCallStructMethod(conn, 64, in, 88..256, ...)`,
  свип команды {130,0x82,0x83,0x8d,0x10,0,1,0x8e,0x8f,0x90} × u32-слотов [4,sz)
  × capacity {0,1,2,3,7,8,15,16,31,32,33,63,64,128,4096}. Каждый нестандартный
  kern_return и каждый KERN_SUCCESS логируются. Bounded (4096 вызовов), watchdog-safe.
* UI: кнопка **«IOGPU sel64»** (ContentView) → `AppState.iogpuOob64()`.
* Сборка проходит: `packages/srk801_20261019-201645.ipa`.

#### 6. Что это меняет

**Примитив OOB из приложения больше НЕ заперт за W-T3.** Селектор 64 + type 1
живут в клиенте, который открывается из обычного sandbox-приложения. WebKit-пивот
нужен только если понадобится GPU-entitlement для чего-то ещё; сам путь до
`IOGPUGroupMemory::init` из приложения открыт.

Следующие шаги:
1. Прогнать `nk_iogpu_oob64_run()` на устройстве — найти комбинацию
   (cmd, offset, capacity), дающую нестандартный kr / KERN_SUCCESS.
2. Определить, какой u32-слот реально становится capacity (свип уже это делает).
3. Связать с unchecked-путём `0x9f64910` (grow) — нужен count < 32.
4. Из OOB — R/W в kernel; дальше data-only root (SPTM для data-only не нужен).

### 4.4.10 «Свой user client» ЗАКРЫТ СТАТИЧЕСКИ (2026-10-17 10:40)

§4.4.6 item 3 («найти класс, владеющий 1-entry таблицей @0xfffffff007e669b8;
требует парсинг __mod_init_func + metaclass-строк; не начато») — начат и
закрыт за один проход, отрицательным результатом. Три статических скана по
полному 64МБ образу (`Artifacts/carve/kernelcache.release.iPhone14,5`,
VA = fileoff + 0xFFFFFFF007004000):

1. ADRP+ADD-пары на таблицу: adrp → страница 0xFFFFFFF007E66000,
   add-imm ∈ {0x8b0, 0x9b8, 0x9c0} — **0 пар по всему образу**.
   Контроль корректности метода: тот же adrp-скан по той же странице даёт
   644 референса; на смещение LDR #0x648 — 389hit'ов (горячий глобал-флаг),
   семейство #0x638/#0x5f8/#0x678/#0x610 — соседние флаги IOGPU.
2. ADRP+LDR (adrp; ldr xN,[ page,#0x8b0/0x9b8/0x9c0]) — **0**.
3. Данные: сырые qword (0xFFFFFFF007E668B0 / 0xFFFFFFF007E669B8) и
   chained-энкодинги (low32 = fileoff цели: 0x00e628b0/0x00e628a8/
   0x00e629b8/0x00e629b0/0x00e629c0) — **0 слотов в любом сегменте**
   (скан по каждым 4 байтам, fileoff 0x8000..0x3D80000).

**Вывод (камень): блок @0x…68b0..0x…69b8 НЕ ДИСПЕТЧИРУЕТСЯ. Ни код, ни
данные образа на него не ссылаются → «свой user client» через этот блок
невозможен по построению.** Эмпирика §4.4.9 (99 открытых сервисов ×
selector 11 = 0 попаданий) теперь объясняется не «тип не открывается», а
фактической несвязностью блока.

**ПОПРАВКА 2026-10-19 20:20 (важно, снимает «камень»):** вывод выше верен
ТОЛЬКО для блока @0x…68b0. Настоящая dispatch-таблица IOGPUFamily — **@0x7e67c58,
112 селекторов на type 1**, и групповой создатель в ней — **селектор 64**
(`0x9f541ec`), а не 11. Селектор 64 не был опробован ни разу (эмпирика била
по sel 11 в неверной таблице). Итог: путь до `IOGPUGroupMemory::init` из
sandbox открыт, WebKit-пивот для него не требуется. Детали — §4.4.9.

Подтвердающий, НЕ load-bearing (пере-выводимо): словарь символов
(symbols_all, /tmp/kc262 — утрачен на reboot, пересобирается `nm`-style);
`vtable for IOGPUVirtualMemory` @0x…68a8 и MetaClass-vtable @0x…69e0
ограничивают блок — он интерьер C++ vtable IOGPUVirtualMemory (слоты 32-36:
fn→0x9F4E0BC, fn2→0x9F4AFB0 — IOGPU-код; соседние слоты — XNU __TEXT_EXEC
generic OSObject-методы, согласуется с §2 Docs/iokit_field_map.md).
Раскладка «24 байта = {fn, fn2, inScalar, inStruct, outScalar}» из §4.4.5
— артефакт: в этом блоке нет закромлённых u32-полей, каждый 8-байтовый
слот — chained fixup на код.

Открытые вопросы после закрытия:
- Какой живой вход ветвляет в group-creator (0x9F4E0BC→…→0x9F60A84,
  §4.4.5-цепь) — псевдотаблица не даёт ответа; хозяин диспетчеризации
  должен определяться runtime-sweep'ом из WebContent (как §4.4.9, item 2),
  статический «поиск владельца» снят с плаша.
- IOGPUVirtualMemory сам по себе без единого референса на свой vtable —
  класс может быть вырезан/деадкожен в этой сборке; если он вырезан, то
  и слоты его vtable — мертвовес, что согласуется с нулём ссылок.

Поправка к «cmdовскому» весу §4.4.9: эмпирика осталась в силе, но
интерпретация («таблица принадлежит не-открываемому клиенту») заменена:
блок не принадлежит НИКАКОМУ открышему клиенту, т.к. не подключён ни к
чему. §4.4.6 item 3 → DEAD. Критический путь не меняется: W-T3 пивот →
WebContent; OOB-диспетчеризация там — по результатам новой части.

### 4.4.11 Кандидат #4 (vm_fault_copy busy-page race) — снят по источнику (2026-10-17)

Дзен-разбор DJ-сессии: REPORT-23C55 #1-#8. DJ-вердикт «потолок низкий» подтверждён
исходником 61.12→81.4, панель:

- Окно 62.10: vm_fault_copy vm_fault.c:7837-7928 — последняя dst_object-лок-пара
  (:7849-7861, проверка vo_copy) дропается ДО физической записи
  (:7868-7928: vm_page_part_zero_fill / vm_page_part_copy / vm_page_zero_fill /
  vm_page_copy — pmap_copy_page / pmap_copy_part_page через transient KVA aperture).
  Состояние dst_page (vmp_busy / vmp_cleaning / iopl_wired / frame type) не
  перепроверяется — признана дропнутой нить.
- 81.4 фикс (vm_fault.c ~7858 diff): (a) recheck dst_page->vmp_busy после дропа →
  teardown + continue (livelock-safe, comment: vm_fault_page подождёт unbusy);
  (b) re-verify vmp_iopl_wired → KERN_MEMORY_ERROR, vmp_cleaning → vm_page_sleep;
  (c) CONFIG_SPTM: PMAP_PAGE_IS_USER_EXECUTABLE → pmap_disconnect_options(
  ..., PMAP_OPTIONS_RETYPE) «Consumers ... will be forced to re-fault ... 
  re-validate it for codesigning»;
  (d) dst_object-лок ДЕРЖИТСЯ через копию (SET_PAGE_DIRTY без unlock/relock) —
  основное устранение окна; full-page копия переведена на vm_page_part_copy.
- Замки в записи (vm_resident.c:6998/7050): vm_page_is_restricted panic обе
  стороны; vm_page_copy CS-валидация при code_signed src; MTE-tag паника
  untagged→tagged.
- Attacker-model: триггер = mach_vm_read / vm_copy / mach_msg OOL — полностью
  sandbox-легально, НО жертва = чистый dst_object (свежий при vm_map_copyout
  vm_map.c:11359 или keep-existing при copyin-оверхайте vm_map.c:11871) —
  входящий OOL буфер, не kernel-структура. Restricted-page = panic;
  exec-фрейм = SPTM aperture сам энафорит тип («physical aperture mapping is
  write-protected» — фикс-коммент) → в 62.10 это panic-DoS, не corrupted write;
  cross-task через "пережившие" маппинги нет — free-list фрейм отдаётся без
  extant pmap mappings (disconnect = hygiene после retype, не вешать атаку).
- Статус: CLOSED, на device-log не ставить. Если aperture писать можно при
  несовпадении frame_type → баг SPTM-firmware, другая категория.

---

---




### 4.9 УЯЗВИМОСТИ iOS 26.3 -> ЖИВЫ НА 23C55 (26.2) (2026-10-20 20:15, ПЕРЕПРОВЕРЕНО)

**Источник истины — advisory Apple для iOS 26.3 (Released February 11, 2026).**
CVE, помеченные как исправленные в 26.3, на 23C55 (26.2) **НЕ пропатчены** — по
определению. Это достоверное утверждение, оно не зависит от моих догадок о коде.

#### Подтверждённые advisory (iOS 26.3), живые на 26.2

| CVE | Компонент | Impact (цитата Apple) | Автор | Доступ из приложения |
|---|---|---|---|---|
| **CVE-2026-20626** | **Kernel** | **A malicious app may be able to GAIN ROOT PRIVILEGES** (improved checks) | Keisuke Hosoda | **да, напрямую** |
| **CVE-2026-20615** | **CoreServices** | **An app may be able to GAIN ROOT PRIVILEGES** (path handling, improved validation) | **Csaba Fitzl (theevilbit), Gergely Kalman** | да (xattr/файлы) |
| **CVE-2026-20617** | **CoreServices** | **An app may be able to GAIN ROOT PRIVILEGES** (race condition, improved state handling) | Golden Helm, Kalman, Fitzl | да |
| **CVE-2026-20667** | **libxpc** | **An app may be able to BREAK OUT OF ITS SANDBOX** (logic issue, improved checks) | anonymous | **да, тривиально (XPC)** |
| **CVE-2026-20628** | **Sandbox** | **An app may be able to BREAK OUT OF ITS SANDBOX** (additional restrictions) | Noah Gregory (wts.dev) | да |
| CVE-2026-20654 | Kernel | app -> unexpected termination (improved memory handling) | Jian Lee | да |
| CVE-2026-20637 | AppleKeyStore | UAF | Johnny Franks | да |
| CVE-2026-20634 | ImageIO | disclosure of **process** memory | gkarchemsky/ZDI | да |
| CVE-2026-20609 | CoreMedia | file -> disclose memory contents | Y. Can YILMAZ | да |
| CVE-2026-20611 | CoreAudio | **out-of-bounds access** | Trend Micro ZDI | да |
| CVE-2026-20700 | dyld | memory corruption, **0-day, эксплуатируется в дикой природе** | Google TAG | нужен memory write |

**Приоритет для нашей цепочки (app -> kernel RW -> jailbreak):**
1. **CVE-2026-20667 (libxpc, sandbox escape)** — XPC доступен из любого sandbox-приложения,
   «logic issue ... improved checks» = отсутствующая проверка. В связке с WebKit-pivot
   (уже есть renderer RCE, §4.1) это **песочница -> native exec**, без всякого IOGPU.
2. **CVE-2026-20615 / -20617 (CoreServices -> root)** — theevilbit & Kalman публикуют
   разбор с PoC. «path handling» + «race condition» — обе дают write-what-where.
3. **CVE-2026-20626 (Kernel -> root)** — «improved checks» в ядре. Самый ценный,
   но и самый закрытый (Keisuke Hosoda, без публичного PoC).
4. **CVE-2026-20611 (CoreAudio, OOB)** — OOB-доступ в CoreAudio из приложения.

#### Проверка по бинарям: что реально изменилось 26.2 -> 26.3

Скачан только kernelcache 26.3 (build 23D127) и извлечены кексты обеих версий.
Реально изменившиеся (остальное — churn подписи):
```
com.apple.kernel                        -32 720   XNU
com.apple.AGXG14P                       +16 472   GPU
AppleMobileDispH14P-DCP                 +16 408   display
AppleM2ScalerCSCDriver                  +16 560
AppleEmbeddedUSBHost                    +32 912
AppleGPIOICController                   +16 512
AppleSEPManager                         +16 392
IOUSBHostFamily                         +16 440
```

**Исправленная атрибуция (было неверно):**
* Строка `"Partial mapping of a memory entry"` **отсутствует в 26.2 и есть в 26.3** — но
  функция, которая её использует, **идентична в обоих билдах** (последовательность
  `add #0xb38 / casa / strb #0x154 / ldr #0x450 / casl / cmp #6 / ldrb / tbz` — 26.2 @0x8233fd8,
  26.3 @0x8239248, совпадает 1:1). Значит строка новая, а **проверка — нет**; вывод
  «в 26.2 нет проверки» был поспешным. Привязать её к CVE-2026-20626 нельзя.
* **CVE-2026-20620 (GPU Drivers, OOB read) — в advisory macOS 26.3, а НЕ в iOS.** Моя
  привязка строк про DP-pipe-лимиты (`Platform limits applied %u overall limited %u`) к
  CVE-2026-20620 для iOS **необоснована**. Изменение в AppleMobileDispH14P-DCP реальное
  (+16 КБ, новые строки про `limited %u` / `Apple Display %u pipes %u`), но его CVE в
  iOS-списке отсутствует => внутренний/нераскрытый фикс.

#### Чего НЕ доказано
* Эксплуатируемость. Diff доказывает, что **фикс в 26.3 отсутствует в 26.2**, но не
  что баг эксплуатируем (нужен либо публичный PoC, либо собственная проверка на устройстве).
* Публичных PoC на эти CVE нет (поиск 2026-10-20). История «Speedyfriend67 потерял PoC»
  — хайп без артефактов; сам CVE-2026-20654 в advisory Apple **реален** (вопреки статье
  pbxscience, утверждающей, что такого CVE нет).
* Конкретный код для CVE-2026-20626 не идентифицирован — Kernel-диф показывает
  32 КБ изменений без символов, нужна привязка по функциям.

#### Что сделано
`Sources/Legacy/iogpu_oob64.m` переписан в «method map»: P1 — открыть 8 сервисов x 8 типов
x 128 селекторов с валидным 256-байтным struct'ом (outCnt = sizeof(out); при outCnt=0
structureOutput = NULL и хендлер выходит сразу), записать kr по каждому; P2 — карта
`sel -> {OK,FAIL,BADARG,OTHER}`; P3 — реплей живых селекторов с cmd {0,1,2,3,64,130} x
capacity {1..4096}.

### 4.8 CVE-2025-24257 в IOGPUFamily 23C55 — ОКОНЧАТЕЛЬНО НЕДОСТИЖИМ ИЗ USER-SPACE (2026-10-20 15:40)

**Итог многоцикловой статики + эмпирики. Прежние два вывода («sel 64 = group creator»,
«достижимо, нужен только ключ») — оба неверны. Ниже — как получено.**

**1. Настоящая dispatch-таблица** прочитана прямо из кекста, вытащенного из kernelcache
(`ipsw kernel extract --all`): `__const` @ `0xfffffff007e66888`, таблица @ `0x7e67c58`,
stride 0x18, 112 записей. Формат — `IOExternalMethodDispatch` (XNU
`iokit/IOKit/IOUserClient.h`): `+0 fn`, `+8 checkScalarInputCount`,
`+0xC checkStructureInputSize`, `+0x10 checkScalarOutputCount`, `+0x14 checkStructureOutputSize`.

**2. «sel 64 -> 0x9f541ec» было ложным.** Указателей на `0x9f541ec` нет НИГДЕ: ни abs64,
ни low32, ни chained `0x8030bcad02f541ec` — ни в кексте, ни в kernelcache. У функции
`0x9f541ec` нет ни одного `bl`-вызова. BFS по call-графам всех 12 group-capable
dispatch-обработчиков (idx 6, 8, 25, 45, 52, 53, 62, 64, 81, 101, 108, 109 — те, у кого
`checkStructureInputSize == 0xffffffff`) **не находит пути** ни к `0x9f541ec` (group
dispatcher), ни к `0x9f60a84` (newResourceGroup), ни к `0x9f5fb04` (args-путь).
Цепочка `0x9f541ec -> 0x9f7314c -> 0x9f60a84 -> IOGPUGroupMemory::init` — **мёртвый код**.

**3. Эмпирика с устройства** (`Documents/oob64.log`):
```
IOGPU type=1 : 56/128 сел.   IOGPU type=33 : 128/128
AGX   type=1 : 56/128        AGX   type=33 : 128/128
```
112 = 56 + 56: это ДВЕ 56-элементные таблицы подряд (idx 0..55 и 56..111 — разные
наборы хендлеров, не дубли). Type 1 -> таблица A, type 33 -> A+B.

**4. `IOConnectCallStructMethod` не умеет передавать scalar-входы** — все строки с
`checkScalarInputCount > 0` отбивались ядром (`kIOReturnBadArgument`) ДО входа в хендлер.
Отсюда 0 SUCCESS во всех прогонах S3. Правильный вызов — `IOConnectCallMethod`
(несёт и скаляры, и struct).

**5. CVE-2025-24257 в IOGPUFamily 129.3.2 / 23C55 — недостижим.** Паттерн
`capacity>>6 - 1` (`0x9f612a4`) есть только в IOGPUFamily; в AGXG14P (отдельный кекст,
свой `IOGPUNewResourceArgs`) — **отсутствует**. Нужен другой путь создания ресурсов.

**Следствие для цепочки.** Путь `webkit pivot -> IOGPU OOB 24257 -> kernel RW` в этой
прошивке **не существует в виде user-space-exploitable**. Варианты:
  (а) искать OOB в ДРУГИХ kext'ах (AppleAVE2 / IOMobileGraphicsFamily-DCP — в лаборатории
      уже есть их бинари);
  (б) искать OOB в IOGPUFamily, НЕ связанный с group-memory (другие 56 обработчиков);
  (в) вернуться к B12 (kernel R/W через UAF-канал, нужен write) или к WebKit-ветке.

### 4.7 IOGPU 23C55 — метод-таблица разобрана, прежний «sel 64» ОКАЗАЛСЯ НЕВЕРНЫМ (2026-10-20 15:05)

**Эмпирика с устройства** (`Documents/oob64.log`, 14:57):
```
IOGPU type=1  : 56/128 селекторов существуют   (таблица A: idx 0..55)
IOGPU type=33 : 128/128                      (A + B)
AGX   type=1  : 56/128   AGX type=33 : 128/128
sel 8 на type=1 -> KERN_SUCCESS, outN=512
```

**Исправление прежнего вывода.** «Групповой создатель = sel 64 -> 0x9f541ec» было взято из
blocks-скана, а не из IOKit-таблицы. Проверено тремя способами: значения `0x9f541ec`
нет ни как abs64, ни как low32, ни как chained `0x8030bcad02f541ec` **нигде в кексте**.
Функция `0x9f541ec` не имеет ни одного `bl`-вызова — это внутренний обработчик,
достижимый только через per-row handler table.

**Реальная структура.** Таблица `0xfffffff007e67c58` (n=112) — это **две 56-элементные
таблицы подряд**: idx 0..55 = таблица A, idx 56..111 = таблица B (тот же fn-список со
сдвигом 56). Type 1 отдаёт A, type 33 отдаёт A+B.

**Формат записи** `{chained fn, q1, q2}`: **q1 = число scalar-входов, q2 = размер
structure-входа**. Пример: idx 42 `q1=2 q2=2` · idx 49 `q1=1 q2=0` · idx 54 `q1=2 q2=1`.
`q1/q2 = 0xffffffff` => «без аргументов».

**Групповой путь внутри кекста** (не через user-client селектор):
```
0x9f5415c  external method: w20 = scalarInput[0] -> 0x9f51970 -> 0x9f518a8 (поиск по индексу)
0x9f541ec  dispatcher: structSize>=88; outSize>=inScalar+88; struct[0]=cmd; cmd==130;
           key=struct[56] -> lookup в target->[240]; struct[60]>=validator
0x9f734b4  capacity = struct[60]
0x9f60fe4  newResourceGroup: capacity > 63 (проверка ЕСТЬ)
0x9f64910  grow: capacity = 2*count, нижней границы НЕТ  <- CVE
0x9f612a4  init: obj+40 = (capacity>>6)-1 ; capacity<64 => 0xffffffff
```

**Что сделано.** `Sources/Legacy/iogpu_oob64.m` переписан: таблица q1/q2 генерируется
из `hunt/dispatch_23c55.json` (без ручного переноса), S3 драйвит каждый существующий
селектор **с правильной арностью** (q1 scalars + q2-байтная структура) и ищет
KERN_SUCCESS/новый код возврата. Следующий шаг: найти селектор с q2>=0x58 (88) —
только такие дотягиваются до группового пути с capacity<64.

### 4.6 Логи в Documents (2026-10-20 14:40)

Добавлен устойчивый лог-канал рядом с `trace.log`:

| Файл | Что | Механизм |
|---|---|---|
| `Documents/srk801.log` | вся сессия (каждая строка `nk_log`) | `write(2)`+`fsync(2)` на строку |
| `Documents/oob64.log` | прогон IOGPU sel-64 | то же, плюс заголовок сессии |
| `Documents/trace.log` | WebKit/bridge события (было) | не тронут |

Хелпер: `Sources/Core/nk_trace.c` -> `nk_doc_log_open/nk_doc_log/nk_doc_log_close_all()`
(декл. в `nk_trace.h`). Lazy-open: первые строки не теряются, если `nk_log` сработал
до явного `nk_doc_log_open`. `nk_run()` открывает `srk801.log` на старте; probe
`iogpu_oob64` открывает `oob64.log` (макрос `ol()` дублирует в оба).

Зачем: паника ядра / fly-away убивают процесс — на диске остаётся ровно тот файл,
который закончился на killer-строке. Это единственное доказательство, переживающее
reboot.

### 4.5 SPTM 23C55 — оффлайн-разбор бинаря + кандидаты на race (2026-10-19 19:30)

Полный разбор: **Docs/sptm_23c55.md**. Артефакты: `Artifacts/sptm/` (sptm.macho, DeviceTree),
`Tools/{macho,sptm,refmap,findfn}.py`, `/home/abzal/ios262_lab/spmt/extract_sptm.sh`.

**Факт #1 (разблокировка).** На A15 SPTM лежит отдельным файлом в IPSW —
`Firmware/sptm.t8110.release.im4p`, 172 KB, **без шифрования** (LZFSE → Mach-O arm64e
1 064 992 B, UUID eaa5b2d2-6ced-302b-82f8-f8bf7b6af443). `sep-firmware.d17` при этом
зашифрован (production keybag, device key) — его не распаковать без девайса. Итог: SPTM
23C55 разобран офлайн, впервые.

**Карта SPTM (адреса в образе).** `sptm_map_page` 0x270d300c · `sptm_retype` 0x270d28dc ·
`sptm_map_table` 0x270d4550 · `sptm_unmap_table` 0x270d4fd0 · `sptm_update_region` 0x270d7350 ·
`sptm_update_disjoint` 0x270d7afc · `sptm_guest_dispatch` 0x270db1ec ·
`frame_acquire` 0x270c8b50 · `frame_release` 0x270c8d20 ·
`sptm_iofilter_protected_write` 0x270bebe8. FTE: +0 lock(casah) / +2 type(u8) /
+3 flags / +4 in_flight_ops(u16) / +6 mapping_refcnt(u16) / +8 nested_refcnt(u16).
Матрица типов — таблица 0x2701d720, stride 0x60, 64 типа (perm16, trans20, ctx30, fn+0x50).

**S1 (главный кандидат) — stale SPTM frame type.** `pmap_recycle_page`
(osfmk/arm64/sptm/pmap/pmap_data.c:2397) = 3 НЕАТОМАРНЫХ SPTM-вызова:
`pmap_is_page_free()` → `sptm_get_frame_type()` → `sptm_retype(..., XNU_DEFAULT)`,
причём **возврат sptm_retype игнорируется**. SPTM отклоняет retype, если заявленный текущий
тип не совпадает с фактическим (0x270d29bc `cmp w8,w23` → violation) ⇒ при гонке с
конкурентным retype кадр уходит в VM free-list с типом ≠ XNU_DEFAULT. Проверки типа при
free — только assert (release no-op): vm_resident.c:5646, pmap_data.c:575 (SPTM TODO).
Тип «липкий»: `pmap_type_requires_retype_on_recycle()` (pmap_data.h:2196) сбрасывает только
USER_EXEC/USER_DEBUG/USER_JIT/ROZONE/KERNEL_RESTRICTED. Второй вход — окно
retype→map_page в `pmap_enter_pte()` (pmap.c:6152-6180), где сам код признаёт, что
`pmap_remove()` снимает маппинг БЕЗ PVH-lock (pmap.c:6134-6138).

**S3 — граница in-flight/карантин.** `sptm_paddr_is_inflight()` (sptm.h:60) +
`pmap_paddr_inflight_barrier()` (pmap_data.c:2263) — это запрос, потом отдельный запрос
`pmap_is_page_free()`, потом free; атомарности нет. Ядро само признаёт, что батчевые
multipage-операции делают SPTM-вызовы **без PVH/pmap-лока** (pmap.c:4033-4039). Обход
карантина SPTM (то, что в pmap_tte_remove названо блокирующей эксплуатацию фичей) —
отдельная задача, искать надо в SPTM-бинаре.

**ЗАКРЫТО (проверено, с док-вами).**
- CVE-2025-43520 (DarkSword, TOCTOU в VFS cluster_write_contig) — **уже пропатчено**:
  vfs_cluster.c:3700 и :6105 в 61.12 уже содержат `if (!(upl_flags & UPL_PHYS_CONTIG))`;
  61.12 < 62.10 ⇒ есть в 23C55. Блоги/Feedly противоречат друг другу — источник правды
  исходник, а не пресс-релиз.
- uint16-overflow refcnt → dangling PTE (pmap_tte_remove) — **на SPTM-сборках не проходит**:
  SPTM режет число маппингов на кадр до 2048 (0x270d477c `cmp w9,#0x801` → violation/panic).
  Переполнения не будет, будет DoS.
- Внутри SPTM check-then-act окна нет: тип читается и PTE ставится CAS-ом под
  exclusive-guard кадра (0x270d30c0 frame_acquire → 0x270d3330 `casl`).

**Дальше:** (1) дописать матрицу «тип → права → kernel-контексты» и понять, какой залипший
тип опасен; (2) найти смену типа без PVH-lock; (3) ловить SPTM-violation в device-log
(`VIOLATION_ILLEGAL_RETYPE`, `VIOLATION_FRAME_HELD_EXCLUSIVE`, `VIOLATION_FRAME_OWNER`);
(4) искать обход карантина в SPTM-бинаре; (5) параллельно — `sptm_update_disjoint` читает
op-массив по ФИЗИЧЕСКОМУ адресу per-CPU буфера ядра ⇒ если до него можно дотянуться из
user (линия T3) — это отдельный канал.

---

## 5.0 СВОДКА: ВЫБРАННЫЙ ПУТЬ К KERNEL R/W (2026-10-20 20:40)

Полный реестр уязвимостей с оговорками — в **`VULNS.txt`** (в корне репо).

**Выбранный путь: AIO kevent UAF (трек B, «B12»).** Единственный, где в репо уже
есть **подтверждённый на устройстве** примитив, и он не требует нового CVE.

```
aio_read(SIGEV_KEVENT)  -> aio_workq_entry в aio_workq_zonep + knote на kqueue
aio_read(SIGEV_NONE)    -> донор: его запись free + LIFO-claim в тот же слот
dangling knote          -> filt_aioprocess() идёт по ОСВОБОЖДЁННОЙ записи:
                             kev.ext[0] = errorval  (+0x28)   [R] подтверждено
                             kev.ext[1] = returnval (+0x20)   [R] подтверждено
                             kev.ident  = uaiocbp    (+0x48)
                             kev.udata  = sival_ptr  (+0x50)
```

**Запись — тот же примитив**, потому что все три опасных действия читают свои
операнды ИЗ САМОЙ записи:

| в filt_aioprocess | читает | даёт |
|---|---|---|
| `TAILQ_REMOVE(entry)` | +0x10 prev, +0x18 next | **write-what-where** (`*prev = next`) |
| `aio_entry_unref(entry)` | +0x2C refcount | **double free** → отравление freelist |
| `aio_proc_lock(*(entry+0x40))` | +0x40 procp | procp=0 ⇒ **PANIC FAR=0x58** (наблюдаемый ребут) |

Сейчас слот обнулён на free ⇒ писать некуда ⇒ «запись мертва». **Не хватает
одного: спрея в зону `aio_workq_zonep`** (224 B / 0xE0), чтобы свободный слот
переиспользовался НАШИМ содержимым. Тогда: TAILQ_REMOVE пишет по нашим адресам,
unref даёт double free, procp из нашего объекта убирает панику.

`Sources/Legacy/nk_spray.m` — портовый спрей (E1), зону aio не трогает ⇒ нужен
свой zone-спрей. Остальное (read-канал, карта объекта, root-эскалация) в дереве.

**Что изменилось в оценке линий:**
* **CVE-2025-24257 (IOGPU) — ЗАКРЫТ на 26.2.** Фикс 18.4 присутствует в 23C55
  (`cmp w2,#0x3f` @ `0x9f60fcc`): capacity<64 ⇒ kIOReturnNoResources. Прежний
  «тупик» был ВЕРЕН, но объяснялся неверно (искали sel 11/64 в неверной таблице;
  реальная таблица IOGPUFamily = `0x7e67c58` = ДВЕ 56-элементные, sel 64 есть
  только на type 33, а группа создаётся **sel 8 на type 1**).
* **Найдены живые CVE 26.3** (приложения → root / sandbox escape / OOB) — фикс в
  26.3 ⇒ на 23C55 не пропатчены. Приоритет: libxpc-20667 (sandbox escape),
  CoreServices-20615/-20617 (root, theevilbit+Kalman), Kernel-20626 (root).
* **CVE-2026-20620 (GPU Drivers) — macOS-only**, в iOS-списке его нет.


### 5.1 НОВАЯ ЦЕПОЧКА (решение dj 2026-10-20 20:45): AIO отложен, идём по DCP + libxpc

**AIO-трек (B12) отложен.** UAF доказан, но запись требует контролируемого объекта
в зоне `aio_workq_zonep` (224 B); текущий спрей — Mach-портовый и в эту зону не
попадает. Это тот же cross-type reclaim, что закрыт для 192-бакета.

**Что открыто нового:**

1. **Скачан 26.1 kernelcache** (build 23B85) — теперь локально ТРИ версии
   (26.1 / 26.2 / 26.3) => можно искать РЕГРЕССИИ (снятые проверки), а не
   только фиксы.
2. **Хантинг-тулчейн** `Tools/regress/` (= `~/ios262_lab/diff27/`):
   `macho.py` (секции/строки/adrp-резолв; LC_FUNCTION_STARTS от базы __TEXT),
   `regress.py` (инвентарь функций), `removed_checks.py` (точка расхождения),
   `filter_regress.py` (авто-флаг «cmp #imm+ветвление -> cbz» = снятая граница).
3. **Первые результаты 26.1->26.2:** ядро — **107 удалённых кодовых путей**,
   AGXG14P — 21. Два AGX-кандидата (`0x883b2c`, `0x883c4c`) авто-флагнуты, но
   ручная проверка показала: сдвиг тоже изменился (0x16->0x1b), константа та же
   0x5e7ec00000 => это смена проверяемого поля, НЕ снятая граница. AGX = рефакторинг.
4. **DCP (AppleMobileDispH14P-DCP) — подтверждённый фикс Apple в 26.3:**
   новые строки «Platform limits applied %u overall limited %u» и
   «Update Ext Pipe state: is_plug %u total count %u limited %u Apple Display %u pipes %u»,
   счётчики в __DATA_CONST +0x668/+0x66c/+0x670. В 26.2 такого кода нет =>
   **лимита на число pipe'ов нет** => OOB-WRITE в массив pipe'ов.
   26.3 @0x947807c: vtable+0xa0 -> кол-во; `cmp w0,#4` -> bail; затем
   `add x8,x21,w0,uxtw ; sub x20,x8,#4` (массив, индексируемый количеством).
   Осталось: найти 26.2-эквивалент и подтвердить отсутствие границы.
5. **CVE-2026-20667 (libxpc -> sandbox escape)** — [LIVE], XPC доступен из любого
   sandbox-приложения, «logic issue ... improved checks» = отсутствующая проверка.
   В связке с W-T0/W-T2 (renderer RCE уже есть) даёт native-код вне песочницы.

