# SPTM на 23C55 (iOS 26.2, A15/t8110) — оффлайн-разбор, карта внутренностей, кандидаты на race

Дата: 2026-10-19. Устройство: iPhone14,5 (A15, t8110), iOS 26.2 = 23C55, xnu-12377.62.10.
Ядро в лаборатории: `xnu-12377.61.12` (`/home/abzal/ios262_lab/hunt/xnu-61`).
SPTM-прошивка: `Firmware/sptm.t8110.release.im4p` внутри IPSW.

---

## 0. Где лежит прошивка

| Что | Путь |
|---|---|
| IPSW (10 GB) | `/home/abzal/ios262_lab/iPhone14,5_26.2_23C55_Restore.ipsw` |
| Распакованный firmware | `/home/abzal/ios262_lab/extracted/kernel/23C55__iPhone14,5/Firmware/all_flash/` |
| **SPTM-прошивка (НОВОЕ)** | `/home/abzal/ios262_lab/spmt/sptm.t8110.release.im4p` → `sptm.macho` |
| DeviceTree | `/home/abzal/ios262_lab/spmt/DeviceTree.d17ap.payload` (+ `dt.json`) |
| KC 23C55 | `/home/abzal/ios262_lab/diff27/262/kernelcache.release.iPhone14,5` |
| Kexts 23C55 | `/home/abzal/ios262_lab/kexts23c55/` |
| SPTM-тулы (macho.py / sptm.py / refmap.py / findfn.py) | `Tools/` в проекте + `/home/abzal/ios262_lab/sptm/ana/` |

Воспроизводимо: `bash /home/abzal/ios262_lab/spmt/extract_sptm.sh` (достаёт SPTM+DT из IPSW, распаковывает, печатает sha256).

---

## 1. ГЛАВНОЕ: SPTM на A15 доступен без устройства

На A15 SPTM лежит **отдельным файлом в IPSW**, а не внутри `sep-firmware`:

```
Firmware/sptm.t8110.release.im4p        172 000 B   (IMG4, без шифрования, LZFSE)
  -> payload 1 064 992 B                Mach-O 64-bit arm64e executable
  UUID eaa5b2d2-6ced-302b-82f8-f8bf7b6af443
  sha256 6aac538a592ba71686713f9db9a6ab80f778722712055bc4973fc8e55ac7aad2 (1 064 992 B)
  Mach-O 64-bit arm64e executable, flags:<NOUNDEFS|PIE>, код-подпись PAK00
```

Для сравнения: `sep-firmware.d17.RELEASE.im4p` — **зашифрован** (production keybag, AES-CBC; ключ
устройства → без девайса не распаковать), там же SPTM-составляющая не читается.

Практическое следствие: **полный статический анализ SPTM для 23C55 теперь возможен офлайн.**
Это снимает главный блокер «SPTM race bypass» — раньше не было даже бинаря SPTM, не говоря
о дизассембле. Всё ниже получено из этого бинаря + исходников 61.12.

Проверка, что SPTM реально активен в 23C55: в KC присутствуют клиентские символы
`sptm_get_frame_type`, `sptm_get_page_table_refcnt`, `sptm_paddr_is_inflight`,
`sptm_frame_is_last_mapping`, `SPTM load address: %p`, `sptm_stability_hacks`.

### 1.1 Устройство бинаря

| Сегмент | VA | Размер | prot |
|---|---|---|---|
| `__TEXT` (`__cstring` 0x4860, `__const`, `__binname`, `__chain_starts`) | 0xfffffff027004000 | 0x14000 | r-x |
| `__DATA_CONST` | 0xfffffff027018000 | 0x8000 | rw- |
| `__LATE_CONST` (инициализируется в рантайме, в файле нули) | 0xfffffff027020000 | 0x68000 | rw- |
| `__TEXT_EXEC` (`__text`) | 0xfffffff027088000 | 0x58000 | r-x |
| `__DATA` | 0xfffffff0270e4000 | 0x10000 | rw- |
| `__BOOTDATA` | 0xfffffff0270f4000 | 0x14000 | rw- |

Символов нет (1 символ `__start`), LC_FUNCTION_STARTS нет → границы функций восстановлены
эвристикой по прологу; имена функций восстановлены по их `__func__`-строкам (см. `Tools/refmap.py`).
В `__cstring` 65 107 байт строк — это и есть карта: имена функций, имена параметров,
assert-строки, violation-коды.

---

## 2. Внутренности SPTM (нужны для оценки любого race)

### 2.1 FTE (frame table entry) — запись на физический кадр

| Offset | Тип | Что |
|---|---|---|
| +0 | u16 | **lock word**: `casah` — эксклюзивный guard кадра (`VIOLATION_FRAME_HELD_EXCLUSIVE`) |
| +2 | u8 | **type** (0..63) — тип кадра |
| +3 | u8 | flags (бит1 = «held shared») |
| +4 | u16 | `in_flight_ops` — счётчик незавершённых операций (в кадре) |
| +6 | u16 | `mapping_refcnt` — число маппингов на этот кадр |
| +8 | u16 | `nested_refcnt` — для root-таблиц |

Тип читается как `ldrb [fte,#2]`; refcnt — `ldrh`.

### 2.2 Матрица типов (table `0xfffffff02701d720`, stride 0x60, по 64 типа)

Поля записи типа T:

| Offset | Поле | Смысл |
|---|---|---|
| +0x00 | u64 | флаги типа (низкие биты: 0x0301 user-data, 0x0601 IO, 0x0101 root, 0x0201 page-table, 0x0501 IOMMU; высокие — маска «классов прав») |
| +0x04 | u16 | **разрешённые классы прав** (perm-class: 4 бита = {PTE[54:53], PTE[5:4]}) |
| +0x12 | u8 | 1 ⇒ тип «исполняемый пользователем» |
| +0x20 | u64 | **разрешённые переходы INTO этот тип** (бит = старый тип) |
| +0x30 | u64 | **разрешённые контексты** (бит = тип) — маска «в каких контекстах тип допустим» |
| +0x40 | u16 | маска «из каких типов переход разрешён» |
| +0x50 | u64 | **указатель на per-type retype-обработчик** (xnu_exec_retype_out, xnu_generic_retype_out, …) |

Расшифровка (SPTM-внутренний enum, ID = порядок строк в `__cstring`):

| ID | Тип | perm16 | переходы INTO (0x20) |
|---|---|---|---|
| 11 | XNU_DEFAULT | 0x8a88 (3,7,11,15) | 0x100000cbb9fbc802 |
| 12 | XNU_RO | 0x0000 | — (маппится батчем, не через sptm_map_page) |
| 14 | XNU_USER_EXEC | 0xa800 (11,15) | 0x800 (только из XNU_DEFAULT) |
| 15 | XNU_USER_DEBUG | 0xa080 (11,15) | 0x800 |
| 16 | XNU_USER_JIT | 0x8020 (5,15) | 0x800 |
| 17 | XNU_USER_ROOT_TABLE | 0 | 0x40800 |
| 19 | XNU_PAGE_TABLE | 0 | 0x800 |
| 24 | XNU_ROZONE | 0x0800 (11) | 0x800 |
| 25 | XNU_IO | 0x8888 | — |
| 26 | XNU_PROTECTED_IO | 0x0800 | — |
| 29 | XNU_COMMPAGE_RX | 0xa000 (13,15) | — |
| 33 | XNU_KERNEL_RESTRICTED | 0x0808 (3,11) | 0x200000800 |
| 39 | TXM_DEFAULT | 0 | 0x0300400000000000 |

Практический вывод: **тип XNU_DEFAULT не даёт маппинга «свободно-исполняемым пользователем»**
(в perm16 нет 0/1 в старшем ниббле) — исполняемый user-тип выдаётся только явным retype
XNU_DEFAULT → XNU_USER_EXEC/DEBUG/JIT. Именно поэтому в ядре есть
`pmap_type_requires_retype_on_recycle()` (pmap_data.h:2196) — при возврате страницы в
free-list тип сбрасывается в XNU_DEFAULT **только** для USER_EXEC/USER_DEBUG/USER_JIT,
XNU_ROZONE, XNU_KERNEL_RESTRICTED. Все остальные типы «липкие».

### 2.3 Карта функций (адреса в SPTM-образе, база 0xfffffff027004000)

| Адрес | Функция | Что делает |
|---|---|---|
| `0x270d300c` | `sptm_map_page` | главный путь маппинга: get_ptep → **frame_acquire** → чтение типа → проверка perm16/perm-матрицы → **CAS установка PTE** |
| `0x270d28dc` | `sptm_retype` | смена типа кадра: CAS-lock кадра, **сверка типа с заявленным**, проверка домена и маски переходов, вызов per-type обработчика |
| `0x270d4550` | `sptm_map_table` | инкремент `mapping_refcnt` кадра таблицы (`ldaddh`, cap 2048) |
| `0x270d4fd0` | `sptm_unmap_table` | декремент + освобождение таблицы |
| `0x270d7350` | `sptm_update_region` | массовое обновление прав в VA-регионе (preflight/finalize внутри SPTM) |
| `0x270d7afc` | `sptm_update_disjoint` | обновление разрозненных маппингов (op-массив читается с физического адреса per-CPU!) |
| `0x270db1ec` | `sptm_guest_dispatch` | гостевая (виртуализация) ветка |
| `0x270c8b50` | `frame_acquire` | взять кадр в работу (инкремент `in_flight_ops`) |
| `0x270c8d20` | `frame_release` | отпустить кадр |
| `0x270c7ad8` | `mapping_refcnt` accessor | читает FTE+6 / FTE+8 |
| `0x270c824c` | rc16-хелпер | `ldaddh` по 16-битным refcnt + проверки overflow/underflow |
| `0x270bebe8` | `sptm_iofilter_protected_write` | медиация SPTM-сторонней записи в защищённый IO (DT-фильтры) |

Ключевые инструкции (цитаты из дизассембла):

```
; sptm_retype: сверка «заявленный текущий тип» == «фактический тип в FTE»
0x270d29bc: cmp  w8, w23          ; w8 = FTE->type, w23 = аргумент current_type
0x270d29c0: b.ne 0x270d2dd4       ; -> VIOLATION (тип не совпал, отказ)

; sptm_map_page: атомарная установка PTE
0x270d332c: mov  x20, x25
0x270d3330: casl x20, x26, [x16]  ; CAS старого PTE -> нового
0x270d3338: b.eq 0x270d342c        ; успех

; sptm_map_table: потолок счётчика маппингов
0x270d4778: ldaddh w9, w9, [x8]   ; FTE+6, атомарно +1
0x270d477c: cmp   w9, #0x801
0x270d4780: b.lo  0x270d47b0       ; старое < 0x801 -> ok
0x270d4784: ldarh w10, [x8]        ; иначе -> VIOLATION/panic (0x270d4e5c)
```

### 2.4 Что SPTM уже НЕ пропускает (проверено, закрыто)

* **Overflow 16-битного refcnt кадра** — SPTM ограничивает число маппингов на кадр 2048
  (`0x801` порог → violation/panic). Т.е. «65537 MAP_SHARED → uint16 overflow → dangling PTE»
  (публикация Indegosblade, pmap_tte_remove) **на SPTM-сборках не проходит**: SPTM упадёт
  раньше, чем счётчик перевернётся. На 23C55 — DoS, не UAF.
* **Гонка «тип проверили, потом маппинг»** — SPTM атомарен: тип читается, проверяется по
  perm16/контекстной маске, PTE ставится CAS-ом, всё под exclusive-guard кадра.
  Окно «check-then-act» **внутри SPTM отсутствует**.
* **Отказ при несовпадении типа в retype** — есть (0x270d29bc), и именно это делает
  уязвимым *ядро*, а не SPTM (см. S1).

---

## 3. Кандидаты на race (ранжировано)

### S1 — `pmap_recycle_page`: TOCTOU → «липкий» тип кадра в SPTM  (главный кандидат)

Ядро (`xnu-12377.61.12`, `osfmk/arm64/sptm/pmap/pmap_data.c:2397`):

```c
inline void
pmap_recycle_page(ppnum_t pn)
{
        const bool is_freed = pmap_is_page_free(ptoa(pn));      // (1) запрос в SPTM
        if (__improbable(!is_freed)) { ... panic ... }

        const pmap_paddr_t paddr = ptoa(pn);
        const sptm_frame_type_t frame_type = sptm_get_frame_type(paddr);  // (2) запрос в SPTM
        if (__improbable(pmap_type_requires_retype_on_recycle(frame_type))) {
                const sptm_retype_params_t retype_params = {.raw = SPTM_RETYPE_PARAMS_NULL};
                sptm_retype(paddr, frame_type, XNU_DEFAULT, retype_params); // (3) действие в SPTM
        }
}
```

Три **отдельных** SPTM-раунд-трипа, атомарности между ними нет:

1. (1) `pmap_is_page_free()` (pmap_data.c:2286) — если SPTM говорит «in flight», крутимся в
   `pmap_paddr_inflight_barrier()`; иначе `sptm_frame_is_last_mapping(paddr, SPTM_REFCOUNT_NONE)`.
2. (2) `sptm_get_frame_type()` — читаем тип.
3. (3) `sptm_retype(paddr, frame_type, XNU_DEFAULT)` — **возвращаемое значение игнорируется**.

Гонка между (2) и (3):

* Другой поток меняет тип кадра (например `pmap_enter_pte()` → `sptm_retype(pa, prev, new)`,
  pmap.c:6152-6156).
* Наш `sptm_retype(paddr, frame_type, XNU_DEFAULT)` приходит с **устаревшим** `frame_type`.
* SPTM сверяет заявленный тип с фактическим (0x270d29bc) → **отказ** (violation).
* Ядро результат не проверяет → кадр остаётся с не-default типом.
* `vm_page_free_prepare()` (vm_resident.c:5636-5647) проверяет тип **только assert-ом**
  (в release — no-op): `assert(frame_type == XNU_DEFAULT);`
* `pmap_page_free()` (pmap_data.c:573-575) — в коде стоит комментарий
  `/* SPTM TODO: assert that the page to be freed is of type XNU_DEFAULT in frame table */`
  и ничего не делает.

Итог: **физический кадр уходит в VM free-list с типом ≠ XNU_DEFAULT**, и тип «липкий»
(pmap_type_requires_retype_on_recycle чинит только USER_EXEC/DEBUG/JIT/ROZONE/KERNEL_RESTRICTED).

Что это даёт — надо довести до конца (это следующий шаг, не сделано):

* Если «залипший» тип — **XNU_USER_EXEC**, то SPTM разрешит маппинг этого кадра как
  исполняемого в user-адресном пространстве, хотя ядро считает его обычной user-страницей.
  Для самого атакующего это не новость (JIT), но SPTM-исключение «physical aperture mapping is
  write-protected» перестаёт работать так, как задумано.
* Если «залипший» тип — **что-то привилегированное** (XNU_RO / XNU_ROZONE / XNU_KERNEL_RESTRICTED /
  XNU_PROTECTED_IO), то SPTM разрешит маппинг кадра с правами, которые ядро не запрашивало
  (perm16 у XNU_ROZONE = 0x0800, у XNU_KERNEL_RESTRICTED = 0x0808) — то есть SPTM-матрица
  разрешит то, что при корректном типе было бы запрещено.
* Направление опасного перехода (user→kernel) требует, чтобы **ядро** само попросило маппинг
  кадра в kernel VA; SPTM такие запросы отклоняет по типу. Поэтому чистый «stale type» →
  kernel-code-exec не даёт. Он даёт **рассинхрон типа и реального содержимого** — это и есть
  точка, которую надо проверять на устройстве (см. §5).

Проверяемость: нужно (а) найти путь, где тип меняется без PVH-lock, и (б) на device-log поймать
`VIOLATION` из SPTM на retype (в SPTM есть violation-подсистема со строками
`VIOLATION_ILLEGAL_RETYPE`, `VIOLATION_FRAME_HELD_EXCLUSIVE`, `VIOLATION_FRAME_OWNER`).

### S2 — окно `retype → map_page` в `pmap_enter_pte()`

`pmap.c:6132-6180`:

```c
if (__improbable(new_frame_type != prev_frame_type)) {
        pmap_page_protect_options_with_flush_range(... PMAP_OPTIONS_PPO_PENDING_RETYPE ...);
        prev_frame_type = sptm_get_frame_type(pa);
        if (new_frame_type != prev_frame_type) {
                sptm_retype(pa, prev_frame_type, new_frame_type, retype_params);  // тип меняется
        }
}
...
const sptm_return_t sptm_status = sptm_map_page(pmap->ttep, v, new_pte);           // маппинг ставится
```

Между retype и map_page кадр имеет «привилегированный» тип. SPTM-часть атомарна
(map_page сам перечитывает тип и ставит PTE CAS-ом), но:

* ядро в этот момент **держит PVH-lock на кадре**, однако комментарий в самом коде
  (pmap.c:6134-6138) признаёт: `pmap_remove()` может снять маппинг **не** беря PVH-lock.
  Значит параллельный `pmap_remove()`/recycle кадра в это окно — реальная, не умозрительная гонка.
* На failure-пути ядро делает `sptm_retype(pa, new_frame_type, prev_frame_type)` (pmap.c:6193-6195)
  — опять без проверки возврата; если этот retype отклонён (тип уже сменила третья нить),
  кадр остаётся с типом `new_frame_type`.

Это второй вход в тот же stale-type баг, что и S1.

### S3 — граница kernel↔SPTM: in-flight / карантин

Механизм защиты SPTM от «использования освобождаемого кадра»:

* SPTM держит `in_flight_ops` (u16, FTE+4) и эксклюзивный guard (`casah` по FTE+0).
  `frame_acquire` (0x270c8b50) ставит guard и инкрементит in-flight **до** чтения типа.
* Ядро спрашивает `sptm_paddr_is_inflight(paddr)` (sptm.h:60) и, если «in flight» — ждёт
  (`pmap_paddr_inflight_barrier`, pmap_data.c:2263).
* Перед освобождением: `pmap_is_page_free()` → `sptm_frame_is_last_mapping(paddr, SPTM_REFCOUNT_NONE)`.

Окно: «не in flight» и «нет маппингов» — это **два разных запроса** и они не атомарны между
собой и с последующим `vm_page_free()`. Само ядро признаёт, что часть батчевых операций
(«multipage batched cacheability/attribute update») **делает SPTM-вызовы без PVH/pmap-лока**
(pmap.c:4033-4039):

```
 * Drain any concurrent retype-sensitive SPTM operations. This is needed to
 * ensure that we don't unmap the page table and retype it while those operations
 * are still finishing on other CPUs, leading to an SPTM violation. In particular,
 * the multipage batched cacheability/attribute update code may issue SPTM calls
 * without holding the relevant PVH or pmap locks ...
```

То есть окно «SPTM-операция стартовала на кадре, который ядро уже считает свободным» —
признано самими исходниками. Это и есть точка для гонки с карантином SPTM.

**Карантин SPTM** (то, что в публикации pmap_tte_remove названо блокирующей эксплуатацию
фичей) реализован на стороне SPTM: освобождённые табличные страницы удерживаются SPTM
(«in flight»/quarantine) и не возвращаются в аллокатор. Значит **обход карантина SPTM** —
это отдельная задача, и она в SPTM-бинаре искать проще, чем в ядре.

### S4 — protected-IO фильтр (проверен, выглядит закрытым)

`sptm_iofilter_protected_write` (0x270bebe8), вызывается, когда ядро/устройство пишет в
«защищённый IO»:

```
size ∈ {1,2,4,8}          ; (1<<size)&0x116 != 0
paddr выровнен по size    ; paddr & (size-1) == 0
paddr внутри DT-диапазона pmap-io-ranges
off = paddr & 0x3fff
off >= filter.offset && off+size <= filter.offset+filter.length   ; всё в 32-битной арифметике
```

Арифметика без переполнения (32-битные add, границы в u16), фильтры — из DeviceTree
(недоступны для модификации атакующим). Итог: вектор слабый, оставляю как «проверено, не
приоритет».

---

## 4. Что проверено и закрыто (не тратить время)

| Кандидат | Статус на 23C55 | Доказательство |
|---|---|---|
| CVE-2025-43520 (DarkSword, TOCTOU в VFS `cluster_write_contig`) | **уже пропатчено** | `bsd/vfs/vfs_cluster.c:3700` и `:6105` в 61.12 уже содержат проверку `if (!(upl_flags & UPL_PHYS_CONTIG)) { error = EINVAL; ... }`. 61.12 < 62.10 ⇒ есть и в 23C55. Feedly/блоги («фикс в 26.3») противоречат друг другу — **источник правды здесь исходник**. |
| CVE-2025-43510 (AppleM2ScalerCSCDriver) | не применимо | macOS-драйвер, в iOS нет |
| uint16-overflow refcnt → dangling PTE (pmap_tte_remove) | **на SPTM-сборках не проходит** | SPTM ограничивает маппинги на кадр 2048 (`0x270d477c cmp w9,#0x801` → violation). Переполнения не будет, будет panic |
| свой user client в kext | закрыт статически | Docs/PROJECT §4.4.10 |

---

## 5. Что делать дальше (план на device)

1. **Декодировать типы до конца.** Собрать финальную таблицу «тип → разрешённые классы прав →
   разрешённые VA-контексты» и выписать, какие типы дают маппинг в **kernel-пространство**
   (`sptm_map_page` с root=kernel_pmap). Это даёт ответ, какой «залипший» тип опасен.
   Инструмент: `Tools/sptm.py` + таблица `0x2701d720`.
2. **Найти окно смены типа без PVH-lock.** Искать в `pmap.c` все места с `sptm_retype(` и
   проверять, держится ли PVH-lock; плюс `pmap_remove()` (комментарий pmap.c:6134 признаёт,
   что он его не берёт). Цель — воспроизвести stale-type в логе.
3. **Ловить SPTM-violation на устройстве.** В SPTM есть своя подсистема violation
   (`VIOLATION_ILLEGAL_RETYPE`, `VIOLATION_FRAME_HELD_EXCLUSIVE`, `VIOLATION_FRAME_OWNER`,
   `VIOLATION_ILLEGAL_PTE_WRITABLE`, `VIOLATION_INVALID_IOFILTER_WRITE_SIZE` и др.) —
   их появление в device-log = гонка попала в окно.
4. **Обход карантина SPTM** (если нужен именно он): в SPTM-бинаре искать, где
   `in_flight_ops`/`mapping_refcnt` обнуляются и кто решает, что кадр можно вернуть в
   аллокатор. Строки-подсказки: `array_fte->in_flight_ops`, `fte->in_flight_ops`,
   `sptm_paddr_is_inflight` (клиент ядра), `%s: Frame %p not acquired, in_flight_ops: %hu`.
5. **Быстрый выигрыш параллельно:** `sptm_update_disjoint` принимает op-массив **по физическому
   адресу** (per-CPU буфер ядра). Проверить, может ли user-код добраться до per-CPU буфера
   (утечка указателя через kalloc-конфлизионный баг — это как раз линия T3 проекта).

---

## 6. Приложение: команды

```sh
# достать SPTM+DT из IPSW
bash /home/abzal/ios262_lab/spmt/extract_sptm.sh

# разобрать SPTM (нужен capstone: /tmp/kilo/venv)
cd /home/abzal/ios262_lab/spmt/ana
/tmp/kilo/venv/bin/python findfn.py sptm_map_page sptm_retype sptm_map_table
/tmp/kilo/venv/bin/python sptm.py func 0xfffffff0270d300c 1200   # sptm_map_page
/tmp/kilo/venv/bin/python sptm.py ref sptm_retype                 # xref по строке-имени
/tmp/kilo/venv/bin/python refmap.py                               # полная карта ссылок
```

Инструмент `Tools/macho.py` — минимальный парсер Mach-O (сегменты/секции/symtab/uleb
function-starts), `Tools/sptm.py` — дизассемблер SPTM с разрешением adrp+add/mem,
`Tools/refmap.py` — построитель карты ссылок, `Tools/findfn.py` — поиск функции по строке.
