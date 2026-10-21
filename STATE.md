# 23C55 (iOS 26.2, iPhone 13 / A15) — состояние на 2026-10-21 18:20

## Подтверждённые факты (эмпирика, телефон)
- IOGPU открывается: IOServiceOpen("IOGPU", type=1), селектор 8.
- cmd=3 (new group) принимает struct[56] = ТИП РЕСУРСА: работают только
  64/128/256/1024/4096/65536/262144 (степени двойки >= 64). Остальное
  kIOReturnNoResources (0xe00002be). Гейт в коде: 0x9f60fe4 cmp w2,#63
  + проверка "степень двойки".
- cmd=3 возвращает в out+0x10 ПОЛЬЗОВАТЕЛЬСКИЙ адрес (0x1_xxxx_xxx0) —
  группа отдаётся как userspace-маппинг, ядерного указателя там нет.
- cmd=130 (add resource): struct[56] = IOSurface global id. Принимает
  валидные id, отклоняет невалидные (0xe00002c2).
- cmd=130 ПРИНИМАЕТ ПОВТОРНЫЙ add того же id (kr=0) — insert выбрасывает
  старую запись.
- cmd=64 (2D-путь) закрыт: NoResources на всех комбинациях, и на свежей
  сессии, и после cmd=3. Команд удаления ресурса по id нет (перебраны все
  256).
- Канал чтения ядра мёртв: NECP data-only вектор на 23.55 не отражает
  (phase 1 -> 0 смещений); nk_do_kread возвращает -1.
- Охота за утечкой по 40 именам служб: 0 ядерных указателей, открылись
  только IOGPU, AGXAcceleratorG14P, IOSurfaceRoot, IOMobileFramebuffer.
  Обход всего IORegistry: IOServiceMatching(NULL) + IOIteratorNext
  (IORegistryCreateIterator на iOS не даёт ничего).

## Карта кода (проверена llvm-objdump)
- CREATE 0x9f60fcc: capacity группы = ТИП ресурса; гейты >63 и степень двойки.
- group info 0x9f61200: +0x20 capacity, +0x24 cap-1, +0x28 MASK=(cap>>6)-1,
  +0x2c log2(cap), +0x10 bitmap (4 байта на bucket), +0x00 элементы (8 байт).
- hash table 0x9f7552c: +0x28 capacity, +0x2c cap-1, +0x30 MASK,
  +0x34 log2, +0x10 массив kalloc(cap*4) (4 байта на слот), +0x18 bitmap,
  +0x40 max.
- insert 0x9f62b38: hash = [resource+0x70] * 0x9e3779b97f4a7c15;
  bucket = hash >> (64 - log2(cap)); индекс слова bitmap = (bucket>>6) & MASK
  (0x9f63148 / 0x9f6314c); индекс элемента = (bit+bucket) & (cap-1).
- remove хеш-таблицы 0x9f518ac: элемент по индексу с шагом 8 байт из +0x10
  (аллоцирован 4 байта на слот) при единственной проверке index < capacity
  => индекс в [cap/2, cap) пишет 8 байт за конец (0x9f518f0 str xzr).
- grow группы 0x9f64910: удваивает capacity (цикл проходит дважды).
- grow хеш-таблицы 0x9f7699c: capacity = w1 (явная) либо 2*старая;
  единственный вызов с w1 != 0 считает w1 = count + (count>>2) = count*5/4
  (0x9f7588c).
- Маска декрементируется при удалении: 0x9f51914/18/1c.

## ГЛАВНЫЙ ВЫВОД
Для WILD OOB (bucket = полный 64-битный хеш) нужно log2(cap) == 0,
то есть capacity == 1: mask = 0xffffffff И log2 = 0 одновременно.
При capacity 2..64 bucket < 64 => индекс слова bitmap = 0 => запись
внутри массива; маска, сломанная декрементом, при cap=64 тоже ничего
не даёт (bucket>>6 == 0). При cap >= 128 bucket < cap и индекс в границах.
=> НУЖЕН capacity == 1. Источники capacity: тип ресурса (>=64) и grow
с явной capacity (count*5/4). Тип закрыт гейтом, cmd=64 закрыт.
ОСТАЁТСЯ: путь, где grow хеш-таблицы срабатывает с маленьким счётчиком
(тогда w1 = count*5/4 = 1 при count = 1) => capacity = 1 => wild OOB.

## Инструменты
- Кнопка "OOB триггер (дубль + свип индекса)" -> Documents/group_oob.log
- "Охота за утечкой ядра" -> Documents/kern_leak.log
- "NECP цепочка (чтение)" -> Documents/necp_chain.log (нужен преф
  "NECP Data-Only Chain")
- "Матрица capacity" -> Documents/cap_matrix.log
- Логи: /home/abzal/jailbreak 26/Test-main/VULNS.txt (история), этот файл.
