#!/usr/bin/env python3
"""kext_fix_hunt.py -- find functions that gained a bounds check / validation
between two builds of a stripped kext, without symbols and without relying on
layout alignment.

For every function of the old image the best match in the new image is found by
mnemonic-sequence similarity (candidate pruning by size and first mnemonic).
Matched pairs are then diffed on normalized operands; pairs whose only change is
a small set of added compare/branch instructions are security-fix candidates.

Usage:
  kext_fix_hunt.py <old.dis> <old.kext> <new.dis> <new.kext> [out.txt] [--min-ratio 0.85]
"""
import importlib.util
import re
import sys
from difflib import SequenceMatcher

spec = importlib.util.spec_from_file_location(
    'kad', '/home/abzal/jailbreak 26/Test-main/Tools/regress/kext_align_diff.py')
kad = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kad)

CHECK = re.compile(
    r'^(cmp|cmn|ccmp|tst|cbz|cbnz|tbz|tbnz|b\.(hi|ls|hs|lo|cs|cc|ge|lt|gt|le)|subs|adds)\b')


def fn_mn(f):
    return tuple(m for _, m, _ in f['body'])


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    old_dis, old_kext, new_dis, new_kext = args[:4]
    out_path = args[4] if len(args) > 4 else None
    min_ratio = 0.85
    for a in sys.argv:
        if a.startswith('--min-ratio'):
            min_ratio = float(a.split('=', 1)[1]) if '=' in a else min_ratio

    a = kad.build(old_dis, old_kext)
    b = kad.build(new_dis, new_kext)

    b_by_first = {}
    for f in b:
        if not f['body']:
            continue
        b_by_first.setdefault(f['body'][0][1], []).append(f)

    out = []
    hits = 0
    for fo in a:
        if not fo['body']:
            continue
        first = fo['body'][0][1]
        cands = b_by_first.get(first, [])
        if not cands:
            cands = b
        best, best_r = None, 0.0
        for fn in cands:
            if not fn['body']:
                continue
            if not (0.6 * fo['size'] <= fn['size'] <= 1.6 * fo['size'] + 8):
                continue
            r = SequenceMatcher(None, fn_mn(fo), fn_mn(fn), autojunk=False).ratio()
            if r > best_r:
                best, best_r = fn, r
        if best is None or best_r < min_ratio:
            continue
        mo = [kad.norm(m, o) for _, m, o in fo['body']]
        mn = [kad.norm(m, o) for _, m, o in best['body']]
        if mo == mn:
            continue
        sm = SequenceMatcher(None, mo, mn, autojunk=False)
        added, removed = [], []
        for t, x1, x2, y1, y2 in sm.get_opcodes():
            if t in ('insert', 'replace'):
                added += [best['body'][i][1] + ' ' + best['body'][i][2]
                          for i in range(y1, y2)]
            if t in ('delete', 'replace'):
                removed += [fo['body'][i][1] + ' ' + fo['body'][i][2]
                            for i in range(x1, x2)]
        chk = [x for x in added if CHECK.match(x)]
        if not chk:
            continue
        if len(added) > 24 or len(removed) > 24:
            continue
        hits += 1
        out.append('== old 0x%x(%d) -> new 0x%x(%d) ratio %.2f  +%d/-%d' % (
            fo['addr'], fo['size'], best['addr'], best['size'],
            best_r, len(added), len(removed)))
        for x in added:
            out.append('   + %s' % x)
        for x in removed:
            out.append('   - %s' % x)

    text = '\n'.join(out)
    if out_path:
        open(out_path, 'w').write(text + '\n')
        print('candidates %d -> %s' % (hits, out_path))
    else:
        print(text)


if __name__ == '__main__':
    main()
