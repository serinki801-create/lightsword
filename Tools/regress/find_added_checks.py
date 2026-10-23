#!/usr/bin/env python3
"""find_added_checks.py -- locate security-style bounds checks added between two
kext builds (old vs new), without symbols.

Alignment: functions from LC_FUNCTION_STARTS, aligned by instruction count with
difflib (layout orders match across builds).  Within each aligned pair the
normalized instruction streams are compared and only *added* instructions are
reported, filtered to compare/branch shapes that a bounds check adds.

Usage:
  find_added_checks.py <old.dis> <old.kext> <new.dis> <new.kext> [out.txt]
"""
import importlib.util
import re
import sys
from difflib import SequenceMatcher

spec = importlib.util.spec_from_file_location(
    'kad', '/home/abzal/jailbreak 26/Test-main/Tools/regress/kext_align_diff.py')
kad = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kad)

CHECK = re.compile(r'^(cmp|cmn|ccmp|tst|cbz|cbnz|tbz|tbnz|b\.(hi|ls|hs|lo|cc|cs|ge|lt|gt|le)|cmn|subs?)\b')


def main():
    old_dis, old_kext, new_dis, new_kext = sys.argv[1:5]
    out_path = sys.argv[5] if len(sys.argv) > 5 else None
    a = kad.build(old_dis, old_kext)
    b = kad.build(new_dis, new_kext)
    sm = SequenceMatcher(None, [f['size'] for f in a], [f['size'] for f in b],
                         autojunk=False)
    lines = []
    hits = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            pairs = [(a[i1 + x], b[j1 + x]) for x in range(i2 - i1)]
        elif tag == 'replace':
            # greedy pair by size closeness inside the block
            left = list(range(i1, i2))
            right = list(range(j1, j2))
            pairs = []
            while left and right:
                best = None
                for li in left:
                    for rj in right:
                        d = abs(a[li]['size'] - b[rj]['size'])
                        if best is None or d < best[0]:
                            best = (d, li, rj)
                _, li, rj = best
                pairs.append((a[li], b[rj]))
                left.remove(li)
                right.remove(rj)
        else:
            continue
        for fo, fn in pairs:
            mo = [kad.norm(m, o) for _, m, o in fo['body']]
            mn = [kad.norm(m, o) for _, m, o in fn['body']]
            if mo == mn:
                continue
            sm2 = SequenceMatcher(None, mo, mn, autojunk=False)
            added, removed = [], []
            for t2, x1, x2, y1, y2 in sm2.get_opcodes():
                if t2 in ('insert', 'replace'):
                    added += [fn['body'][i][1] + ' ' + fn['body'][i][2]
                              for i in range(y1, y2)]
                if t2 in ('delete', 'replace'):
                    removed += [fo['body'][i][1] + ' ' + fo['body'][i][2]
                                for i in range(x1, x2)]
            chk = [x for x in added if CHECK.match(x)]
            body_new = ' | '.join(m for _, m, _ in fn['body'])
            has_copy = bool(re.search(r'\b(bl|blr)\b', body_new))
            if chk and fn['size'] >= fo['size']:
                hits += 1
                lines.append('== old 0x%x(%d) -> new 0x%x(%d)  +%d  checks=%s copy=%s' % (
                    fo['addr'], fo['size'], fn['addr'], fn['size'],
                    fn['size'] - fo['size'], '; '.join(chk), has_copy))
                for x in added:
                    lines.append('   + %s' % x)
                for x in removed:
                    lines.append('   - %s' % x)
    text = '\n'.join(lines)
    if out_path:
        open(out_path, 'w').write(text + '\n')
        print('candidates %d -> %s' % (hits, out_path))
    else:
        print(text)


if __name__ == '__main__':
    main()
