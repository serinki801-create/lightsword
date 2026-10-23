#!/usr/bin/env python3
"""kext_align_diff.py -- layout-aligned function diff for stripped Mach-O kexts.

Functions are taken from LC_FUNCTION_STARTS (the linker keeps them in source
order), hashed by their *normalized* mnemonic/operand stream (numbers and
branch targets replaced by '#', so address shifts do not create false
positives), and the two hash sequences are aligned with SequenceMatcher.
Insertions/deletions then map 1:1 onto real code changes.

Usage:
  python3 kext_align_diff.py <old.dis> <new.dis> [out.txt] [--full]

<old.dis>/<new.dis> come from:
  llvm-objdump -d --no-show-raw-insn <kext> > x.dis
"""
import re
import sys
from bisect import bisect_right
from difflib import SequenceMatcher

ADDR = re.compile(r'^\s*([0-9a-f]+):\s+(.*)$')
NUM = re.compile(r'(?<![a-z])(?:0x[0-9a-f]+|-?\d+)(?![a-z0-9])')
REG = re.compile(r'\b[wx]\d+\b')


def parse_dis(path):
    ins = []
    for line in open(path, 'r', errors='replace'):
        m = ADDR.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        text = m.group(2).strip()
        parts = text.split(None, 1)
        mn = parts[0]
        ops = parts[1] if len(parts) > 1 else ''
        ins.append((addr, mn, ops))
    return ins


def uleb(data, off, size):
    out, end = [], off + size
    while off < end:
        v = s = 0
        while True:
            if off >= end:
                return out
            c = data[off]
            off += 1
            v |= (c & 0x7F) << s
            if not c & 0x80:
                break
            s += 7
        out.append(v)
    return out


def function_starts(kext, dis):
    import struct
    d = open(kext, 'rb').read()
    n = struct.unpack_from('<I', d, 16)[0]
    off, segs, fst = 32, [], None
    for _ in range(n):
        cmd, cs = struct.unpack_from('<II', d, off)
        if cmd == 0x19:
            name = d[off + 8:off + 24].rstrip(b'\0').decode('utf-8', 'replace')
            vm, vs, fo, fsz = struct.unpack_from('<4Q', d, off + 24)
            segs.append((name, vm, fo, fsz))
        elif cmd == 0x26:
            fst = struct.unpack_from('<II', d, off + 8)
        off += cs
    text = next(s for s in segs if s[0] == '__TEXT')
    kfo = min(s[2] for s in segs)
    starts = []
    if fst and fst[1]:
        base = text[1]
        cur, out = 0, []
        for delta in uleb(d, fst[0] - kfo, fst[1]):
            if delta == 0:
                break
            cur += delta
            out.append(base + cur)
        starts = out
    if not starts:
        starts = [dis[0][0]]
    return starts


def norm(mn, ops):
    ops = NUM.sub('#', ops)
    return mn + ' ' + ops


def build(path_dis, path_kext):
    dis = parse_dis(path_dis)
    starts = function_starts(path_kext, dis)
    addrs = [s for s, _, _ in dis]
    funcs = []
    for i, st in enumerate(starts):
        lo = bisect_right(addrs, st) - 1
        if lo < 0 or addrs[lo] != st:
            continue
        hi = bisect_right(addrs, starts[i + 1] - 1) if i + 1 < len(starts) else len(dis)
        if hi <= lo:
            continue
        body = dis[lo:hi]
        mn = tuple(m for _, m, _ in body)
        nm = tuple(norm(m, o) for _, m, o in body)
        funcs.append({'addr': st, 'size': len(body), 'hash': hash(mn),
                      'norm': hash(nm), 'body': body})
    return funcs


def main():
    old_dis, old_kext, new_dis, new_kext = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    out_path = sys.argv[5] if len(sys.argv) > 5 and not sys.argv[5].startswith('--') else None
    full = '--full' in sys.argv

    old = build(old_dis, old_kext)
    new = build(new_dis, new_kext)

    a = [f['hash'] for f in old]
    b = [f['hash'] for f in new]
    sm = SequenceMatcher(None, a, b, autojunk=False)
    ops = sm.get_opcodes()

    out = []
    out.append('old funcs %d   new funcs %d' % (len(old), len(new)))
    counts = {'equal': 0, 'replace': 0, 'delete': 0, 'insert': 0}
    for tag, i1, i2, j1, j2 in ops:
        counts[tag] += 1
        if tag == 'equal':
            for k in range(i2 - i1):
                fo, fn = old[i1 + k], new[j1 + k]
                if fo['norm'] != fn['norm']:
                    out.append('   ~ operands old 0x%x(%d) new 0x%x(%d)' % (
                        fo['addr'], fo['size'], fn['addr'], fn['size']))
            continue
        out.append('\n== %s old[%d:%d] new[%d:%d]' % (tag, i1, i2, j1, j2))
        if tag in ('delete', 'insert'):
            src = old if tag == 'delete' else new
            lo, hi = (i1, i2) if tag == 'delete' else (j1, j2)
            for f in src[lo:hi]:
                out.append('   %s func 0x%x  %d insns' % (tag.upper(), f['addr'], f['size']))
            continue
        lo, hi = i1, i2
        for k in range(max(i2 - i1, j2 - j1)):
            fo = old[i1 + k] if i1 + k < i2 else None
            fn = new[j1 + k] if j1 + k < j2 else None
            dold = fn['size'] - fo['size'] if fo and fn else 0
            out.append('   pair old 0x%x(%d) -> new 0x%x(%d)  delta %+d insns' % (
                fo['addr'] if fo else 0, fo['size'] if fo else 0,
                fn['addr'] if fn else 0, fn['size'] if fn else 0, dold))
            if full and fo and fn:
                so = [(m, o) for _, m, o in fo['body']]
                sn = [(m, o) for _, m, o in fn['body']]
                sm2 = SequenceMatcher(None, [norm(m, o) for m, o in so],
                                      [norm(m, o) for m, o in sn], autojunk=False)
                for t2, x1, x2, y1, y2 in sm2.get_opcodes():
                    if t2 == 'equal':
                        continue
                    for m, o in so[x1:x2]:
                        out.append('      - %s %s' % (m, o))
                    for m, o in sn[y1:y2]:
                        out.append('      + %s %s' % (m, o))
    text = '\n'.join(out)
    if out_path:
        open(out_path, 'w').write(text + '\n')
        print('report -> %s (%d lines)' % (out_path, len(out)))
    else:
        print(text)


if __name__ == '__main__':
    main()
