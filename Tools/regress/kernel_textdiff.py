#!/usr/bin/env python3
"""kernel_textdiff.py -- fast function-level diff of two kernels via llvm-objdump text.

WHY TEXT, NOT CAPSTONE
-----------------------
capstone-in-python over the 8.7 MB __TEXT_EXEC costs minutes per build.
llvm-objdump (theos toolchain) does the same carve in ~28 s, and the diff is
pure text work afterwards.

WHY MNEMONIC-ONLY SIGNATURES
-----------------------------
A fix shows up as added/removed/reordered INSTRUCTIONS. Operand values
(adrp pages, struct offsets, branch targets) shift with global layout and
would mark all 19 000 functions as changed. So:
  signature  = sha1(mnemonic stream)          <- for matching
  raw stream = "mnemonic operands"            <- for the report only

PERFORMANCE
  * one streaming pass per .dis file, no big dicts
  * sig sets built once (the previous version rebuilt a set per function:
    19k x 19k set operations = the 5-minute stall)
  * pairing only by head-3 mnemonic bucket, difflib on those few
  * parsed functions are cached in a .pickle next to the .dis file

USAGE
  python3 kernel_textdiff.py <old.macho> <old.dis> <new.macho> <new.dis> [out.txt]
"""
import struct
import sys
import hashlib
import pickle
import difflib


def uleb(d, off, size):
    out = []
    addr = 0
    end = off + size
    while off < end:
        val = 0
        sh = 0
        while True:
            b = d[off]
            off += 1
            val |= (b & 0x7F) << sh
            if not (b & 0x80):
                break
            sh += 7
        if val == 0:
            break
        addr += val
        out.append(addr)
    return out


def function_starts(macho):
    d = open(macho, 'rb').read()
    ncmds = struct.unpack_from('<I', d, 16)[0]
    off = 32
    text_base = None
    segs = []
    fs = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', d, off)
        if cmd == 0x19:
            name = d[off + 8:off + 24].rstrip(b'\0').decode()
            vm, _vs, fo, _fsz = struct.unpack_from('<4Q', d, off + 24)
            segs.append(fo)
            if name == '__TEXT':
                text_base = vm
        elif cmd == 0x26:
            fs = struct.unpack_from('<II', d, off + 8)
        off += cmdsize
    kfo = min(segs)
    do, ds = fs
    return [text_base + x for x in uleb(d, do - kfo, ds)]


def parse_dis(path, starts):
    """single streaming pass -> list of (addr, mnemonics[], raw[])"""
    cache = path + '.funcs.pickle'
    try:
        with open(cache, 'rb') as fh:
            return pickle.load(fh)
    except Exception:
        pass

    starts = sorted(starts)
    idx = 0
    cur_addr = starts[0] if starts else None
    cur_ops = []
    cur_raw = []
    out = []

    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            # "fffffff007fb0000:\tadd\tx8, x21, #116"
            c = line.find(':')
            if c < 0:
                continue
            head = line[:c]
            if len(head) < 8:
                continue
            try:
                addr = int(head, 16)
            except ValueError:
                continue
            rest = line[c + 1:]
            parts = rest.split('\t')
            if len(parts) < 2:
                continue
            mn = parts[1].strip()
            ops = parts[2].strip() if len(parts) > 2 else ''
            if not mn or mn.startswith('.'):
                continue
            # advance to the function that contains this address
            while idx < len(starts) and starts[idx] < addr:
                if cur_addr is not None:
                    out.append((cur_addr, cur_ops, cur_raw))
                    cur_ops = []
                    cur_raw = []
                idx += 1
                cur_addr = starts[idx] if idx < len(starts) else None
            if cur_addr is None:
                break
            cur_ops.append(mn)
            cur_raw.append((mn + ' ' + ops).strip())
    if cur_addr is not None:
        out.append((cur_addr, cur_ops, cur_raw))

    res = [f for f in out if len(f[1]) >= 3]
    try:
        with open(cache, 'wb') as fh:
            pickle.dump(res, fh, protocol=4)
    except Exception:
        pass
    return res


def sig_of(ops):
    return hashlib.sha1('\n'.join(ops).encode()).hexdigest()


def classify(a, b):
    def checks(ops):
        return sum(1 for o in ops if o.startswith(('cmp', 'cbz', 'cbnz', 'tbn')))
    def branches(ops):
        return sum(1 for o in ops if o == 'b' or o.startswith('b.') or o == 'bl')
    k = []
    if checks(b) > checks(a):
        k.append('NEW-CHECK')
    if branches(b) > branches(a):
        k.append('NEW-BRANCH')
    if len(b) > len(a) * 1.1:
        k.append('GREW')
    if len(b) < len(a) * 0.9:
        k.append('SHRUNK')
    return k or ['MODIFIED']


def main():
    if len(sys.argv) < 5:
        sys.exit(__doc__)
    old_macho, old_dis, new_macho, new_dis = sys.argv[1:5]
    out_path = sys.argv[5] if len(sys.argv) > 5 else None

    print('parse old...', file=sys.stderr)
    of = parse_dis(old_dis, function_starts(old_macho))
    print('parse new...', file=sys.stderr)
    nf = parse_dis(new_dis, function_starts(new_macho))
    print('old funcs %d, new funcs %d' % (len(of), len(nf)), file=sys.stderr)

    osig = set()
    for _a, ops, _r in of:
        osig.add(sig_of(ops))
    nsig = set()
    for _a, ops, _r in nf:
        nsig.add(sig_of(ops))

    new_by_head = {}
    for a, ops, raw in nf:
        new_by_head.setdefault(tuple(ops[:3]), []).append((a, ops, raw))

    changed = []
    added = []
    for a, ops, raw in of:
        if sig_of(ops) not in nsig:
            changed.append((a, ops, raw))
    for a, ops, raw in nf:
        if sig_of(ops) not in osig:
            added.append((a, ops, raw))
    print('changed %d, added %d' % (len(changed), len(added)), file=sys.stderr)

    used = set()
    report = []
    for a, ops, raw in changed:
        best = None
        best_r = 0.0
        for g in new_by_head.get(tuple(ops[:3]), []):
            if g[0] in used:
                continue
            r = difflib.SequenceMatcher(None, ops, g[1], autojunk=False).quick_ratio()
            if r < 0.45:
                continue
            r = difflib.SequenceMatcher(None, ops, g[1], autojunk=False).ratio()
            if r > best_r:
                best_r = r
                best = g
        if best is None:
            report.append('=' * 76)
            report.append('OLD 0x%x ops=%d  ->  NO COUNTERPART (deleted)' % (a, len(ops)))
            report.append('  head: %s' % ' ; '.join(raw[:8])[:200])
            continue
        used.add(best[0])
        kinds = classify(ops, best[1])
        report.append('=' * 76)
        report.append('OLD 0x%x ops=%d  ->  NEW 0x%x ops=%d  ratio=%.2f  %s'
                      % (a, len(ops), best[0], len(best[1]), best_r, ','.join(kinds)))
        sm = difflib.SequenceMatcher(None, ops, best[1], autojunk=False)
        shown = 0
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == 'equal':
                continue
            report.append('  [%s]' % tag)
            report.append('    old: %s' % ' ; '.join(raw[i1:i2])[:240])
            report.append('    new: %s' % ' ; '.join(best[2][j1:j2])[:240])
            shown += 1
            if shown >= 6:
                break

    report.append('=' * 76)
    report.append('ADDED IN NEW: %d' % len(added))
    for a, ops, raw in added:
        report.append('  NEW 0x%x ops=%d : %s' % (a, len(ops), ' ; '.join(raw[:12])[:220]))

    text = '\n'.join(report)
    if out_path:
        open(out_path, 'w').write(text)
        print('report -> %s (%d lines)' % (out_path, len(report)), file=sys.stderr)
    else:
        print(text)


if __name__ == '__main__':
    main()
