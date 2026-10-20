"""Regression diff between two kernelcaches: what did Apple REMOVE in the newer build?

A function that got shorter (or vanished) between two releases usually means a
check was dropped. That is the cheapest possible 0-day: nobody patches it
because nobody filed it.

Usage: python3 regress.py <old_kernelcache> <new_kernelcache> [bundle_id]
"""
import sys, os, struct, hashlib, re
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from macho import Image

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    sys.exit("need capstone")


def uleb(d, off, size):
    out = []
    addr = 0
    end = off + size
    while off < end:
        val = 0
        sh = 0
        while True:
            b = d[off]; off += 1
            val |= (b & 0x7f) << sh
            if not (b & 0x80):
                break
            sh += 7
        if val == 0:
            break
        addr += val
        out.append(addr)
    return out


def func_starts(path):
    d = open(path, 'rb').read()
    ncmds = struct.unpack_from('<I', d, 16)[0]
    off = 32
    fs = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', d, off)
        if cmd == 0x26:
            do, ds = struct.unpack_from('<II', d, off + 8)
            fs = uleb(d, do, ds)
        off += cmdsize
    return fs


MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
MD.skipdata = True


def inventory(path):
    """-> {sig_hash: (size, count)} and {sig_hash: [sizes]}"""
    I = Image(path)
    ins = I.disasm()
    fs = func_starts(path)
    tva, code = I.code()
    if not fs or not code:
        return {}
    bounds = [I.text_base + f for f in fs]
    byaddr = {x.address: i for i, x in enumerate(ins)}
    inv = defaultdict(list)
    for k in range(len(bounds) - 1):
        st, en = bounds[k], bounds[k+1]
        i = byaddr.get(st)
        if i is None:
            continue
        seq = []
        for m in range(i, len(ins)):
            if ins[m].address >= en:
                break
            seq.append(ins[m].mnemonic)
        if len(seq) < 4:
            continue
        h = hashlib.sha1(' '.join(seq).encode()).hexdigest()[:16]
        inv[h].append(en - st)
    return inv


def main():
    old_kc, new_kc = sys.argv[1], sys.argv[2]
    want = sys.argv[3] if len(sys.argv) > 3 else None
    for tag, kc in (('OLD', old_kc), ('NEW', new_kc)):
        d = os.path.dirname(kc)
        print(f'{tag}: {kc}', file=sys.stderr)
    # compare the kernel itself first (com.apple.kernel) and then every kext
    import subprocess
    import glob
    def kext_dir(kc):
        d = os.path.dirname(os.path.abspath(kc))
        subs = [x for x in glob.glob(d + '/*__*') if os.path.isdir(x)]
        return subs[0] if subs else d
    old_dir = kext_dir(old_kc)
    new_dir = kext_dir(new_kc)
    print('OLD dir', old_dir, 'NEW dir', new_dir, file=sys.stderr)
    for root, _dirs, files in os.walk(new_dir):
        for f in files:
            np = os.path.join(root, f)
            rel = os.path.relpath(np, new_dir)
            parts = rel.split(os.sep)
            if len(parts) > 1 and '__' in parts[0]:
                parts = parts[1:]
            rel = os.sep.join(parts)
            op = os.path.join(old_dir, rel)
            if not os.path.exists(op):
                continue
            if want and want not in rel:
                continue
            try:
                a = inventory(op)
                b = inventory(np)
            except Exception as e:
                continue
            if not a or not b:
                continue
            # functions present in OLD but not NEW (same code) -> deleted
            gone = [h for h in a if h not in b]
            # functions whose size shrank -> use multiset of sigs
            sa = sorted(sum(a.values(), []))
            sb = sorted(sum(b.values(), []))
            if len(sa) != len(sb) or abs(len(sa) - len(sb)) > 3:
                print(f'{rel}: funcs {len(sa)} -> {len(sb)}  (delta {len(sb)-len(sa):+d})  deleted_sigs={len(gone)}')
            elif gone:
                print(f'{rel}: same count, {len(gone)} code paths deleted')


if __name__ == '__main__':
    main()
