#!/usr/bin/env python3
"""
Kernelcache recon for natsuk1.
Распаковывает IM4P/LZFSE (bvx2), парсит Mach-O arm64e,
дизассемблирует окна вокруг адресов из паники и пишет recon.txt.
"""
import struct, sys, os, subprocess, shutil, pathlib

ROOT = pathlib.Path('.')
MACHO_MAGIC = b'\xcf\xfa\xed\xfe'

# Pre-slide адреса из паники (slide 0x445fc000 уже вычтен)
TARGETS = {
    'AUTH_SITE_pc':       0xfffffff00846fe6c,
    'chain_lr_1':         0xfffffff00849061c,
    'chain_lr_2':         0xfffffff008491b64,
    'chain_lr_3':         0xfffffff008491e64,
    'kevent_scan_lr':     0xfffffff008618984,
}

WINDOW = 0x80  # байт в каждую сторону от цели


def find_source():
    for name in ('kc.bin', 'kc.im4p', 'kc.raw'):
        p = ROOT / name
        if p.exists():
            return p
    cands = sorted(ROOT.glob('KernelCache*')) + sorted(ROOT.glob('*.im4p'))
    return cands[0] if cands else None


def unwrap_im4p(raw):
    """Снимает IM4P/IMG4 обёртку, возвращает payload (comp/lzfse/macho)."""
    if raw[:4] in (MACHO_MAGIC, b'comp', b'bvx2', b'bvxn', b'bvx1', b'bvx-'):
        return raw
    for magic in (b'comp', b'bvx2', b'bvxn', b'bvx1', b'bvx-', MACHO_MAGIC):
        i = raw.find(magic, 0x10)
        if i != -1:
            return raw[i:]
    return raw


def decompress(payload):
    """payload начинается с comp/bvx*/macho. Возвращает голый Mach-O."""
    if payload[:4] == MACHO_MAGIC:
        return payload

    lzfse_bin = shutil.which('lzfse')
    if lzfse_bin is None:
        for p in (os.path.expanduser('~/lzfse'), '/usr/local/bin/lzfse'):
            if os.path.isfile(p):
                lzfse_bin = p
                break
    if lzfse_bin is None:
        sys.exit('ERROR: lzfse CLI не найден. Собери apple/lzfse.')

    comp_path = ROOT / '_kc_comp.bin'
    out_path = ROOT / '_kc_decomp.bin'
    comp_path.write_bytes(payload)

    r = subprocess.run([lzfse_bin, '-decode', '-i', str(comp_path), '-o', str(out_path)],
                       capture_output=True)
    if r.returncode != 0 or not out_path.exists():
        sys.exit('ERROR: lzfse decode failed: %s' % r.stderr.decode(errors='replace'))

    data = out_path.read_bytes()
    comp_path.unlink(missing_ok=True)
    out_path.unlink(missing_ok=True)

    if data[:4] != MACHO_MAGIC:
        sys.exit('ERROR: после декомпрессии не Mach-O, head=%r' % data[:8])
    return data


def parse_segments(data):
    """Возвращает список (segname, vmaddr, vmsize, fileoff, filesize)."""
    magic, _, _, _, ncmds, _, _ = struct.unpack_from('<IIIIIII', data, 0)
    assert magic == 0xFEEDFACF, hex(magic)
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            name = data[off + 8:off + 24].rstrip(b'\x00').decode('ascii', 'replace')
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize
    return segs


def va_to_fileoff(segs, va):
    for name, vm, vs, fo, fs in segs:
        span = max(vs, fs)
        if vm <= va < vm + span:
            return fo + (va - vm), name
    return None, None


def disasm_window(data, base_va, target_va, md):
    """Дизассемблирует [target-WINDOW, target+WINDOW], возвращает строки."""
    fo, seg = va_to_fileoff(segs_global, target_va)
    if fo is None:
        return ['[skip] %#x не замапплен ни в один сегмент' % target_va], seg

    start_va = target_va - WINDOW
    start_fo = fo - WINDOW
    if start_fo < 0:
        start_fo = 0
        start_va = target_va - (fo)
    chunk = data[start_fo:start_fo + 2 * WINDOW]

    lines = []
    feeds = []
    for ins in md.disasm(chunk, start_va):
        s = '%s %s' % (ins.mnemonic, ins.op_str)
        mark = ''
        if ins.address == target_va:
            mark = '   <== PC/AUTH SITE'
        mn = ins.mnemonic
        if mn.startswith(('aut', 'ldra')) or mn in ('blr', 'bra', 'br'):
            mark += '   <<<'
        if ins.address < target_va and ins.op_str.startswith('x16,'):
            feeds.append((ins.address, s))
        elif ins.address < target_va and mn in ('ldr', 'ldrsw', 'ldur') and ', x16,' in (' ' + ins.op_str):
            feeds.append((ins.address, s))
        lines.append('%#018x: %s%s' % (ins.address, s, mark))

    for a, s in feeds[-5:]:
        lines.append('[feed-x16] %#x: %s' % (a, s))
    return lines, seg


# ---- main ----
src = find_source()
if src is None:
    sys.exit('ERROR: нет kc.bin / kc.im4p в корне')
print('source:', src, 'size:', src.stat().st_size)

raw = src.read_bytes()
payload = unwrap_im4p(raw)
print('payload magic:', payload[:4])

data = decompress(payload)
print('mach-o ready, size:', len(data))

segs_global = parse_segments(data)
print('segments:', [(s[0], hex(s[1])) for s in segs_global])

try:
    import capstone as cs
    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN)
    HAVE_CS = True
except Exception as e:
    print('WARN: capstone недоступен (%s), будет hex-dump' % e)
    HAVE_CS = False

out = []
out.append('# natsuk1 kernelcache recon')
out.append('# source: %s (%d bytes)' % (src, len(data)))
out.append('# slide from panic: 0x445fc000  (адреса ниже уже pre-slide)')
out.append('# kernel text base pre-slide: 0xfffffff007004000')
out.append('')
out.append('## segments')
for name, vm, vs, fo, fs in segs_global:
    out.append('  %-16s vm=%#018x size=%#x fileoff=%#x' % (name, vm, vs, fo))
out.append('')

out.append('## targets (pre-slide адреса из паники)')
for label, va in TARGETS.items():
    out.append('  %-20s %#018x' % (label, va))
out.append('')

for label, target in TARGETS.items():
    out.append('### %s @ %#x' % (label, target))
    if HAVE_CS:
        lines, seg = disasm_window(data, 0, target, md)
        out.append('  segment: %s' % seg)
        for ln in lines:
            out.append('  ' + ln)
    else:
        fo, seg = va_to_fileoff(segs_global, target)
        out.append('  segment: %s  fileoff: %#x' % (seg, fo))
        if fo is not None:
            chunk = data[fo - WINDOW:fo + WINDOW]
            for i in range(0, len(chunk), 4):
                w = struct.unpack_from('<I', chunk, i)[0]
                out.append('  %#018x: %08x' % (target - WINDOW + i, w))
    out.append('')

text = '\n'.join(out)
pathlib.Path('recon.txt').write_text(text)
print('---- recon.txt written (%d bytes) ----' % len(text))
print(text)
