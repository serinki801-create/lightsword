#!/usr/bin/env python3
"""carve_kc_kexts.py -- extract named kexts from a device kernelcache (MH_FILESET).

Usage:
  python3 carve_kc_kexts.py <kernelcache> <out_dir> [bundle_id ...]
  python3 carve_kc_kexts.py <kernelcache> <out_dir> --list

Every LC_FILESET_ENTRY is a self-contained Mach-O image inside the fileset.
The carve is a straight copy of the inner image; segment filesizes are clamped
to the bytes actually present so llvm-objdump is happy.
"""
import os
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_FILESET_ENTRY = 0x80000035


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def u64(b, o):
    return struct.unpack_from('<Q', b, o)[0]


def load_commands(d, off, ncmds):
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', d, off)
        if cmdsize < 8 or off + cmdsize > len(d):
            break
        yield off, cmd, cmdsize
        off += cmdsize


def main():
    src = sys.argv[1]
    outdir = sys.argv[2]
    want = sys.argv[3:]

    d = open(src, 'rb').read()
    ncmds = u32(d, 16)

    entries = []
    for off, cmd, cmdsize in load_commands(d, 32, ncmds):
        if cmd != LC_FILESET_ENTRY:
            continue
        vmaddr = u64(d, off + 8)
        fileoff = u64(d, off + 16)
        eid_off = u32(d, off + 24)
        end = d.index(b'\0', off + eid_off)
        eid = d[off + eid_off:end].decode('utf-8', 'replace')
        entries.append((eid, vmaddr, fileoff))

    if '--list' in want:
        for eid, vm, fo in entries:
            print('%-60s vm=0x%x off=0x%x' % (eid, vm, fo))
        return

    os.makedirs(outdir, exist_ok=True)
    for eid, vm, fo in entries:
        if want and not any(w in eid for w in want):
            continue
        if u32(d, fo) != MH_MAGIC_64:
            continue
        n2 = u32(d, fo + 16)
        inner_end = fo + 32 + u32(d, fo + 20)
        segs = []
        symtabs = []
        for o2, cmd2, cs2 in load_commands(d, fo + 32, n2):
            if cmd2 == LC_SEGMENT_64:
                name = d[o2 + 8:o2 + 24].rstrip(b'\0').decode('utf-8', 'replace')
                vmaddr, vmsize, fsoff, fssize = struct.unpack_from('<4Q', d, o2 + 24)
                segs.append((name, o2, vmaddr, vmsize, fsoff, fssize))
                inner_end = max(inner_end, fo + fsoff + fssize)
            elif cmd2 == LC_SYMTAB:
                symtabs.append(o2)

        avail = len(d) - fo
        final = []
        for name, o2, vmaddr, vmsize, fsoff, fssize in segs:
            clamped = min(fssize, max(0, avail - fsoff))
            final.append((name, o2, vmaddr, vmsize, fsoff, clamped))
            inner_end = max(inner_end, fo + fsoff + clamped)

        out = bytearray(d[fo:inner_end])
        # Segment/section file offsets inside a fileset are CONTAINER-relative.
        # The carved image starts at container offset fo, so every offset must
        # lose fo, otherwise objdump sees a 60 MB gap and prints nothing.
        for name, o2, vmaddr, vmsize, fsoff, fssize in final:
            lo = o2 - fo
            struct.pack_into('<Q', out, lo + 40, fsoff - fo)   # segment fileoff
            struct.pack_into('<Q', out, lo + 48, fssize)      # segment filesize
            nsects = struct.unpack_from('<I', out, lo + 64)[0]
            for si in range(nsects):
                sec = lo + 72 + si * 80
                soff = struct.unpack_from('<I', out, sec + 48)[0]
                if soff:
                    struct.pack_into('<I', out, sec + 48, soff - fo)
        for o2 in symtabs:
            lo = o2 - fo
            for k in (8, 12, 16, 20):
                struct.pack_into('<I', out, lo + k, 0)
        for o2, cmd2, cs2 in load_commands(d, fo + 32, n2):
            if cmd2 == 0x26:      # LC_FUNCTION_STARTS
                lo = o2 - fo
                doff = struct.unpack_from('<I', out, lo + 8)[0]
                if doff:
                    struct.pack_into('<I', out, lo + 8, doff - fo)

        path = os.path.join(outdir, eid)
        open(path, 'wb').write(bytes(out))
        print('carved %-55s -> %s (%d bytes)' % (eid, path, len(out)))


if __name__ == '__main__':
    main()
