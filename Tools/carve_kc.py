#!/usr/bin/env python3
# carve_kc.py -- extract a standalone Mach-O from a device kernelcache (MH_FILESET).
#
# Input : kernelcache.release.iPhone14,5 (MH_FILESET, arm64e, 249 LC_FILESET_ENTRY)
# Output: <out>.macho   standalone kernel image (com.apple.kernel entry)
#         <out>.map.json segment vm/file ranges for disassembly mapping
#
# The carve:
#   1. parses the fileset, locates the "com.apple.kernel" entry -> inner image
#      at its fileoff (this device: 0x8000, vmaddr 0xfffffff007004000);
#   2. writes the inner image out as a self-contained Mach-O (file offsets are
#      already image-relative, so extraction is a straight copy);
#   3. clamps every LC_SEGMENT_64 vmsize to its filesize (objdump-friendly);
#   4. neutralizes LC_SYMTAB (nsyms=0, symoff/stroff/strsize=0) so no symbol
#      table needs to be resolved;
#   5. dumps the vm->file map so disasm windows map exactly:
#         file_off = vmaddr - image_base + image_base_fileoff_in_container
import json
import struct
import sys

REBASE = '--rebase' in sys.argv
if REBASE:
    sys.argv.remove('--rebase')

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_FILESET_ENTRY = 0x80000035
LC_REQ_DYLD = 0x80000000


def u32(b, o):
    return struct.unpack('<I', b[o:o + 4])[0]


def u64(b, o):
    return struct.unpack('<Q', b[o:o + 8])[0]


def cstr(b, o):
    end = b.index(b'\0', o)
    return b[o:end].decode('utf-8', 'replace')


def parse_header(d, base_off, label):
    magic = u32(d, base_off)
    if magic != MH_MAGIC_64:
        raise SystemExit('%s: bad magic 0x%x at 0x%x' % (label, magic, base_off))
    ncmds = u32(d, base_off + 16)
    sizeofcmds = u32(d, base_off + 20)
    return ncmds, sizeofcmds


def load_commands(d, off, ncmds):
    for _ in range(ncmds):
        if off + 8 > len(d):
            break
        cmd = u32(d, off)
        cmdsize = u32(d, off + 4)
        if cmdsize < 8 or off + cmdsize > len(d):
            break
        yield off, cmd, cmdsize
        off += cmdsize


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else 'kernelcache.release.iPhone14,5'
    out = sys.argv[2] if len(sys.argv) > 2 else 'kernel.carve'

    d = bytearray(open(src, 'rb').read())

    ncmds, _ = parse_header(d, 0, 'fileset header')

    kernel = None
    for off, cmd, cmdsize in load_commands(d, 32, ncmds):
        if cmd != LC_FILESET_ENTRY:
            continue
        vmaddr = u64(d, off + 8)
        fileoff = u64(d, off + 16)
        eid_off = u32(d, off + 24)
        eid = cstr(d, off + eid_off)
        if eid == 'com.apple.kernel':
            kernel = (vmaddr, fileoff)
            break
    if not kernel:
        raise SystemExit('com.apple.kernel entry not found (not a fileset KC?)')

    kvm, kfo = kernel

    ncmds2, sizeofcmds2 = parse_header(d, kfo, 'inner kernel header')

    inner_end = kfo + 32 + sizeofcmds2
    symtab_cmds = []
    segs = []

    for off, cmd, cmdsize in load_commands(d, kfo + 32, ncmds2):
        if cmd == LC_SEGMENT_64:
            segname = d[off + 8:off + 24].rstrip(b'\0').decode('utf-8', 'replace')
            vmaddr = u64(d, off + 24)
            vmsize = u64(d, off + 32)
            fileoff = u64(d, off + 40)
            filesize = u64(d, off + 48)
            segs.append((segname, off, vmaddr, vmsize, fileoff, filesize))
            inner_end = max(inner_end, kfo + fileoff + filesize)
        elif cmd == LC_SYMTAB:
            symtab_cmds.append(off)

    # The container's own __LINKEDIT claims past EOF (0x3d860d1 > file end):
    # clamp every segment's filesize to the bytes actually present. vmsize
    # stays original -- sections must remain inside vmaddr+vmsize for objdump.
    # The clamped map.json reflects the real dumpable ranges.
    avail_total = len(d) - kfo
    segs_final = []
    for segname, off, vmaddr, vmsize, fileoff, filesize in segs:
        avail = avail_total - fileoff
        clamped = min(filesize, avail)
        inner_end = max(inner_end, kfo + fileoff + clamped)
        segs_final.append((segname, off, vmaddr, vmsize, fileoff, clamped))

    out_bytes = bytearray(d[kfo:inner_end])

    # patch the clamped filesizes into the carved image's load commands
    for segname, off, vmaddr, vmsize, fileoff, filesize in segs_final:
        lo = off - kfo
        struct.pack_into('<Q', out_bytes, lo + 48, filesize)  # filesize = clamped

    # optionally rebase the image to 0 so VMA == file offset: disasm windows
    # can then be given directly as file ranges (e.g. 0x1473000-0x1476000).
    # The carve starts at container offset kfo, so segment fileoff and section
    # offset fields must lose kfo for the image to be self-consistent.
    if REBASE:
        for segname, off, vmaddr, vmsize, fileoff, filesize in segs_final:
            lo = off - kfo
            nsects = struct.unpack_from('<I', out_bytes, lo + 64)[0]
            struct.pack_into('<Q', out_bytes, lo + 24, vmaddr - kvm)   # segment vmaddr
            struct.pack_into('<Q', out_bytes, lo + 40, fileoff - kfo)  # segment fileoff
            for s in range(nsects):
                sec = lo + 72 + s * 80
                addr = struct.unpack_from('<Q', out_bytes, sec + 32)[0]  # sectname16+segname16
                if addr >= kvm:
                    struct.pack_into('<Q', out_bytes, sec + 32, addr - kvm)
                soff = struct.unpack_from('<I', out_bytes, sec + 48)[0]
                if soff:
                    struct.pack_into('<I', out_bytes, sec + 48, soff - kfo)

    # neutralize symtab
    for off in symtab_cmds:
        lo = off - kfo
        for k in (8, 12, 16, 20):  # cmd,cmdsize,symoff,nsyms,stroff,strsize
            struct.pack_into('<I', out_bytes, lo + k, 0)

    open(out + '.macho', 'wb').write(bytes(out_bytes))

    seg_map = {
        'image_base': hex(kvm),
        'container_fileoff': hex(kfo),
        'vm_to_file': 'IDENTITY with --rebase: carve file offset == VMA',
        'note': 'carve starts at container offset %s; with --rebase VMA == carve file offset' % hex(kfo),
        'segments': [
            {'name': s[0], 'vmaddr': hex(s[2]), 'vmsize': hex(s[3]),
             'fileoff': hex(s[4]), 'filesize_dumpable': hex(s[5])}
            for s in segs_final
        ],
    }
    open(out + '.map.json', 'w').write(json.dumps(seg_map, indent=2))

    print('carved %s -> %s.macho (%d bytes)' % (src, out, len(out_bytes)))
    for s in segs:
        print('  %-16s vm=%s size=%s file=%s' % (s[0], hex(s[2]), hex(s[5]), hex(s[4])))


if __name__ == '__main__':
    main()
