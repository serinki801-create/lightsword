#!/usr/bin/env bash
# carve_kernelcache.sh -- reproduce the standalone kernel Mach-O from the
# device kernelcache (fileset) for llvm-objdump work (S1).
#
# Usage: Tools/carve_kernelcache.sh [input_kernelcache] [out_prefix]
#   default input : Artifacts/carve/kernelcache.release.iPhone14,5
#   default out   : Artifacts/carve/kernel.carve
# Outputs:
#   <out>.macho    standalone com.apple.kernel image (segments clamped,
#                  symtab neutralized)
#   <out>.map.json segment vm/file ranges; file_off = vmaddr - image_base
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IN="${1:-$HERE/Artifacts/carve/kernelcache.release.iPhone14,5}"
OUT="${2:-$HERE/Artifacts/carve/kernel.carve}"
python3 "$HERE/Tools/carve_kc.py" "$IN" "$OUT"
