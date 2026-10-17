#!/usr/bin/env bash
# build_inline.sh: inline exploit.js into exploit.html at package time.
# Why: the 15:16 and 15:32 device runs loaded the HTML fine, but the external
# <script src="exploit.js"> read-failed from LiveContainer's copy of the app
# under Documents/Applications/<uuid>/... (fetch=FAIL on the same directory
# that served the HTML). One file to load removes the whole failure class.
# Substitutes the <!--WT3_INLINE_JS--> marker in exploit.html with the full
# contents of exploit.js inside a <script> tag.
set -euo pipefail
PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_JS="$PROJ/Resources/webkit/exploit.js"
SRC_HTML="$PROJ/Resources/webkit/exploit.html"
OUT="$PROJ/Resources/webkit/exploit.inline.html"
[[ -f "$SRC_JS" && -f "$SRC_HTML" ]] || { echo "[INLINE] ERROR: sources missing" >&2; exit 1; }
node --check "$SRC_JS"
if grep -q '</script>' "$SRC_JS"; then
    echo "[INLINE] ERROR: exploit.js contains </script> — would close the inline tag early" >&2
    exit 1
fi
if ! grep -q '<!--WT3_INLINE_JS' "$SRC_HTML"; then
    echo "[INLINE] ERROR: marker <!--WT3_INLINE_JS--> missing from exploit.html" >&2
    exit 1
fi
# python for a byte-exact substitution (no sed escaping hell on 120 KB of JS)
python3 - "$SRC_JS" "$SRC_HTML" "$OUT" <<'PYEOF'
import sys
js = open(sys.argv[1], encoding="utf-8").read()
html = open(sys.argv[2], encoding="utf-8").read()
marker = "<!--WT3_INLINE_JS"
i = html.index(marker)
end = html.index("-->", i) + 3
html = html[:i] + "<script>\n" + js + "\n</script>" + html[end:]
open(sys.argv[3], "w", encoding="utf-8").write(html)
print("[INLINE] %d B js + %d B html -> %d B" % (len(js), len(html), len(html)))
PYEOF
grep -q 'window.nkSelfTest' "$OUT" || { echo "[INLINE] ERROR: sanity — no nkSelfTest in output" >&2; exit 1; }
echo "[INLINE] OK: $OUT"
