#!/usr/bin/env bash
#
# 编译 dylib —— 需要 Linux / macOS + Theos
# GitHub Actions 直接跑 .github/workflows/build.yml 更省事
#
# 用法:
#   export THEOS=~/theos
#   bash tools/build_dylib.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist"
mkdir -p "$OUT"

if [ -z "${THEOS:-}" ]; then
    if [ -d "$HOME/theos" ]; then
        export THEOS="$HOME/theos"
    else
        echo "!! 没设 THEOS，先装："
        echo "   git clone --recursive https://github.com/theos/theos.git ~/theos"
        echo "   export THEOS=~/theos"
        exit 1
    fi
fi

if ! command -v ldid >/dev/null 2>&1; then
    echo "!! 缺 ldid（brew install ldid / apt install ldid）"
fi

echo "== THEOS = $THEOS"
echo "== 开始编译 =="
cd "$ROOT/Tweak"
make clean >/dev/null 2>&1 || true
make FINALPACKAGE=1 DEBUG=0

DYLIB="$(find "$ROOT/Tweak/.theos" -name 'LegacyCostTweak.dylib' -type f | head -1)"
if [ -z "$DYLIB" ]; then
    echo "!! 编译完了但没找到 dylib，检查 Makefile"
    find "$ROOT/Tweak/.theos" -name '*.dylib' || true
    exit 1
fi

cp "$DYLIB" "$OUT/LegacyCostTweak.dylib"
echo "== dylib -> $OUT/LegacyCostTweak.dylib"
file "$OUT/LegacyCostTweak.dylib" || true

echo "== 打包 IPA =="
cd "$ROOT"
python3 tools/pack_ipa.py "$OUT/LegacyCostTweak.dylib" "$OUT/负之遗产_mod.ipa"

echo
echo "全部完成，产物在 $OUT/"
ls -la "$OUT"
