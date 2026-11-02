#!/usr/bin/env bash
# build.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating test PNGs ==="
python3 tools/gen_pngs.py

if ! command -v xcodegen &>/dev/null; then
    echo "ERROR: xcodegen not found. Install with: brew install xcodegen"
    exit 1
fi

echo "=== Running XcodeGen ==="
xcodegen generate

echo "=== Building (unsigned) ==="
xcodebuild -project Parasite.xcodeproj \
    -scheme Parasite \
    -sdk iphoneos \
    -configuration Release \
    CODE_SIGNING_ALLOWED=NO \
    CONFIGURATION_BUILD_DIR="$SCRIPT_DIR/build" \
    -quiet

echo "=== Packaging IPA ==="
rm -rf Payload Parasite.ipa
mkdir -p Payload
cp -R build/Parasite.app Payload/
zip -r -q Parasite.ipa Payload
rm -rf Payload

echo "IPA ready: $SCRIPT_DIR/Parasite.ipa"

# For jailbroken installs:
# ldid -S Parasite.ipa
