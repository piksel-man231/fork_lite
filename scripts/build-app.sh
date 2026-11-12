#!/bin/bash
# Собирает ForkLite.app в корне репозитория.
set -euo pipefail
cd "$(dirname "$0")/.."
swift build -c release
APP=ForkLite.app
rm -rf $APP; mkdir -p $APP/Contents/MacOS
cp .build/release/Fork $APP/Contents/MacOS/Fork
mkdir -p $APP/Contents/Resources/helper
cp helper/* $APP/Contents/Resources/helper/
cp scripts/install-helper.sh $APP/Contents/Resources/install-helper.sh
cp Assets/AppIcon.icns $APP/Contents/Resources/AppIcon.icns
cat > $APP/Contents/Info.plist <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>online.pikselman.forklite</string>
  <key>CFBundleName</key><string>Fork Lite</string>
  <key>CFBundleExecutable</key><string>Fork</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PL
codesign --force --sign - $APP >/dev/null 2>&1 || true
echo "Готово: $(pwd)/$APP"
