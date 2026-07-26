#!/bin/zsh
# Wrap the release gilbreth-app binary into Gilbreth.app and (optionally)
# sign it — MAC-1 start-gate item 4's bundle wrap.
#
# TCC persistence binds to bundle id + signing identity, so a stable grant
# requires a stable identity: pass --identity with the self-signed
# development certificate's common name (creation steps:
# the macOS dev-signing record). Unsigned and --adhoc bundles get
# grants keyed to the exact binary hash — every rebuild re-prompts, which
# poisons TCC-persistence testing (use only for throwaway checks).
#
# Usage:
#   scripts/make_macos_app_bundle.sh                    # unsigned wrap
#   scripts/make_macos_app_bundle.sh --adhoc            # ad-hoc signature
#   scripts/make_macos_app_bundle.sh --identity "Gilbreth Dev Signing"
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: macOS only" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUNDLE_ID="com.tylersystems.gilbreth"
APP_NAME="Gilbreth"
IDENTITY=""
ADHOC=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --identity)
      IDENTITY="${2:?--identity needs a certificate common name}"
      shift 2
      ;;
    --adhoc)
      ADHOC=1
      shift
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -n "$IDENTITY" && "$ADHOC" -eq 1 ]]; then
  echo "error: --identity and --adhoc are mutually exclusive" >&2
  exit 1
fi

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -1)"

# Honor CARGO_TARGET_DIR (relative values resolve against this shell's cwd,
# matching what the cargo invocation below will do).
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
[[ "$TARGET_DIR" != /* ]] && TARGET_DIR="$PWD/$TARGET_DIR"

echo "==> building gilbreth-app (release)"
cargo build --release -p gilbreth-app --manifest-path "$REPO_ROOT/Cargo.toml"

APP_DIR="$REPO_ROOT/dist/macos/$APP_NAME.app"
echo "==> assembling $APP_DIR"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
cp "$TARGET_DIR/release/gilbreth-app" "$APP_DIR/Contents/MacOS/gilbreth-app"

# LSUIElement: gilbreth-app is the tray (menu-bar) host — no Dock icon.
# The dashboard runs in-process; promoting to a regular activation policy
# while a window is open is app-layer work, not packaging work.
cat > "$APP_DIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>$BUNDLE_ID</string>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundleDisplayName</key>
    <string>$APP_NAME</string>
    <key>CFBundleExecutable</key>
    <string>gilbreth-app</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundleVersion</key>
    <string>$VERSION</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

if [[ -n "$IDENTITY" ]]; then
  echo "==> signing with identity: $IDENTITY"
  codesign --force --sign "$IDENTITY" --identifier "$BUNDLE_ID" \
    --timestamp=none "$APP_DIR"
  codesign --verify --verbose=2 "$APP_DIR"
  echo "==> signed. TCC grants made to this bundle persist across rebuilds"
  echo "    signed with the same identity."
elif [[ "$ADHOC" -eq 1 ]]; then
  echo "==> ad-hoc signing (throwaway: TCC grants die with the next rebuild)"
  codesign --force --sign - --identifier "$BUNDLE_ID" "$APP_DIR"
else
  echo "==> UNSIGNED bundle: fine for launch tests; do not use for"
  echo "    TCC-persistence testing (grants key to the exact binary hash"
  echo "    and every rebuild re-prompts). See --identity."
fi

echo "==> done: $APP_DIR"
