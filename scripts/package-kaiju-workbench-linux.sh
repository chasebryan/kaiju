#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="$(uname -m)"
APPDIR="${1:-"$ROOT/target/kaiju-workbench.AppDir"}"
BIN="$ROOT/target/release/kaiju-workbench"
ICON="$APPDIR/usr/share/icons/hicolor/scalable/apps/kaiju-workbench.svg"

cargo build --release -p kaiju-workbench

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/scalable/apps"

install -m 755 "$BIN" "$APPDIR/usr/bin/kaiju-workbench"
install -m 644 "$ROOT/packaging/linux/kaiju-workbench.desktop" \
  "$APPDIR/usr/share/applications/kaiju-workbench.desktop"
install -m 644 "$ROOT/packaging/linux/kaiju-workbench.desktop" \
  "$APPDIR/kaiju-workbench.desktop"

awk '/<svg id="kaiju-word-banner"/,/<\/svg>/' "$ROOT/README.md" > "$ICON"
install -m 644 "$ICON" "$APPDIR/kaiju-workbench.svg"

cat > "$APPDIR/AppRun" <<'APPRUN'
#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$HERE/usr/bin/kaiju-workbench" "$@"
APPRUN
chmod 755 "$APPDIR/AppRun"

if command -v appimagetool >/dev/null 2>&1; then
  appimagetool "$APPDIR" "$ROOT/target/kaiju-workbench-$ARCH.AppImage"
  echo "Wrote target/kaiju-workbench-$ARCH.AppImage"
else
  tar -C "$(dirname "$APPDIR")" -czf \
    "$ROOT/target/kaiju-workbench-linux-$ARCH.tar.gz" \
    "$(basename "$APPDIR")"
  echo "appimagetool not found; wrote target/kaiju-workbench-linux-$ARCH.tar.gz"
fi
