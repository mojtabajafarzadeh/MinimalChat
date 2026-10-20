#!/usr/bin/env bash
# Optional installer: copies the bundle to ~/.local/share/mchat and
# links the launcher into ~/.local/bin. Fully offline, no sudo needed.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-$HOME/.local/share/mchat}"
BIN_DIR="$HOME/.local/bin"

# Refuse the destinations where a recursive delete is a disaster rather than a
# reinstall. This argument is operator input, and "install over my home
# directory" must not be a thing this script can be talked into doing.
case "$DEST" in
  ""|"/"|"$HOME"|"$HOME/")
    echo "refusing to install over $DEST" >&2
    exit 1
    ;;
esac
# Only replace a directory that looks like a previous install, or one that does
# not exist yet. Anything else is a typo worth stopping for.
if [ -e "$DEST" ] && [ ! -e "$DEST/mchat" ] && [ ! -e "$DEST/run.py" ]; then
  echo "refusing: $DEST exists and does not look like an mchat install" >&2
  exit 1
fi

mkdir -p "$BIN_DIR"
rm -rf "$DEST"
mkdir -p "$DEST"
# Copy everything except runtime data.
tar -cf - -C "$SRC_DIR" --exclude='./data' . | tar -xf - -C "$DEST"
ln -sf "$DEST/mchat" "$BIN_DIR/mchat"

echo "Installed to $DEST"
echo "Linked launcher: $BIN_DIR/mchat"
echo "Run with: mchat   (make sure ~/.local/bin is on your PATH)"
echo "نصب شد. اجرا با دستور: mchat"
