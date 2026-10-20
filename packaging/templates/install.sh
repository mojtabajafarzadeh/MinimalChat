#!/usr/bin/env bash
# Optional installer: copies the bundle to ~/.local/share/chat-app and
# links the launcher into ~/.local/bin. Fully offline, no sudo needed.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-$HOME/.local/share/chat-app}"
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
if [ -e "$DEST" ] && [ ! -e "$DEST/chat-app" ] && [ ! -e "$DEST/run.py" ]; then
  echo "refusing: $DEST exists and does not look like a chat-app install" >&2
  exit 1
fi

mkdir -p "$BIN_DIR"
rm -rf "$DEST"
mkdir -p "$DEST"
# Copy everything except runtime data.
tar -cf - -C "$SRC_DIR" --exclude='./data' . | tar -xf - -C "$DEST"
ln -sf "$DEST/chat-app" "$BIN_DIR/chat-app"

echo "Installed to $DEST"
echo "Linked launcher: $BIN_DIR/chat-app"
echo "Run with: chat-app   (make sure ~/.local/bin is on your PATH)"
echo "نصب شد. اجرا با دستور: chat-app"
