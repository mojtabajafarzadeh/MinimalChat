#!/usr/bin/env bash
# Optional installer: copies the bundle to ~/.local/share/chat-app and
# links the launcher into ~/.local/bin. Fully offline, no sudo needed.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-$HOME/.local/share/chat-app}"
BIN_DIR="$HOME/.local/bin"

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
