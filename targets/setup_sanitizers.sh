#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Installing JS sanitizers..."
cd "$SCRIPT_DIR"
npm init -y 2>/dev/null || true
npm install dompurify jsdom sanitize-html xss

echo "[*] Installing Python sanitizers..."
pip install bleach nh3

echo "[+] All sanitizers installed successfully."
