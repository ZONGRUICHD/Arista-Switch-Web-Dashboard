#!/usr/bin/env sh
set -eu

REPO="${REPO:-zong1024/Arista-Management-Port-Web-Interface}"
BRANCH="${BRANCH:-master}"
APP_URL="${APP_URL:-https://raw.githubusercontent.com/$REPO/$BRANCH/onbox/arista7050_web.py}"
APP_PATH="${APP_PATH:-/mnt/flash/arista7050_web.py}"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-2480}"
LOG="${LOG:-/mnt/flash/arista7050_web.log}"
PYTHON="${PYTHON:-python3}"

download() {
  url="$1"
  target="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --connect-timeout 15 --max-time 120 -o "$target" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$target" "$url"
  else
    echo "ERROR: curl or wget is required." >&2
    exit 1
  fi
}

echo "Arista WebUI installer"
echo "Source: $APP_URL"
echo "Target: $APP_PATH"
echo "Listen: $HOST:$PORT"

tmp="${APP_PATH}.download.$$"
backup=""
if [ -f "$APP_PATH" ]; then
  backup="${APP_PATH}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$APP_PATH" "$backup"
  echo "Backup: $backup"
fi

download "$APP_URL" "$tmp"
chmod 755 "$tmp"
"$PYTHON" -m py_compile "$tmp"
mv "$tmp" "$APP_PATH"

if command -v pkill >/dev/null 2>&1; then
  pkill -f "$APP_PATH" >/dev/null 2>&1 || true
fi

"$PYTHON" "$APP_PATH" --host "$HOST" --port "$PORT" --daemon --log "$LOG"
sleep 1

if command -v ss >/dev/null 2>&1; then
  ss -ltnp 2>/dev/null | grep ":$PORT " || true
elif command -v netstat >/dev/null 2>&1; then
  netstat -ltnp 2>/dev/null | grep ":$PORT " || true
fi

echo "Done. Open: http://<switch-management-ip>:$PORT/"
echo "Note: this installer does not change EOS ACL or startup configuration."
