#!/usr/bin/env sh
set -u

cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)" || exit 1

INSTALL_DEV_DEPS="${LOCALDNSGUARD_INSTALL_DEV_DEPS:-0}"
for arg in "$@"; do
  case "$arg" in
    --dev|--dev-deps|dev)
      INSTALL_DEV_DEPS=1
      ;;
    --no-dev|--no-dev-deps)
      INSTALL_DEV_DEPS=0
      ;;
  esac
done
export LOCALDNSGUARD_INSTALL_DEV_DEPS="$INSTALL_DEV_DEPS"

if [ "$(id -u)" -ne 0 ]; then
  echo "DNS port 53 requires root privileges."
  if command -v sudo >/dev/null 2>&1; then
    echo "Restarting with sudo..."
    exec sudo sh "$0" "$@"
  fi
  echo "sudo was not found. Please run: sudo sh ./start-localdnsguard.sh"
  exit 1
fi

export LOCALDNSGUARD_WEB_HOST=0.0.0.0
export LOCALDNSGUARD_WEB_PORT=8080
export LOCALDNSGUARD_DNS_HOST=0.0.0.0
export LOCALDNSGUARD_DNS_PORT=53
export LOCALDNSGUARD_STRICT_DNS_PORT=1
export LOCALDNSGUARD_MAX_DNS_WORKERS=48
export LOCALDNSGUARD_MAX_UPSTREAM_WORKERS=16

install_python() {
  echo "Python was not found. Trying automatic installation..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y python3 python3-pip python3-venv
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm python python-pip
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 py3-pip
  elif command -v brew >/dev/null 2>&1; then
    brew install python
  else
    return 1
  fi
}

find_python() {
  if [ -n "${PYTHON_EXE:-}" ] && [ -x "$PYTHON_EXE" ]; then
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_EXE="$(command -v python3)"
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    PYTHON_EXE="$(command -v python)"
    return 0
  fi
  return 1
}

PYTHON_EXE="${PYTHON_EXE:-}"
if ! find_python; then
  install_python
  find_python || {
    echo "Python could not be installed or found automatically."
    echo "Please install Python 3.11+ and pip, then start this script again."
    exit 1
  }
fi

BASE_PYTHON_EXE="$PYTHON_EXE"
if [ ! -x ".venv/bin/python" ]; then
  echo "Creating local Python environment..."
  "$BASE_PYTHON_EXE" -m venv .venv || {
    echo "Local Python environment could not be created."
    echo "Please install python3-venv and then start this script again."
    exit 1
  }
fi
PYTHON_EXE="$(pwd)/.venv/bin/python"

echo "Starting LocalDNSGuard..."
echo "Web UI: http://127.0.0.1:${LOCALDNSGUARD_WEB_PORT}"
echo "DNS:    ${LOCALDNSGUARD_DNS_HOST}:${LOCALDNSGUARD_DNS_PORT} UDP/TCP"
echo "Python: ${PYTHON_EXE}"
echo

if ! "$PYTHON_EXE" -m pip --version >/dev/null 2>&1; then
  echo "Installing pip..."
  if "$PYTHON_EXE" -m ensurepip --upgrade >/dev/null 2>&1; then
    :
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y python3-pip
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3-pip
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm python-pip
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache py3-pip
  elif command -v brew >/dev/null 2>&1; then
    brew install python
  fi
fi

runtime_requirements_ok() {
  "$PYTHON_EXE" - <<'PY' >/dev/null 2>&1
import bcrypt
import certifi
import cryptography
import OpenSSL
import service_identity
import nacl
import aioquic
import psutil
PY
}

echo "Checking Python runtime requirements..."
if runtime_requirements_ok; then
  echo "Runtime requirements are already installed."
else
  echo "Installing Python runtime requirements..."
  "$PYTHON_EXE" -m pip install -r requirements.txt --disable-pip-version-check
  if [ $? -ne 0 ]; then
    echo "FAILED: Python runtime requirements could not be installed."
    echo "If this machine is offline or DNS is not working, restore network access or preinstall requirements.txt."
    exit 1
  fi
fi

if [ "$INSTALL_DEV_DEPS" = "1" ]; then
  echo "Installing Python development requirements..."
  "$PYTHON_EXE" -m pip install -r requirements-dev.txt --disable-pip-version-check
  if [ $? -ne 0 ]; then
    echo "FAILED: Python development requirements could not be installed."
    exit 1
  fi
fi

echo "All required Python runtime packages are installed."
echo
echo "Server console is active. Commands: restart, stop, status, dnssec test, cache clear, update blocklist, dedupe blocklists"
echo

"$PYTHON_EXE" ./app.py 2>>server.err.log
EXIT_CODE=$?

if [ "$EXIT_CODE" -ne 0 ]; then
  CRASH_STAMP="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo fallback)"
  CRASH_FILE="crash_${CRASH_STAMP}.txt"
  CRASH_LATEST="crash_timestamp.txt"
  {
    echo "LocalDNSGuard process exited unexpectedly"
    echo "timestamp: $(date 2>/dev/null || true)"
    echo "exit_code: ${EXIT_CODE}"
    echo "command: ${PYTHON_EXE} ./app.py"
    echo
  } >"$CRASH_FILE"
  if [ -f startup.log ]; then
    {
      echo "--- startup.log tail ---"
      tail -n 80 startup.log
    } >>"$CRASH_FILE"
  fi
  if [ -f server.err.log ]; then
    {
      echo
      echo "--- server.err.log tail ---"
      tail -n 120 server.err.log
    } >>"$CRASH_FILE"
  fi
  if [ -f fatal-python.log ]; then
    {
      echo
      echo "--- fatal-python.log tail ---"
      tail -n 120 fatal-python.log
    } >>"$CRASH_FILE"
  fi
  cp "$CRASH_FILE" "$CRASH_LATEST" 2>/dev/null || true
  echo
  echo "Crash report written: ${CRASH_FILE}"
  echo "Latest crash report: ${CRASH_LATEST}"
fi

exit "$EXIT_CODE"
