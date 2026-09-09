#!/usr/bin/env bash
# AutoSecAudit launcher for Linux / macOS
set -e
cd "$(dirname "$0")"

if [ -d "venv" ]; then
    source venv/bin/activate
fi

python3 autosecaudit.py "$@"
