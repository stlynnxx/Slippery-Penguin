#!/bin/bash
# Slippery Penguin Launch Wrapper

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Auto-activate venv if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run the main script with all passed arguments
python3 slipperypenguin.py "$@"