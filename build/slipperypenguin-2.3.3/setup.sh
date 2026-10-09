#!/bin/bash
if command -v apt &> /dev/null; then
    apt install -y strace libcap2-bin
    sudo apt-get install -y libpango-1.0-0 libharfbuzz0b libcairo2-dev libpangoft2-1.0-0
elif command -v dnf &> /dev/null; then
    sudo dnf install strace
elif command -v pacman &> /dev/null; then
    sudo pacman -S strace
else
    echo "Could not detect package manager. Please install strace manually."
pip install weasyprint


fi