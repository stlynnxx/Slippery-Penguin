#!/bin/bash
if command -v apt &> /dev/null; then
    apt install -y strace libcap2-bin
elif command -v dnf &> /dev/null; then
    sudo dnf install strace
elif command -v pacman &> /dev/null; then
    sudo pacman -S strace
else
    echo "Could not detect package manager. Please install strace manually."
fi