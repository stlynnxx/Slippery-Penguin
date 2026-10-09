
#!/bin/bash
# Slippery Penguin Setup Script v2.3.3

set -e

echo "=========================================="
echo "  Slippery Penguin Installer"
echo "=========================================="

if command -v apt &> /dev/null; then
    echo "Debian/Ubuntu/Kali"
    sudo apt-get update -qq
    sudo apt-get install -y strace libcap2-bin python3-pip \
        libpango-1.0-0 libharfbuzz0b libcairo2-dev libpangoft2-1.0-0 \
        libgdk-pixbuf2-0 2>/dev/null || true
elif command -v dnf &> /dev/null; then
    echo "Fedora/RHEL"
    sudo dnf install -y strace gcc cairo-devel pango-devel gdk-pixbuf2-devel \
        python3-devel python3-pip 2>/dev/null || true
elif command -v pacman &> /dev/null; then
    echo "Arch Linux"
    sudo pacman -S --noconfirm strace base-devel cairo pango \
        python-pip 2>/dev/null || true
else
    echo "Error: Could not detect package manager."
    echo "Please ensure strace and pango libraries are installed manually."
fi

echo "Creating Python virtual environment"
python3 -m venv venv

echo "Activating virtual environment"
source venv/bin/activate

echo "Upgrading pip"
pip install --upgrade pip

echo "Installing Python dependencies"
pip install yattag weasyprint rich

echo "Verifying installations"
python3 -c "import yattag" && echo "yattag installed"
python3 -c "import weasyprint" && echo "weasyprint installed"
python3 -c "import rich" && echo "rich installed"

echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Activate environment: source venv/bin/activate"
echo "  2. Run the tool: python3 slipperypenguin.py --help"
echo ""
echo "Or use the wrapper: ./run.sh --output both"
echo ""