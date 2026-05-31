#!/usr/bin/env bash
# setup.sh – Install dependencies and run SecureVault on Linux / macOS
set -e

echo "=================================================="
echo " SecureVault – Setup"
echo "=================================================="
echo

OS="$(uname -s)"

if [[ "$OS" == "Linux" ]]; then
    if command -v apt-get &>/dev/null; then
        echo "[INFO] Detected Debian/Ubuntu – installing packages..."
        sudo apt-get update -q
        sudo apt-get install -y ruby ruby-dev ruby-gtk3 libgtk-3-dev
    elif command -v dnf &>/dev/null; then
        echo "[INFO] Detected Fedora/RHEL – installing packages..."
        sudo dnf install -y ruby ruby-devel gtk3-devel
        gem install gtk3
    elif command -v pacman &>/dev/null; then
        echo "[INFO] Detected Arch Linux – installing packages..."
        sudo pacman -Sy --noconfirm ruby gtk3
        gem install gtk3
    else
        echo "[WARN] Unknown distro – install ruby and gtk3 manually, then rerun."
        exit 1
    fi

elif [[ "$OS" == "Darwin" ]]; then
    echo "[INFO] Detected macOS – using Homebrew..."
    if ! command -v brew &>/dev/null; then
        echo "[ERROR] Homebrew not found. Install from https://brew.sh"
        exit 1
    fi
    brew install ruby gtk+3 pkg-config
    gem install gtk3

else
    echo "[ERROR] Unsupported OS: $OS"
    exit 1
fi

echo
echo "[INFO] All dependencies installed."
echo "[INFO] Launching SecureVault..."
echo
ruby securevault.rb
