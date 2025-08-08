#!/bin/bash

set -e

echo -e "\033[1;34m[+] Starting tool installation...\033[0m"

# === 1. Install system dependencies ===
echo -e "\033[1;34m[+] Installing dependencies: curl, git, jq, unzip...\033[0m"
sudo apt update -y
sudo apt install -y curl git jq unzip wget

# === 2. Install Golang if not installed ===
if ! command -v go &>/dev/null; then
    echo -e "\033[1;34m[+] Installing Golang...\033[0m"
    GO_VERSION="1.22.2"
    wget https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz
    rm go$GO_VERSION.linux-amd64.tar.gz
else
    echo -e "\033[1;32m[✓] Go is already installed.\033[0m"
fi

# === 3. Set PATH and Go environment ===
SHELL_RC="$HOME/.bashrc"
[[ "$SHELL" == *"zsh"* ]] && SHELL_RC="$HOME/.zshrc"

GO_PATH_LINE='export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin'
if ! grep -qxF "$GO_PATH_LINE" "$SHELL_RC"; then
    echo "$GO_PATH_LINE" >> "$SHELL_RC"
    echo -e "\033[1;32m[+] Added Go paths to $SHELL_RC\033[0m"
fi
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# === 4. Install Go tools ===
echo -e "\033[1;34m[+] Installing Go tools (subfinder, gf, waybackurls)...\033[0m"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/waybackurls@latest

# === 5. Setup GF Auto-Completion ===
GF_COMPLETION=$(find "$HOME/go/pkg/mod/github.com/tomnomnom/gf@"*/gf-completion.bash 2>/dev/null | head -n1)
if [[ -f "$GF_COMPLETION" ]]; then
    if ! grep -q "source $GF_COMPLETION" "$SHELL_RC"; then
        echo "source $GF_COMPLETION" >> "$SHELL_RC"
        echo -e "\033[1;32m[+] Enabled gf auto-completion in $SHELL_RC\033[0m"
    fi
else
    echo -e "\033[1;33m[!] GF completion script not found. Skipping.\033[0m"
fi

# === 6. Setup GF patterns ===
echo -e "\033[1;34m[+] Installing GF patterns from 1ndianl33t...\033[0m"
mkdir -p ~/.gf
if [ ! -d "$HOME/Gf-Patterns" ]; then
    git clone https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns
fi
cp -f ~/Gf-Patterns/*.json ~/.gf/

# === 7. Python requirements (colorama) ===
echo -e "\033[1;34m[+] Installing Python requirements...\033[0m"
pip3 install --upgrade pip
pip3 install colorama

# === 8. Confirm tools are accessible ===
echo -e "\033[1;32m[✓] Verifying installed tools...\033[0m"
command -v subfinder && echo "  ✔ subfinder found"
command -v gf && echo "  ✔ gf found"
command -v waybackurls && echo "  ✔ waybackurls found"

echo -e "\n\033[1;32m[✓] All tools installed successfully.\033[0m"
echo -e "\033[1;33m[!] Please run 'source $SHELL_RC' or restart your terminal.\033[0m"
