#!/bin/bash
# ══════════════════════════════════════════════════════════
#  RECON//OS — Setup & Launch Script
#  Installs Python deps + checks for optional Go tools
# ══════════════════════════════════════════════════════════

set -e
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${GREEN}"
echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗"
echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║"
echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║"
echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║"
echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║"
echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝"
echo -e "${NC}  Bug Bounty Recon Automation — Setup Script"
echo ""

# ── Python deps ──
echo -e "${GREEN}[1/4]${NC} Installing Python dependencies..."
pip install django uvicorn pydantic 2>/dev/null || pip3 install django uvicorn pydantic
echo -e "  ✓ Django, FastAPI compatibility libs, Uvicorn installed"

# ── Check Go tools ──
echo ""
echo -e "${GREEN}[2/4]${NC} Checking optional recon tools..."

check_tool() {
  if command -v "$1" &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} $1 — found"
  else
    echo -e "  ${YELLOW}✗${NC} $1 — missing (Python fallback will be used)"
    echo -e "      Install: $2"
  fi
}

check_tool subfinder "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
check_tool httpx     "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
check_tool nmap      "sudo apt install nmap  OR  brew install nmap"
check_tool ffuf      "go install github.com/ffuf/ffuf/v2@latest"
check_tool gau       "go install github.com/lc/gau/v2/cmd/gau@latest"

# ── Wordlist ──
echo ""
echo -e "${GREEN}[3/4]${NC} Checking wordlists..."
WORDLIST=""
for p in /usr/share/wordlists/dirb/common.txt /usr/share/dirb/wordlists/common.txt; do
  if [ -f "$p" ]; then
    WORDLIST="$p"
    echo -e "  ${GREEN}✓${NC} Wordlist found: $p"
    break
  fi
done
if [ -z "$WORDLIST" ]; then
  echo -e "  ${YELLOW}✗${NC} No wordlist found — installing dirb..."
  if command -v apt &>/dev/null; then
    sudo apt-get install -y dirb 2>/dev/null && echo -e "  ${GREEN}✓${NC} dirb installed"
  elif command -v brew &>/dev/null; then
    brew install dirb 2>/dev/null && echo -e "  ${GREEN}✓${NC} dirb installed via brew"
  else
    echo -e "  ${RED}✗${NC} Could not auto-install dirb. Dir fuzzing may be limited."
  fi
fi

# ── Launch ──
echo ""
echo -e "${GREEN}[4/4]${NC} Starting RECON//OS Django server..."
echo ""
echo -e "  ${GREEN}►${NC} API:       http://localhost:8000"
echo -e "  ${GREEN}►${NC} Docs:      http://localhost:8000/docs"
echo -e "  ${GREEN}►${NC} Dashboard: http://localhost:8000"
echo ""
echo -e "${YELLOW}  TIP:${NC} Only scan targets you own or have written permission to test."
echo ""

uvicorn reconsite.asgi:application --host 127.0.0.1 --port 8000
