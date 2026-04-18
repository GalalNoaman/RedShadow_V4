#!/bin/bash
# ─────────────────────────────────────────────────────────────
# RedShadow V4 — Setup Script
# Developed by Galal Noaman
# For educational and lawful use only.
# ─────────────────────────────────────────────────────────────

set -e

# ── Colours ──
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
RESET='\e[0m'

ok()   { echo -e "${GREEN}[✓]${RESET} $1"; }
warn() { echo -e "${YELLOW}[+]${RESET} $1"; }
err()  { echo -e "${RED}[!]${RESET} $1"; }
info() { echo -e "${BLUE}[ℹ]${RESET} $1"; }

# ── Banner ──
echo
echo -e "${RED}  ██████╗ ███████╗██████╗ ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗${RESET}"
echo -e "${RED}  ██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║${RESET}"
echo -e "${RED}  ██████╔╝█████╗  ██║  ██║███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║${RESET}"
echo -e "${RED}  ██╔══██╗██╔══╝  ██║  ██║╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║${RESET}"
echo -e "${RED}  ██║  ██║███████╗██████╔╝███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝${RESET}"
echo -e "${RED}  ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝${RESET}"
echo
echo -e "${CYAN}  🛡️  RedShadow V4 — Setup${RESET}"
echo -e "${RESET}  Developed by Galal Noaman | For lawful use only${RESET}"
echo

# ─────────────────────────────────────────
# Step 1 — System Checks
# ─────────────────────────────────────────
echo -e "${BLUE}── Step 1: System Checks ──────────────────────────${RESET}"

# Python 3.9+
if ! command -v python3 &>/dev/null; then
    err "Python3 is not installed."
    info "Install it with: sudo apt install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")

if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]; }; then
    err "Python 3.9+ required. Found: $PYTHON_VERSION"
    info "Upgrade Python and try again."
    exit 1
fi
ok "Python $PYTHON_VERSION found"

# pip
if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null; then
    err "pip is not installed."
    info "Install it with: sudo apt install python3-pip"
    exit 1
fi
ok "pip found"

# Nmap
if ! command -v nmap &>/dev/null; then
    warn "Nmap not found — installing..."
    sudo apt-get update -qq
    sudo apt-get install -y nmap
    ok "Nmap installed"
else
    NMAP_VERSION=$(nmap --version | head -1)
    ok "Nmap found: $NMAP_VERSION"
fi

# ─────────────────────────────────────────
# Step 2 — Virtual Environment
# ─────────────────────────────────────────
echo
echo -e "${BLUE}── Step 2: Virtual Environment ─────────────────────${RESET}"

if [ ! -d "venv" ]; then
    warn "Creating Python virtual environment..."
    python3 -m venv venv
    ok "Virtual environment created"
else
    ok "Virtual environment already exists"
fi

source venv/bin/activate

warn "Upgrading pip..."
pip install --upgrade pip --quiet
ok "pip upgraded"

# ─────────────────────────────────────────
# Step 3 — Python Dependencies
# ─────────────────────────────────────────
echo
echo -e "${BLUE}── Step 3: Python Dependencies ─────────────────────${RESET}"

if [ ! -f "requirements.txt" ]; then
    err "requirements.txt not found — cannot install dependencies."
    exit 1
fi

warn "Installing packages from requirements.txt..."
pip install -r requirements.txt --quiet
ok "All Python packages installed"

# ─────────────────────────────────────────
# Step 4 — Directory Structure
# ─────────────────────────────────────────
echo
echo -e "${BLUE}── Step 4: Directory Structure ──────────────────────${RESET}"

# outputs/
mkdir -p outputs
ok "outputs/ ready"

# data/nvd_cache/ — auto-populated by nvd.py
mkdir -p data/nvd_cache
ok "data/nvd_cache/ ready"

# data/wordlists/ — user drops custom wordlists here
mkdir -p data/wordlists
ok "data/wordlists/ ready"

# .gitkeep files so empty dirs are tracked by git
touch data/nvd_cache/.gitkeep
touch data/wordlists/.gitkeep

# ─────────────────────────────────────────
# Step 5 — Module Verification
# All 14 modules + utils checked
# ─────────────────────────────────────────
echo
echo -e "${BLUE}── Step 5: Module Files ─────────────────────────────${RESET}"

MODULES=(
    "modules/__init__.py"
    "modules/utils.py"
    "modules/domain.py"
    "modules/bruteforce.py"
    "modules/passive.py"
    "modules/probe.py"
    "modules/takeover.py"
    "modules/redirect.py"
    "modules/secret.py"
    "modules/s3scanner.py"
    "modules/jsextractor.py"
    "modules/wayback.py"
    "modules/githubscan.py"
    "modules/scan.py"
    "modules/nvd.py"
    "modules/analyse.py"
    "modules/report.py"
    "modules/pipeline.py"
    "main.py"
    "config.yaml"
)

ALL_OK=true
for f in "${MODULES[@]}"; do
    if [ ! -f "$f" ]; then
        err "Missing: $f"
        ALL_OK=false
    else
        ok "Found: $f"
    fi
done

if [ "$ALL_OK" = false ]; then
    err "One or more files are missing. Check your installation."
    exit 1
fi

# ─────────────────────────────────────────
# Step 6 — Data Files
# ─────────────────────────────────────────
echo
echo -e "${BLUE}── Step 6: Data Files ───────────────────────────────${RESET}"

if [ ! -f "data/cve_map.json" ]; then
    warn "data/cve_map.json not found — local CVE fallback will not work."
    info "The NVD API will be used instead. Add NVD_API_KEY to .env for best results."
else
    ok "data/cve_map.json found"
fi

# ─────────────────────────────────────────
# Step 7 — .env Template
# ─────────────────────────────────────────
echo
echo -e "${BLUE}── Step 7: Environment File ─────────────────────────${RESET}"

if [ ! -f ".env" ]; then
    cat > .env << 'EOF'
# RedShadow V4 — Environment Variables
# Add your API keys here. Never commit this file to git.

# NVD API key — higher rate limit (50 req/30s vs 5 req/30s)
# Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=

# GitHub personal access token — faster GitHub scanning (50 req/min vs 10 req/min)
# Generate at: https://github.com/settings/tokens (no scopes required for public search)
GITHUB_TOKEN=
EOF
    ok ".env template created — add your API keys to .env"
else
    ok ".env already exists"
fi

# ─────────────────────────────────────────
# Step 8 — Quick Smoke Test
# ─────────────────────────────────────────
echo
echo -e "${BLUE}── Step 8: Smoke Test ───────────────────────────────${RESET}"

if python3 main.py --version &>/dev/null; then
    ok "main.py runs correctly"
else
    warn "main.py --version failed — check for import errors"
    info "Run: python3 main.py --help"
fi

# ─────────────────────────────────────────
# Done
# ─────────────────────────────────────────
echo
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║        ✅  RedShadow V4 — Setup Complete         ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${RESET}"
echo
echo -e "${BLUE}  Quick start (full pipeline):${RESET}"
echo -e "${CYAN}    sudo venv/bin/python3 main.py auto --target hackerone.com${RESET}"
echo
echo -e "${BLUE}  Resume an interrupted scan:${RESET}"
echo -e "${CYAN}    sudo venv/bin/python3 main.py auto --target hackerone.com --resume${RESET}"
echo
echo -e "${BLUE}  Manual mode:${RESET}"
echo -e "${CYAN}    source venv/bin/activate${RESET}"
echo -e "${CYAN}    python3 main.py --help${RESET}"
echo
echo -e "${BLUE}  NVD cache stats:${RESET}"
echo -e "${CYAN}    python3 main.py cache --stats${RESET}"
echo
echo -e "${YELLOW}  ⚠️  Add API keys to .env for best performance:${RESET}"
echo -e "${YELLOW}      NVD_API_KEY  — faster CVE lookups${RESET}"
echo -e "${YELLOW}      GITHUB_TOKEN — faster GitHub scanning${RESET}"
echo
echo -e "${RED}  ⚠️  Use responsibly. Only scan targets you have explicit permission to test.${RESET}"
echo

