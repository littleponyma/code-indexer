#!/usr/bin/env bash
# code-indexer installer — works on Windows (Git Bash), macOS, Linux
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; exit 1; }

# --- Detect OS ---
OS="$(uname -s 2>/dev/null || echo Unknown)"
case "$OS" in
    Linux*)   PLATFORM="linux";;
    Darwin*)  PLATFORM="macos";;
    MINGW*|MSYS*|CYGWIN*) PLATFORM="windows";;
    *)        PLATFORM="unknown";;
esac
info "Platform: $PLATFORM"

# --- Check Python ---
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYVER=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+')
        MAJOR=$(echo "$PYVER" | cut -d. -f1)
        MINOR=$(echo "$PYVER" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    error "Python 3.10+ required. Install from https://python.org"
fi
info "Python: $($PYTHON --version 2>&1)"

# --- Project directory ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# --- Install Python dependencies ---
info "Installing Python packages..."
$PYTHON -m pip install --upgrade pip -q
$PYTHON -m pip install -r requirements.txt -q
info "Python packages installed"

# --- Install Claude Code skill ---
SKILL_NAME="code-indexer"
if [ "$PLATFORM" = "windows" ]; then
    SKILL_DIR="$(cmd.exe /c "echo %USERPROFILE%\\.claude\\skills\\$SKILL_NAME" 2>/dev/null | tr -d '\r')"
else
    SKILL_DIR="$HOME/.claude/skills/$SKILL_NAME"
fi

info "Installing Claude Code skill to: $SKILL_DIR"
mkdir -p "$SKILL_DIR"
cp -f ".claude/skills/$SKILL_NAME/SKILL.md" "$SKILL_DIR/SKILL.md" 2>/dev/null || true
cp -f ".claude/skills/$SKILL_NAME/INP.py" "$SKILL_DIR/INP.py" 2>/dev/null || true
info "Skill installed"

# --- IDA Pro check (optional) ---
info "Checking IDA Pro idalib (optional)..."
if $PYTHON -c "import idapro; idapro.get_library_version(); print('idalib available')" 2>/dev/null; then
    info "idalib: available"
else
    warn "idalib: not found — IDA deep analysis disabled"
    warn "  To enable: install IDA Pro 9 and set IDA_HOME or install idapro package"
fi

# --- Verify ---
info "Verifying installation..."
if $PYTHON -c "from indexer.models import Symbol; print('OK')" 2>/dev/null; then
    info "Core modules: OK"
else
    error "Core modules failed to import"
fi

echo ""
info "========================================="
info "  code-indexer installed successfully!"
info "========================================="
echo ""
info "Usage:"
info "  CLI:    python -m indexer.cli <path>"
info "  Skill:  /code-indexer <path>"
echo ""
info "Tested environments:"
info "  Windows 11 + Python 3.13.5"
info "  macOS 14  + Python 3.12"
info "  Ubuntu 22 + Python 3.10"
