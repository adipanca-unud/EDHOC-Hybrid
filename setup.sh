#!/usr/bin/env bash
# ============================================================================
# setup.sh — Post-clone setup for EDHOC-Hybrid (Raspberry Pi / ARM)
#
# Run this ONCE after:
#   git clone --recursive https://github.com/adipanca-unud/EDHOC-Hybrid.git
#   cd EDHOC-Hybrid
#   git checkout raspberrypi
#   git submodule update --init --recursive
#   ./setup.sh
#
# What it does:
#   1. Applies patches to lib/uoscore-uedhoc (disable DEBUG_PRINT, -O2,
#      compact25519 ARM build fixes)
#   2. Runs a full build
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================="
echo " EDHOC-Hybrid — Post-clone setup"
echo "============================================="
echo ""

# ── Step 1: Apply lib/uoscore-uedhoc patch ──────────────────────────────────
PATCH_FILE="patches/uoscore-uedhoc.patch"
SUBMOD_DIR="lib/uoscore-uedhoc"

if [ ! -f "$PATCH_FILE" ]; then
    echo "ERROR: Patch file '$PATCH_FILE' not found."
    echo "       Make sure you're on the 'raspberrypi' branch."
    exit 1
fi

if [ ! -d "$SUBMOD_DIR" ]; then
    echo "ERROR: Submodule directory '$SUBMOD_DIR' not found."
    echo "       Run: git submodule update --init --recursive"
    exit 1
fi

# Check if patch is already applied by testing one of the changes
if grep -q '^OPT = -O2' "$SUBMOD_DIR/makefile_config.mk" 2>/dev/null; then
    echo "✓ Patch already applied to $SUBMOD_DIR — skipping."
else
    echo "→ Applying patch to $SUBMOD_DIR ..."
    git -C "$SUBMOD_DIR" apply "$SCRIPT_DIR/$PATCH_FILE"
    echo "✓ Patch applied successfully."
fi

echo ""

# ── Step 2: Build ────────────────────────────────────────────────────────────
echo "→ Building (make lib-clean && make -j$(nproc)) ..."
echo "  This may take a few minutes on Raspberry Pi."
echo ""

make lib-clean
make -j"$(nproc)"

echo ""
echo "============================================="
echo " ✓ Setup complete!"
echo ""
echo " To run the benchmark:"
echo "   Responder:  ./build/edhoc_hybrid 9 --responder --port 30000"
echo "   Initiator:  ./build/edhoc_hybrid 9 --initiator --host <IP> --port 30000"
echo "============================================="
