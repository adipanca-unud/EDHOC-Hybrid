#!/usr/bin/env bash
#
# build_freeradius.sh — Build FreeRADIUS 3.2.5 from the lib/ submodule
# with the custom rlm_eap_edhoc module.
#
# Usage:   ./freeradius/build_freeradius.sh
# Prefix:  /opt/freeradius-edhoc
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FREERADIUS_SRC="$PROJECT_ROOT/lib/freeradius-server"
PREFIX="/opt/freeradius-edhoc"

echo "============================================="
echo "  Building FreeRADIUS 3.2.5 + rlm_eap_edhoc"
echo "============================================="
echo "  Source : $FREERADIUS_SRC"
echo "  Prefix : $PREFIX"
echo ""

cd "$FREERADIUS_SRC"

# Step 1 — Configure (if not already configured)
if [ ! -f Makefile ] || [ ! -f config.log ]; then
    echo "[1/3] Running configure ..."
    ./configure \
        --prefix="$PREFIX" \
        --with-modules="rlm_eap rlm_eap_edhoc" \
        --without-rlm_eap_pwd \
        --without-rlm_eap_tnc \
        --without-rlm_eap_ikev2 \
        --without-rlm_sql \
        --without-rlm_ldap \
        --without-rlm_krb5 \
        --without-rlm_perl \
        --without-rlm_python \
        --without-rlm_redis \
        --without-rlm_rest \
        --without-rlm_smsotp \
        --without-rlm_unbound \
        --without-rlm_yubikey \
        --without-rlm_couchbase \
        --without-collectdclient \
        2>&1 | tail -20
    echo ""
else
    echo "[1/3] Already configured (remove config.log to reconfigure)"
fi

# Step 2 — Build
echo "[2/3] Building (make -j$(nproc)) ..."
make -j"$(nproc)" 2>&1 | tail -40
echo ""

# Step 3 — Install
echo "[3/3] Installing to $PREFIX ..."
sudo make install 2>&1 | tail -20
echo ""

# Verify the module
EAP_EDHOC_SO="$PREFIX/lib/rlm_eap_edhoc.so"
if [ -f "$EAP_EDHOC_SO" ]; then
    echo "✓ rlm_eap_edhoc.so installed at $EAP_EDHOC_SO"
    ls -la "$EAP_EDHOC_SO"
else
    # It might be under a different path in FR 3.x
    FOUND=$(find "$PREFIX" -name "rlm_eap_edhoc*" 2>/dev/null || true)
    if [ -n "$FOUND" ]; then
        echo "✓ Found rlm_eap_edhoc at:"
        echo "$FOUND"
    else
        echo "✗ WARNING: rlm_eap_edhoc.so not found under $PREFIX"
        echo "  Checking build directory..."
        find "$FREERADIUS_SRC/build" -name "rlm_eap_edhoc*" 2>/dev/null || echo "  Not found in build/ either"
    fi
fi

echo ""
echo "Done."
