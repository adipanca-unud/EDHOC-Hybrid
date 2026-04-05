#!/bin/bash
# =============================================================================
# setup_freeradius.sh - Configure FreeRADIUS for EAP-EDHOC benchmark
# =============================================================================
#
# Sets up the custom FreeRADIUS installation at /opt/freeradius-edhoc
# with the rlm_eap_edhoc module for 3-party EAP-EDHOC benchmarking.
#
# Architecture:
#   EAP Peer (Initiator) <-> Authenticator (RADIUS NAS) <-> FreeRADIUS AAA Server
#                                                            (EDHOC Responder via
#                                                             edhoc_engine process)
# =============================================================================

set -e

RADDB="/opt/freeradius-edhoc/etc/raddb"

echo "[*] Configuring FreeRADIUS for EAP-EDHOC benchmark..."

# --- 1. Set default EAP type to edhoc ---
sudo sed -i 's/default_eap_type = md5/default_eap_type = edhoc/' "$RADDB/mods-available/eap"

# --- 2. Add EAP-EDHOC sub-module config (before the closing brace) ---
# Check if edhoc section already exists
if ! sudo grep -q "edhoc {" "$RADDB/mods-available/eap"; then
    # Add edhoc section before the final closing brace
    sudo sed -i '/^}$/i\\n\t#  EAP-EDHOC\n\t#\n\t#  The EDHOC module implements EAP-EDHOC per draft-ietf-emu-eap-edhoc.\n\t#  EDHOC crypto is handled by an external engine process.\n\t#\n\tedhoc {\n\t\t#  Path to the EDHOC engine Unix socket\n\t\tengine_socket = "/tmp/edhoc_engine.sock"\n\t}' "$RADDB/mods-available/eap"
    echo "  [+] Added EAP-EDHOC section to mods-available/eap"
fi

# --- 3. Enable the EAP module (should already be enabled) ---
if [ ! -L "$RADDB/mods-enabled/eap" ]; then
    sudo ln -sf ../mods-available/eap "$RADDB/mods-enabled/eap"
    echo "  [+] Enabled EAP module"
fi

# --- 4. Configure RADIUS client (the Authenticator / NAS) ---
# Use shared secret "edhoc_benchmark_secret" on 127.0.0.1
if ! sudo grep -q "edhoc_benchmark" "$RADDB/clients.conf"; then
    sudo tee -a "$RADDB/clients.conf" > /dev/null << 'EOF'

# EDHOC Benchmark Authenticator (NAS)
client edhoc_benchmark {
    ipaddr = 127.0.0.1
    secret = edhoc_bench_secret
    shortname = edhoc-nas
    nastype = other
}
EOF
    echo "  [+] Added benchmark client to clients.conf"
fi

# --- 5. Configure authorize to accept any identity for EDHOC ---
# The EDHOC exchange doesn't use passwords; authentication is
# done entirely within the EAP-EDHOC method.
if ! sudo grep -q "edhoc-hybrid" "$RADDB/users"; then
    sudo tee -a "$RADDB/users" > /dev/null << 'EOF'

# EAP-EDHOC benchmark user — accepts any identity
# Authentication is handled by the EAP-EDHOC method
DEFAULT EAP-Type == EDHOC, Auth-Type := EAP
EOF
    echo "  [+] Added EDHOC user entry"
fi

# --- 6. Set auth port to non-standard for benchmark (avoid conflicts) ---
# Use port 18120 (auth) and 18121 (acct) to avoid conflicts with system FreeRADIUS
LISTEN_CONF="$RADDB/sites-available/default"
if ! sudo grep -q "18120" "$LISTEN_CONF"; then
    sudo sed -i 's/port = 0$/port = 18120/' "$LISTEN_CONF" 2>/dev/null || true
    echo "  [+] Set auth port to 18120"
fi

# --- 7. Disable unused modules to speed up startup ---
for mod in ldap sql python python3 redis krb5; do
    if [ -L "$RADDB/mods-enabled/$mod" ]; then
        sudo rm -f "$RADDB/mods-enabled/$mod"
    fi
done

echo "[*] FreeRADIUS configuration complete."
echo ""
echo "  To start FreeRADIUS for benchmark:"
echo "    sudo /opt/freeradius-edhoc/sbin/radiusd -X"
echo ""
echo "  Auth port: 18120"
echo "  Shared secret: edhoc_bench_secret"
echo "  Engine socket: /tmp/edhoc_engine.sock"
