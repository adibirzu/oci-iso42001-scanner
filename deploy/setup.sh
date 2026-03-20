#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# ISO 42001 Scanner — Standalone Deployment Setup
# For any OCI instance (OL8/OL9, 1+ OCPU)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

INSTALL_DIR="/home/opc/iso42001-scanner"
SERVICE_NAME="iso42001-scanner"
PORT=8080

echo "═══ ISO 42001 Scanner Setup ═══"

# Check required arg
if [ -z "${1:-}" ]; then
    echo "Usage: $0 <TENANCY_OCID> [AUTH_MODE]"
    echo "  AUTH_MODE: instance_principal (default) or config"
    exit 1
fi
TENANCY_OCID="$1"
AUTH_MODE="${2:-instance_principal}"

# 1. Install OCI CLI if missing
if ! command -v oci &>/dev/null && ! [ -f /home/opc/.local/bin/oci ]; then
    echo "[1/5] Installing OCI CLI..."
    pip3 install --user oci-cli
else
    echo "[1/5] OCI CLI found."
fi

# 2. Copy scanner files
echo "[2/5] Installing scanner to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}/config" "${INSTALL_DIR}/deploy"
cp scanner.py server.py "${INSTALL_DIR}/"
cp -r config/ "${INSTALL_DIR}/config/" 2>/dev/null || true

# 3. Configure systemd service
echo "[3/5] Configuring systemd service..."
sed "s|TENANCY_OCID_PLACEHOLDER|${TENANCY_OCID}|g" \
    deploy/iso42001-scanner.service > /tmp/${SERVICE_NAME}.service

if [ "${AUTH_MODE}" = "config" ]; then
    sed -i "s|--auth instance_principal|--auth config --profile DEFAULT|g" \
        /tmp/${SERVICE_NAME}.service
fi

sudo cp /tmp/${SERVICE_NAME}.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}
sudo systemctl start ${SERVICE_NAME}

# 4. Setup daily cron scan
echo "[4/5] Setting up daily scan cron (02:00 UTC)..."
CRON_CMD="0 2 * * * curl -s -X POST http://localhost:${PORT}/api/iso42001/scan >/dev/null 2>&1"
(crontab -l 2>/dev/null | grep -v "iso42001/scan"; echo "${CRON_CMD}") | crontab -

# 5. Verify
echo "[5/5] Verifying..."
sleep 3
if curl -s "http://localhost:${PORT}/health" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Scanner v{d.get(\"scanner\",\"?\")} - Status: {d.get(\"status\",\"?\")}')"; then
    echo ""
    echo "═══ Setup Complete ═══"
    echo "Scanner API: http://localhost:${PORT}"
    echo "Tenancy: ${TENANCY_OCID}"
    echo "Auth: ${AUTH_MODE}"
    echo "Daily scan: 02:00 UTC"
    echo ""
    echo "Test: curl http://localhost:${PORT}/api/iso42001/summary"
    echo "Scan: curl -X POST http://localhost:${PORT}/api/iso42001/scan"
else
    echo "WARNING: Service may not have started. Check: systemctl status ${SERVICE_NAME}"
fi
