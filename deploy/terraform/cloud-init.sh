#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# ISO 42001 Scanner — Cloud-Init Setup Script
# Runs on first boot of OCI compute instance
# Fully autonomous — no human intervention required
# ═══════════════════════════════════════════════════════════════
set -euo pipefail
exec > >(tee /var/log/iso42001-cloud-init.log) 2>&1

INSTALL_DIR="/home/opc/iso42001-scanner"
TENANCY_OCID="${tenancy_ocid}"
SCANNER_PORT="${scanner_port}"
ENABLE_CRON="${enable_cron}"
SCAN_TIME="${scan_time}"
REPO_URL="${repo_url}"
REPO_BRANCH="${repo_branch}"

echo "[cloud-init] ISO 42001 Scanner setup starting at $(date -u)"

# 1. Install prerequisites
echo "[cloud-init] Step 1/7: Installing prerequisites..."
dnf install -y python39 python39-pip git 2>/dev/null || yum install -y python39 python39-pip git 2>/dev/null || true

# Ensure python3 points to python3.9 if available
if command -v python3.9 &>/dev/null && ! command -v python3 &>/dev/null; then
    alternatives --set python3 /usr/bin/python3.9 2>/dev/null || true
fi

# 2. Install OCI CLI
echo "[cloud-init] Step 2/7: Installing OCI CLI..."
sudo -u opc python3 -m pip install --user --quiet oci-cli 2>/dev/null || \
    sudo -u opc pip3 install --user --quiet oci-cli 2>/dev/null || true

# Verify OCI CLI
if sudo -u opc /home/opc/.local/bin/oci --version 2>/dev/null; then
    echo "[cloud-init] OCI CLI installed successfully"
else
    echo "[cloud-init] WARNING: OCI CLI installation may have failed, continuing..."
fi

# 3. Clone scanner from GitHub
echo "[cloud-init] Step 3/7: Downloading scanner from $REPO_URL (branch: $REPO_BRANCH)..."
rm -rf "$INSTALL_DIR"

if git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>/dev/null; then
    echo "[cloud-init] Scanner cloned successfully"
else
    echo "[cloud-init] Git clone failed, trying with --single-branch..."
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR" || {
        echo "[cloud-init] FATAL: Cannot download scanner. Exiting."
        exit 1
    }
fi

chown -R opc:opc "$INSTALL_DIR"

# 4. Install Python dependencies
echo "[cloud-init] Step 4/7: Installing Python dependencies..."
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    sudo -u opc python3 -m pip install --user --quiet -r "$INSTALL_DIR/requirements.txt" 2>/dev/null || true
fi

# 5. Create systemd service
echo "[cloud-init] Step 5/7: Creating systemd service..."
cat > /etc/systemd/system/iso42001-scanner.service << SVCEOF
[Unit]
Description=OCI ISO 42001 AI Compliance Scanner API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=opc
WorkingDirectory=$INSTALL_DIR
ExecStart=/home/opc/.local/bin/python3 server.py \\
    --auth instance_principal \\
    --tenancy $TENANCY_OCID \\
    --port $SCANNER_PORT \\
    --scan-on-start
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable iso42001-scanner

# 6. Setup daily cron if enabled
if [ "$ENABLE_CRON" = "true" ]; then
    HOUR=$(echo "$SCAN_TIME" | cut -d: -f1)
    MINUTE=$(echo "$SCAN_TIME" | cut -d: -f2)
    echo "[cloud-init] Step 6/7: Setting up daily scan cron at $SCAN_TIME UTC..."
    (crontab -u opc -l 2>/dev/null | grep -v "iso42001"; \
     echo "$MINUTE $HOUR * * * curl -s -X POST http://localhost:$SCANNER_PORT/api/iso42001/scan >/dev/null 2>&1") | crontab -u opc -
else
    echo "[cloud-init] Step 6/7: Daily cron disabled, skipping..."
fi

# 7. Open firewall port and start service
echo "[cloud-init] Step 7/7: Opening firewall and starting service..."
firewall-cmd --permanent --add-port=$SCANNER_PORT/tcp 2>/dev/null || true
firewall-cmd --reload 2>/dev/null || true

systemctl start iso42001-scanner

# Wait for service to become healthy
echo "[cloud-init] Waiting for scanner API to become healthy..."
for i in $(seq 1 30); do
    if curl -sf "http://localhost:$SCANNER_PORT/health" >/dev/null 2>&1; then
        echo "[cloud-init] Scanner API is healthy!"
        break
    fi
    sleep 2
done

echo "[cloud-init] ISO 42001 Scanner setup complete at $(date -u)"
echo "[cloud-init] API: http://$(hostname -I | awk '{print $1}'):$SCANNER_PORT"
echo "[cloud-init] Health: curl http://$(hostname -I | awk '{print $1}'):$SCANNER_PORT/health"
