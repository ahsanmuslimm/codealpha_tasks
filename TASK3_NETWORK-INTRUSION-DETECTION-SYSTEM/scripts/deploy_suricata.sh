#!/usr/bin/env bash
# ============================================================
#  Deploy Suricata + the PyNIDS rule pack + EVE feed on Ubuntu/Debian
#  Usage: sudo bash scripts/deploy_suricata.sh [interface]
# ============================================================
set -euo pipefail

IFACE="${1:-}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -z "$IFACE" ]]; then
    IFACE="$(ip -o -4 route show default | awk '{print $5; exit}')"
    echo "[*] No interface given - using default route interface: $IFACE"
fi

echo "[1/6] Installing Suricata"
apt-get update -qq
apt-get install -y -qq suricata

echo "[2/6] Deploying project configuration"
cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak.$(date +%s) || true
cp "$PROJECT_DIR/config/suricata.yaml" /etc/suricata/suricata.yaml

# point HOME_NET at the interface's real subnet
SUBNET="$(ip -o -4 addr show "$IFACE" | awk '{split($4,a,"."); print a[1]"."a[2]"."a[3]".0/24"}')"
if [[ -n "${SUBNET:-}" ]]; then
    echo "[*] Setting HOME_NET to $SUBNET in suricata.yaml"
    sed -i "s#HOME_NET: \"\[.*\]\"#HOME_NET: \"[${SUBNET}]\"#" /etc/suricata/suricata.yaml
fi

echo "[3/6] Deploying the project rule pack"
cp "$PROJECT_DIR/rules/custom.rules" /etc/suricata/rules/custom.rules
chown root:suricata /etc/suricata/rules/custom.rules
chmod 640 /etc/suricata/rules/custom.rules

echo "[4/6] Validating configuration"
suricata -T -c /etc/suricata/suricata.yaml -v | tail -5

echo "[5/6] Enabling the service"
systemctl enable --now suricata
systemctl restart suricata
sleep 3
systemctl --no-pager status suricata | head -12

echo "[6/6] Wiring the EVE feed into the PyNIDS dashboard/response stack"
echo "    One-shot import :  python3 ${PROJECT_DIR}/run_nids.py --import-eve /var/log/suricata/eve.json"
echo "    Continuous feed :  python3 ${PROJECT_DIR}/run_nids.py --service --eve /var/log/suricata/eve.json --with-dashboard"
echo "    Dashboard       :  http://127.0.0.1:5000"
echo
echo "[+] Suricata deployment complete."
