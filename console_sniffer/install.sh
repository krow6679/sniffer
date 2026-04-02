#!/usr/bin/env bash
# Console sniffer — Linux setup (Debian/Ubuntu and similar).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "Installing Console Packet Sniffer (Linux)"
echo "==========================================="

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y python3 python3-pip python3-venv python3-dev build-essential libpcap-dev
else
  echo "[!] apt-get not found. Install python3, pip, venv, and libpcap dev headers for your distro."
fi

python3 -m venv sniffer_env
# shellcheck source=/dev/null
source sniffer_env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

PY="$(readlink -f sniffer_env/bin/python3)"
echo ""
echo "Optional: download GeoLite2-City.mmdb from MaxMind and place it in:"
echo "  $ROOT/"
echo ""
echo "Raw sockets — pick one:"
echo "  1) Run with sudo:  sudo ./sniffer_env/bin/python3 main.py"
echo "  2) Or grant caps (recommended):"
echo "       sudo setcap cap_net_raw,cap_net_admin+eip $PY"
echo "     then:  ./sniffer_env/bin/python3 main.py"
echo ""
echo "Configure interface (often eth0 or wlan0):"
echo "  source sniffer_env/bin/activate && python3 setup_wizard.py"
echo ""
echo "Done."
