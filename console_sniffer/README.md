# Console packet sniffer (Linux)

Captures traffic on a chosen interface and highlights packets matching known game port lists. **ARP spoofing is off by default** (`ARP_SPOOFING = False` in `config.py`).

## Requirements

- **Linux** with Python 3.10+
- **libpcap** (for Scapy): `libpcap-dev` on Debian/Ubuntu
- Run with **elevated raw access**: `sudo` **or** `setcap cap_net_raw,cap_net_admin+eip` on the venv Python binary (see `install.sh`)

## Quick install (Debian/Ubuntu)

```bash
cd console_sniffer
chmod +x install.sh
./install.sh
source sniffer_env/bin/activate
python3 setup_wizard.py    # pick interface (e.g. eth0, wlan0)
sudo python3 main.py       # or use setcap as printed by install.sh
```

Find interface names: `ip link` or `ip -br link`.

## Geo IP (optional)

Place `GeoLite2-City.mmdb` in the project folder ([MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)). Without it, geo fields fall back to API/whois where possible.

## Chromebook Linux

Same steps; if `apt-get` works, `install.sh` applies. You still need raw capture — use `sudo` or `setcap` on the venv `python3`.

## Legal / ethical note

Only use on networks you own or have **explicit permission** to monitor. ARP spoofing can disrupt others and may be illegal if misused.
