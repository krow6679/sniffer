import re
import threading
import time
from datetime import datetime

import geoip2.database
import requests
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

try:
    import whois
except ImportError:
    whois = None


class PacketSniffer:
    def __init__(self, interface="eth0", target_games=None, geoip_path="GeoLite2-City.mmdb"):
        self.interface = interface
        self.target_games = target_games or []
        self._results = {}
        self._lock = threading.Lock()
        self.geoip_db = None
        try:
            self.geoip_db = geoip2.database.Reader(geoip_path)
        except OSError:
            print(
                f"[!] GeoLite2-City.mmdb not found at {geoip_path}. "
                "Geo lookups disabled; download from MaxMind or see README."
            )

        self.game_ports = {
            "GTA5": [6672, 61455, 61457, 61456, 61458],
            "RDR2": [3074, 6672, 61455],
            "Battlefront2": [3659, 10000, 20000],
            "Fortnite": [5222, 9999, 10000, 19000, 20000],
            "WoLong": [27015, 27016, 27017],
        }

    def packet_handler(self, packet):
        if IP not in packet:
            return
        ip_layer = packet[IP]
        src_ip = ip_layer.src

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            return

        game = self.identify_game_by_port(sport, dport)
        if not game:
            return

        with self._lock:
            if src_ip not in self._results:
                self._results[src_ip] = {
                    "ip": src_ip,
                    "gamertag": self.extract_gamertag(packet),
                    "game": game,
                    "ports": [],
                    "geo": {},
                    "isp": "",
                    "last_seen": datetime.now().isoformat(),
                    "packets": 0,
                }

            self._results[src_ip]["ports"].append(sport)
            self._results[src_ip]["packets"] += 1
            self._results[src_ip]["game"] = game

        self.enrich_ip_data(src_ip)

    def identify_game_by_port(self, sport, dport):
        for game, ports in self.game_ports.items():
            if sport in ports or dport in ports:
                return game
        return None

    def extract_gamertag(self, packet):
        if Raw not in packet:
            return "Unknown"
        payload = packet[Raw].load
        try:
            decoded = payload.decode("utf-8", errors="ignore")
            if "gamertag" in decoded.lower():
                match = re.search(r"gamertag[:=]\s*([\w\s]+)", decoded)
                if match:
                    return match.group(1).strip()

            patterns = [
                r"XBLID[:=]\s*([\w]+)",
                r"PSN[:=]\s*([\w]+)",
                r"(\w{3,15})\s*(?:playing|joined)",
            ]
            for pattern in patterns:
                match = re.search(pattern, decoded)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return "Unknown"

    def enrich_ip_data(self, ip):
        with self._lock:
            if ip not in self._results:
                return
            row = self._results[ip]

        try:
            if self.geoip_db:
                response = self.geoip_db.city(ip)
                with self._lock:
                    if ip in self._results:
                        self._results[ip]["geo"] = {
                            "city": response.city.name,
                            "country": response.country.name,
                            "lat": response.location.latitude,
                            "lon": response.location.longitude,
                        }

            isp_set = False
            if whois is not None:
                try:
                    w = whois.whois(ip)
                    org = getattr(w, "org", None) or (w.get("org") if isinstance(w, dict) else None)
                    if org:
                        with self._lock:
                            if ip in self._results:
                                self._results[ip]["isp"] = str(org)
                        isp_set = True
                except Exception:
                    pass

            if not isp_set:
                api_response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
                if api_response.get("isp"):
                    with self._lock:
                        if ip in self._results:
                            self._results[ip]["isp"] = api_response["isp"]
        except Exception as e:
            print(f"[!] Enrichment failed for {ip}: {e}")

    def start_sniffing(self):
        print(f"[+] Starting sniffer on interface {self.interface}")
        sniff(iface=self.interface, prn=self.packet_handler, store=False)

    def pause_sniffing(self, seconds):
        time.sleep(seconds)

    def get_results(self):
        with self._lock:
            return dict(self._results)
