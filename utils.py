import json

from colorama import Fore, Style
from prettytable import PrettyTable


def display_results(results):
    if not results:
        print("[!] No results yet")
        return

    table = PrettyTable()
    table.field_names = [
        Fore.GREEN + "IP Address" + Style.RESET_ALL,
        Fore.YELLOW + "Gamertag" + Style.RESET_ALL,
        Fore.CYAN + "Game" + Style.RESET_ALL,
        Fore.MAGENTA + "Ports" + Style.RESET_ALL,
        Fore.BLUE + "Country" + Style.RESET_ALL,
        Fore.RED + "ISP" + Style.RESET_ALL,
        Fore.WHITE + "Packets" + Style.RESET_ALL,
    ]

    for ip, data in results.items():
        table.add_row(
            [
                ip,
                data.get("gamertag", "Unknown"),
                data.get("game", "Unknown"),
                ", ".join(str(p) for p in data.get("ports", [])[:3]),
                data.get("geo", {}).get("country", "Unknown"),
                data.get("isp", "Unknown"),
                data.get("packets", 0),
            ]
        )

    print("\n" + table.get_string())


def save_to_log(results):
    with open("sniffer_log.json", "a", encoding="utf-8") as f:
        for ip, data in results.items():
            log_entry = {
                "timestamp": data.get("last_seen"),
                "ip": ip,
                "data": data,
            }
            f.write(json.dumps(log_entry) + "\n")


def get_interface_list():
    import netifaces

    return netifaces.interfaces()
