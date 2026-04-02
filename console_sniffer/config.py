# Default configuration (run setup_wizard.py to regenerate)

# Use `ip link` or setup_wizard.py — often eth0, wlan0, or enp*s*
INTERFACE = "eth0"
ARP_SPOOFING = False

TARGET_GAMES = [
    "GTA5",
    "RDR2",
    "Battlefront2",
    "Fortnite",
    "WoLong",
]

GAME_PORT_RANGES = {
    "GTA5": [6672, 61455, 61457, 61456, 61458],
    "RDR2": [3074, 6672, 61455],
    "Battlefront2": [3659, 10000, 20000],
    "Fortnite": [5222, 9999, 10000, 19000, 20000],
    "WoLong": [27015, 27016, 27017],
}
