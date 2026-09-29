"""Nommage des équipements : devices.json externe + reverse DNS.

Aucun nom ni IP n'est codé en dur — l'outil fonctionne sur n'importe quel
réseau. Pour des noms conviviaux, déposer un fichier devices.json à côté
de l'exécutable (voir devices.example.json) :

    {"192.168.20.15": {"name": "POWERCORE-DANTE", "mac": "00:1d:c1:02:6d:7f"},
     "192.168.20.26": "RECEPTEUR-HF"}

Le "mac" est optionnel ; il permet de résoudre les clockIdentity EUI-64
annoncés dans les messages PTPv2. Sans devices.json, l'app utilise le
reverse DNS puis le préfixe OUI.
"""

import json
import os
import socket

from .constants import APP_DIR
from .parser import clock_id_to_mac

DEVICE_TABLE = {}
_devices_json = os.path.join(APP_DIR, "devices.json")
if os.path.exists(_devices_json):
    try:
        with open(_devices_json, encoding="utf-8") as f:
            for ip, entry in json.load(f).items():
                if isinstance(entry, dict):
                    DEVICE_TABLE[ip] = (entry.get("mac"), entry.get("name", ""))
                else:
                    DEVICE_TABLE[ip] = (None, str(entry))
    except (OSError, json.JSONDecodeError):
        pass

NAME_BY_IP = {ip: name for ip, (_, name) in DEVICE_TABLE.items() if name}
NAME_BY_MAC = {mac: name for ip, (mac, name) in DEVICE_TABLE.items()
               if mac and name}

# ip -> nom reverse DNS découvert pendant l'écoute ("" = échec/pas de PTR)
HOSTNAMES = {}


def resolve_ptr(ip):
    """Reverse DNS bloquant — à appeler depuis un thread dédié."""
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except (OSError, socket.herror):
        return ""


def device_name(ip):
    return NAME_BY_IP.get(ip) or HOSTNAMES.get(ip, "")


def name_or_ip(ip):
    name = device_name(ip)
    return f"{ip} ({name})" if name else ip


def clock_id_name(clock_id):
    """Nom d'équipement pour un clockIdentity EUI-64, si connu."""
    return NAME_BY_MAC.get(clock_id_to_mac(clock_id), "")
