"""Résolution fabricant par préfixe OUI (3 premiers octets d'une MAC/EUI-64).

Sources de données, par ordre de priorité :
  1. oui.csv  — format officiel IEEE, à côté de l'exe
  2. manuf    — format Wireshark, à côté de l'exe
  3. téléchargement automatique de la base IEEE au premier lancement
  4. table de secours embarquée (fabricants AV courants)
"""

import os
import shutil
import urllib.request

from .constants import APP_DIR

# Table de secours : fabricants courants en audio/vidéo sur IP.
OUI_FALLBACK = {
    "00:0e:dd": "Shure",
    "00:0b:72": "Lawo",
    "00:1d:c1": "Audinate (Dante)",
    "00:19:7c": "Riedel",
    "00:21:84": "Powersoft",
    "00:60:45": "Luminex",
    "d0:69:9e": "Luminex",
    "00:50:c2": "IEEE 1588 default",
    "00:1b:66": "Genelec",
    "00:90:fb": "Focusrite/RedNet",
    "00:09:9b": "Lawo",
    "88:a2:9e": "Lawo",
    "f8:b1:56": "QSC",
    "00:0b:2f": "Merging Technologies",
    "00:30:59": "Holophonix",
    "00:19:0f": "QSC",
    "00:13:3b": "Holophonix",
    "00:01:66": "Lab.gruppen",
    "8c:1f:64": "Marian",
}

OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def load_oui_database():
    """Charge la base OUI externe si présente, sinon la table de secours.

    Retourne (table, source) où source vaut 'oui.csv', 'manuf' ou None.
    """
    table = dict(OUI_FALLBACK)
    src = None

    path = os.path.join(APP_DIR, "oui.csv")
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # MA-L,XXXXXX,"Vendor","addr" — assignment en hex sans ':'
                    parts = line.strip().split(",")
                    if len(parts) >= 3 and len(parts[1]) == 6:
                        a = parts[1].strip()
                        mac = ":".join(a[i:i + 2] for i in (0, 2, 4)).lower()
                        table[mac] = parts[2].strip().strip('"')
            src = "oui.csv"
        except OSError:
            pass

    path = os.path.join(APP_DIR, "manuf")
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("#") or not line.strip():
                        continue
                    fields = line.split()
                    prefix = fields[0].lower()
                    if prefix.count(":") == 2:
                        table[prefix] = fields[1]
            src = "manuf"
        except OSError:
            pass
    return table, src


def download_oui_csv(path=None):
    """Télécharge la base OUI officielle IEEE. Lève une exception en cas
    d'échec. À appeler depuis un thread de fond."""
    path = path or os.path.join(APP_DIR, "oui.csv")
    req = urllib.request.Request(OUI_CSV_URL,
                                 headers={"User-Agent": "ptp-monitor"})
    with urllib.request.urlopen(req, timeout=20) as r, open(path, "wb") as f:
        shutil.copyfileobj(r, f)


def reload():
    """(Re)charge la base et retourne (table, source)."""
    global TABLE, SOURCE
    TABLE, SOURCE = load_oui_database()
    return TABLE, SOURCE


TABLE, SOURCE = load_oui_database()


def oui_lookup(clock_id_str):
    """Fabricant pour un clockIdentity/MAC 'xx:yy:zz:...'."""
    parts = (clock_id_str or "").split(":")
    if len(parts) >= 3:
        return TABLE.get(":".join(parts[:3]).lower(), "Unknown")
    return "Unknown"
