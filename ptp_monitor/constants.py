"""Constantes protocole PTP et chemins de l'application."""

import os
import sys

# Multicast PTP standard (UDP 319 = event, 320 = general)
PTP_MCAST = "224.0.1.129"
PTP_EVENT_PORT = 319
PTP_GENERAL_PORT = 320

# Types de messages PTPv1 (IEEE 1588-2002) — champ "control" (octet 32).
# Dante envoie ses Sync avec un messageType trompeur à l'octet 20 ;
# le champ control est la source fiable.
PTPV1_MSG_TYPES = {
    0: "Sync", 1: "Delay_Req", 2: "Follow_Up", 3: "Delay_Resp", 4: "Management",
}

# Types de messages PTPv2 (IEEE 1588-2008) — nibble bas de l'octet 0.
PTPV2_MSG_TYPES = {
    0x0: "Sync", 0x1: "Delay_Req", 0x2: "Pdelay_Req", 0x3: "Pdelay_Resp",
    0x8: "Follow_Up", 0x9: "Delay_Resp", 0xA: "Pdelay_Resp_Follow_Up",
    0xB: "Announce", 0xC: "Signaling", 0xD: "Management",
}

PTPV2_CLOCK_CLASSES = {
    6: "GPS/primary",
    7: "PRC/primary",
    13: "applic. time source",
    14: "NTP",
    248: "interne (free-run)",
    255: "slave-only",
}

# Fenêtre glissante pour les stats d'intervalle par source
INTERVAL_WINDOW = 300


def app_dir():
    """Dossier de données : à côté de l'exe (frozen) ou répertoire courant."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.getcwd()


APP_DIR = app_dir()
LOG_DIR = os.path.join(APP_DIR, "logs")
