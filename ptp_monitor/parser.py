"""Parsing passif des datagrammes PTP (v1 Dante / v2 AES67-Ravenna)."""

import struct
from datetime import datetime

from .constants import PTPV1_MSG_TYPES, PTPV2_MSG_TYPES


def clock_id_to_str(data):
    return ":".join(f"{b:02x}" for b in data)


def clock_id_to_mac(clock_id):
    """EUI-64 -> MAC (retire l'insertion ff:fe)."""
    p = clock_id.split(":")
    if len(p) == 8 and p[3] == "ff" and p[4] == "fe":
        return ":".join(p[:3] + p[5:])
    return clock_id


def parse_ptp(data):
    """Parse un datagramme UDP PTP. Retourne un dict ou None si malformé."""
    if len(data) < 16:
        return None

    version = data[1] & 0x0F
    if version == 2:
        msg_type = data[0] & 0x0F
        result = {
            "version": "ptpv2",
            "msg_type": PTPV2_MSG_TYPES.get(msg_type, f"type{msg_type}"),
            "domain": data[4],
        }
        if len(data) >= 44:
            result["sequence_id"] = struct.unpack("!H", data[30:32])[0]
            result["source_clock_id"] = clock_id_to_str(data[20:28])
        if msg_type == 0x0B and len(data) >= 64:  # Announce
            result.update({
                "gm_clock_id": clock_id_to_str(data[53:61]),
                "gm_priority1": data[47],
                "gm_class": data[48],
                "gm_accuracy": data[49],
                "gm_priority2": data[52],
                "steps_removed": struct.unpack("!H", data[61:63])[0],
            })
        return result

    # PTPv1 (IEEE 1588-2002), utilisé par Dante.
    # En-tête : 0-1 versionPTP(=1), 2-3 versionNetwork, 4-19 subdomain (16 o),
    #           20 messageType, 21 sourceCommTech, 22-27 sourceUuid,
    #           28-29 sourcePortId, 30-31 sequenceId, 32 control
    # NOTE Dante : le champ messageType (octet 20) est trompeur — les Sync
    # Dante arrivent avec msgType=1. Le champ "control" (octet 32) est fiable :
    # 0=Sync, 1=Delay_Req, 2=Follow_Up, 3=Delay_Resp, 4=Management.
    if data[0] == 0 and data[1] == 1 and len(data) >= 34:
        ctrl = data[32]
        mt_code = ctrl if ctrl <= 4 else (data[20] & 0x1F)
        subdomain = data[4:20].rstrip(b"\x00").decode("ascii", errors="ignore").strip()
        return {
            "version": "ptpv1",
            "msg_type": PTPV1_MSG_TYPES.get(mt_code, f"type{mt_code}"),
            "domain": subdomain if subdomain and subdomain != "_DFLT" else "0",
            "source_uuid": clock_id_to_str(data[22:28]),
            "sequence_id": struct.unpack("!H", data[30:32])[0],
        }

    # Tolérance : datagramme qui ressemble à du PTPv1 (variantes Dante)
    # mais pas strictement conforme — on le compte quand même.
    if data[1] == 1 or (data[0] == 0 and data[1] == 0):
        return {
            "version": "ptpv1",
            "msg_type": "unknown",
            "domain": "?",
        }

    return None


def hexdump(data):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hexpart:<48}  {asc}")
    return "\n".join(lines)


def fmt_ts(ts, with_ms=True):
    s = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")
    return s[:-3] if with_ms else s[:8]
