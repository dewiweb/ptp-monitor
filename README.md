# PTP Monitor

**Passive PTP clock monitoring for AoIP networks — Dante (PTPv1) & AES67/Ravenna (PTPv2).**

Desktop tool (Qt / PySide6) to watch PTP clock traffic in real time on a
production audio-over-IP network, detect problems, and record evidence for
vendor support cases.

> The UI is currently in French. Contributions for i18n are welcome.

## What it does

- **100% passive** — joins the standard PTP multicast group `224.0.1.129`
  (UDP 319/320) and listens. It never sends a single PTP packet and cannot
  disturb the clock election or timing of the network.
- **Dante leader (PTPv1)** — tracks who sends Sync, sync interval, jitter
  (mean/min/max/σ), leader change history.
- **AES67 grandmaster (PTPv2)** — clock identity, priorities, clock class,
  steps removed, announce timing, property changes.
- **Per-source stats** — message types, rates, sequence gaps/dupes,
  sync interval statistics, silence detection (a device that stops talking),
  non-standard PTP domains.
- **Malformed packet capture** — every unparsable datagram is logged with
  source IP and full hexdump (useful for "corrupted clock message" reports).
- **Evidence logs** — chronological JSONL journal + optional full packet
  capture, written to `logs/` next to the executable. Easy to correlate with
  crash timestamps, easy to send to vendor support.
- **Works on any network** — no hard-coded addresses. Friendly device names
  come from an optional `devices.json`, reverse DNS, and the IEEE OUI
  database (auto-downloaded at first launch).

## Run

```bash
pip install -r requirements.txt
python -m ptp_monitor
```

1. Select the NIC connected to your AoIP VLAN (or "TOUTES" for all).
2. Click **Démarrer l'écoute**. Allow the app through the firewall when
   prompted — blocked inbound UDP is the #1 cause of "no data".
3. Optionally click **● Enregistrer** to record every packet to JSONL.

## Portable Windows build

```batch
build.bat
```

Produces a single `dist\PTPMonitor.exe` (Python + Qt embedded, nothing to
install). Copy it to the target PC — it is fully self-contained.

## Optional companion files (next to the .exe)

| File | Purpose |
|---|---|
| `devices.json` | IP/MAC → device name mapping (see `devices.example.json`) |
| `oui.csv` | IEEE OUI database — auto-downloaded at launch if absent |
| `manuf` | Wireshark manufacturer file (alternative OUI source) |

`devices.json` format:

```json
{
  "192.168.20.15": {"name": "MIXER-DANTE", "mac": "00:1d:c1:02:6d:7f"},
  "192.168.20.26": "WIRELESS-RX"
}
```

The `mac` key is optional — it lets the app resolve EUI-64 clockIdentities
announced in PTPv2 Announce messages.

## Logs

Files land in `logs/` next to the executable:

- `ptp_journal_YYYYMMDD_HHMMSS.jsonl` — events: leader/GM changes, sequence
  gaps, silent sources, malformed packets, heartbeat status
- `ptp_capture_YYYYMMDD_HHMMSS.jsonl` — every received datagram (hex payload)

Each record has both `"ts"` (epoch) and `"time"` (human readable). Journal
lines are flushed immediately — nothing is lost if the app or PC crashes.

## Troubleshooting "no packets received"

1. **Firewall** — allow inbound UDP for `PTPMonitor.exe`:
   `netsh advfirewall firewall add rule name="PTPMonitor" dir=in action=allow program="C:\path\PTPMonitor.exe"`
2. **Interface** — try the "TOUTES" option.
3. **Cross-check with Wireshark** — filter `udp.port == 319 || udp.port == 320`.
   If Wireshark sees packets but the app doesn't, it's the firewall.
   If Wireshark sees nothing, check IGMP snooping/querier on the switch.

## Disclaimer

A packet flagged "malformed" means *this parser could not decode it* — it
may be truncated, an unsupported variant, or genuinely corrupted. Use the
hexdump and a Wireshark capture for ground truth.

## License

MIT — see [LICENSE](LICENSE).
