"""Threads : réception multicast passive PTP + workers de fond."""

import queue
import select
import socket
import struct
import threading
import time

from PySide6.QtCore import QThread, Signal

from .constants import (
    PTP_EVENT_PORT, PTP_GENERAL_PORT, PTP_MCAST, PTP_MCAST_ALL)
from .devices import HOSTNAMES, resolve_ptr
from .parser import parse_ptp


class PtpListener(QThread):
    """Thread d'écoute multicast. Émet un dict par datagramme reçu."""

    packet = Signal(dict)
    error = Signal(str)
    info = Signal(str)

    def __init__(self, iface_ips, parent=None):
        """iface_ips : liste d'IPs locales sur lesquelles joindre le groupe."""
        super().__init__(parent)
        self.iface_ips = iface_ips
        self._running = True
        self._resolve_q = queue.Queue()
        self._pending_dns = set()

    def _resolver(self):
        """Thread dédié : reverse DNS sans bloquer la réception de paquets."""
        while self._running:
            try:
                ip = self._resolve_q.get(timeout=0.5)
            except queue.Empty:
                continue
            HOSTNAMES[ip] = resolve_ptr(ip)
            self._pending_dns.discard(ip)

    def stop(self):
        self._running = False

    def _join(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", port))
        joined = []
        for ip in self.iface_ips:
            for group in PTP_MCAST_ALL:
                try:
                    mreq = struct.pack("4s4s", socket.inet_aton(group),
                                       socket.inet_aton(ip))
                    sock.setsockopt(socket.IPPROTO_IP,
                                    socket.IP_ADD_MEMBERSHIP, mreq)
                except OSError as e:
                    self.error.emit(
                        f"IGMP join {group} échoué sur {ip}:{port} : {e}")
            joined.append(ip)
        self.info.emit(
            f"UDP {port} : joint {', '.join(PTP_MCAST_ALL)} sur {joined}")
        sock.setblocking(False)
        return sock

    def run(self):
        try:
            socks = {self._join(PTP_EVENT_PORT): PTP_EVENT_PORT,
                     self._join(PTP_GENERAL_PORT): PTP_GENERAL_PORT}
        except OSError as e:
            self.error.emit(
                f"Impossible d'ouvrir les sockets UDP 319/320 : {e}")
            return

        resolver = threading.Thread(target=self._resolver, daemon=True)
        resolver.start()

        while self._running:
            try:
                readable, _, _ = select.select(list(socks), [], [], 0.5)
                for sock in readable:
                    data, addr = sock.recvfrom(2048)
                    if (addr[0] not in HOSTNAMES
                            and addr[0] not in self._pending_dns):
                        self._pending_dns.add(addr[0])
                        self._resolve_q.put(addr[0])
                    self.packet.emit({
                        "ts": time.time(),
                        "src_ip": addr[0],
                        "src_port": addr[1],
                        "dst_port": socks[sock],
                        "len": len(data),
                        "parsed": parse_ptp(data),
                        "raw": data,
                    })
            except OSError as e:
                self.error.emit(f"Erreur réception : {e}")
                break

        for s in socks:
            s.close()


class DownloadWorker(QThread):
    """Worker générique : exécute work() en tâche de fond."""

    def __init__(self, work, parent=None):
        super().__init__(parent)
        self.work = work
        self.result = None

    def run(self):
        self.result = self.work()
