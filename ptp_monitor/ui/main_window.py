"""Fenêtre principale PTP Monitor."""

import binascii
import csv
import json
import os
import re
import socket
import time
import traceback
from collections import Counter
from datetime import datetime

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QGridLayout, QGroupBox, QHBoxLayout,
    QHeaderView, QLabel, QMainWindow, QPlainTextEdit, QPushButton, QSplitter,
    QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .. import oui
from ..constants import LOG_DIR, PTP_MCAST, PTPV2_CLOCK_CLASSES
from ..devices import clock_id_name, device_name, name_or_ip
from ..listener import DownloadWorker, PtpListener
from ..parser import fmt_ts, hexdump
from ..stats import SourceStats
from .chart import IntervalChart
from .dialogs import MalformedDialog


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PTP Monitor — Dante PTPv1 / AES67 PTPv2")
        self.resize(1200, 840)

        self.listener = None
        self.sources = {}            # (version, src_ip) -> SourceStats
        self.source_meta = {}        # (version, src_ip) -> dict (domain, extra)
        self.malformed = []
        self.leader_v1 = None
        self.gm_v2 = None
        self.leader_history = []     # (ts, old, new)
        self.recording = False
        self.record_file = None
        self.record_path = None
        self.log_file = None
        self.log_path = None
        self.session_start = None
        self.total_packets = 0
        self.row_index = {}          # (version, src_ip) -> row
        self._announce_props = {}    # src_ip -> tuple props GM annoncées
        self._leader_sync_ok = True
        self._sync_competitors = set()   # src_ip émettant des Sync v1 concurrents
        self._gm_competitors = set()     # src_ip annonçant un GM v2 concurrent

        self._build_ui()
        self._auto_fetch_oui()

        # Timer de rafraîchissement des tables (1 Hz)
        self.ui_timer = QTimer(self)
        self.ui_timer.setInterval(1000)
        self.ui_timer.timeout.connect(self._refresh_tables)
        self.ui_timer.start()

    # ---------- UI ----------
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # Barre de contrôle
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Interface (IP locale) :"))
        self.iface_combo = QComboBox()
        self.iface_combo.setEditable(True)
        self.iface_combo.setMinimumWidth(160)
        self.iface_combo.addItem("TOUTES (toutes les interfaces)")
        self.iface_combo.addItems(self._local_ips())
        self.iface_combo.setToolTip(
            "IP de la NIC du VLAN AoIP, ou TOUTES pour écouter sur "
            "toutes les interfaces")
        bar.addWidget(self.iface_combo)
        btn_refresh = QPushButton("Rafraîchir")
        btn_refresh.clicked.connect(self._refresh_ifaces)
        bar.addWidget(btn_refresh)

        self.btn_start = QPushButton("Démarrer l'écoute")
        self.btn_start.clicked.connect(self.toggle_listen)
        bar.addWidget(self.btn_start)

        self.btn_record = QPushButton("● Enregistrer")
        self.btn_record.setCheckable(True)
        self.btn_record.setEnabled(False)
        self.btn_record.clicked.connect(self.toggle_record)
        bar.addWidget(self.btn_record)

        self.btn_report = QPushButton("Rapport")
        self.btn_report.clicked.connect(self.save_report)
        bar.addWidget(self.btn_report)

        self.btn_export = QPushButton("Export CSV")
        self.btn_export.clicked.connect(self.export_csv)
        bar.addWidget(self.btn_export)

        self.btn_oui = QPushButton("Base OUI")
        self.btn_oui.setToolTip(
            "Télécharge la base OUI officielle IEEE (oui.csv) à côté de l'exe")
        self.btn_oui.clicked.connect(self.download_oui)
        bar.addWidget(self.btn_oui)

        self.chk_verbose = QCheckBox("Log chaque paquet")
        self.chk_verbose.setToolTip(
            "Logge chaque paquet reçu dans le Journal (verbeux, debug)")
        bar.addWidget(self.chk_verbose)

        bar.addStretch(1)
        root.addLayout(bar)

        # Cartes de statut
        cards = QGridLayout()
        self.lbl_leader = self._card("Leader Dante (PTPv1)", "—")
        self.lbl_interval = self._card("Intervalle Sync", "—")
        self.lbl_jitter = self._card("Jitter moy±σ (min/max)", "—")
        self.lbl_gm = self._card("Grandmaster PTPv2", "—")
        self.lbl_sources = self._card("Sources actives", "0")
        self.lbl_malformed = self._card("Paquets malformés", "0")
        for i, w in enumerate([self.lbl_leader, self.lbl_interval, self.lbl_jitter,
                               self.lbl_gm, self.lbl_sources, self.lbl_malformed]):
            cards.addWidget(w, 0, i)
        root.addLayout(cards)

        # Onglets
        tabs = QTabWidget()

        self.chart = IntervalChart()
        tabs.addTab(self.chart, "Graphe Sync")

        # Onglet sources + détail stats
        split_src = QSplitter(Qt.Vertical)
        self.tbl_sources = QTableWidget(0, 9)
        self.tbl_sources.setHorizontalHeaderLabels(
            ["Version", "Dom.", "Source IP", "Équipement", "Msgs", "Msg/s",
             "Gaps seq", "Intervalle moy±σ", "Dernier vu"])
        self.tbl_sources.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_sources.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_sources.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl_sources.itemSelectionChanged.connect(self._show_source_detail)
        split_src.addWidget(self.tbl_sources)
        self.source_detail = QPlainTextEdit()
        self.source_detail.setReadOnly(True)
        self.source_detail.setMaximumHeight(140)
        split_src.addWidget(self.source_detail)
        tabs.addTab(split_src, "Sources & stats")

        # Onglet malformés
        split = QSplitter(Qt.Vertical)
        self.tbl_malformed = QTableWidget(0, 5)
        self.tbl_malformed.setHorizontalHeaderLabels(
            ["Heure", "Source IP", "Port dst", "Longueur", "Aperçu"])
        self.tbl_malformed.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_malformed.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_malformed.itemSelectionChanged.connect(self._show_malformed_detail)
        self.tbl_malformed.itemDoubleClicked.connect(self._open_malformed)
        split.addWidget(self.tbl_malformed)
        self.malformed_detail = QPlainTextEdit()
        self.malformed_detail.setReadOnly(True)
        split.addWidget(self.malformed_detail)
        tabs.addTab(split, "Paquets malformés")

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        tabs.addTab(self.log_view, "Journal")

        root.addWidget(tabs)
        self.statusBar().showMessage("Arrêté")

    def _card(self, title, value):
        box = QGroupBox(title)
        lay = QVBoxLayout(box)
        lbl = QLabel(value)
        lbl.setStyleSheet("font-size: 14px; font-weight: bold;")
        lay.addWidget(lbl)
        box._value = lbl
        return box

    def _set_card(self, box, text, color=None):
        box._value.setText(text)
        box._value.setStyleSheet(
            f"font-size: 14px; font-weight: bold; color: {color};" if color
            else "font-size: 14px; font-weight: bold;")

    @staticmethod
    def _local_ips():
        ips = set()
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None,
                                           socket.AF_INET):
                ips.add(info[4][0])
        except OSError:
            pass
        if len(ips) <= 1:
            # getaddrinfo() ne retourne souvent qu'une IP sous Windows ;
            # ipconfig liste toutes les NICs.
            try:
                import subprocess
                out = subprocess.run(
                    ["ipconfig"], capture_output=True, text=True,
                    timeout=5).stdout
                for line in out.splitlines():
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s*$",
                                  line.strip())
                    if m and "IPv4" in line:
                        ips.add(m.group(1))
            except (OSError, subprocess.SubprocessError):
                pass
        ips.discard("127.0.0.1")
        return sorted(ips)

    # ---------- Base OUI ----------
    def _auto_fetch_oui(self):
        """Au lancement : télécharge la base IEEE en fond si absente."""
        if oui.SOURCE is not None:
            return

        def work():
            try:
                oui.download_oui_csv()
                return None
            except Exception:
                return True  # échec silencieux (réseau isolé = normal)

        def done(failed):
            if not failed:
                table, _src = oui.reload()
                self._log("INFO",
                          f"Base OUI IEEE téléchargée ({len(table)} entrées)")
        self._start_worker(work, done)

    def download_oui(self):
        """Bouton : (re)télécharge la base OUI IEEE."""
        self.btn_oui.setEnabled(False)
        self.btn_oui.setText("Téléchargement...")

        def work():
            try:
                oui.download_oui_csv()
                return None
            except Exception as e:
                return str(e)

        def done(err):
            if err:
                self._log("ERROR", f"Téléchargement base OUI échoué : {err}")
            else:
                table, _src = oui.reload()
                self._log("INFO",
                          f"Base OUI IEEE chargée ({len(table)} entrées)")
            self.btn_oui.setEnabled(True)
            self.btn_oui.setText("Base OUI")

        self._start_worker(work, done)

    def _start_worker(self, work, done):
        worker = DownloadWorker(work, self)
        worker.finished.connect(lambda: done(worker.result))
        worker.start()
        return worker

    def _refresh_ifaces(self):
        current = self.iface_combo.currentText()
        self.iface_combo.clear()
        self.iface_combo.addItem("TOUTES (toutes les interfaces)")
        self.iface_combo.addItems(self._local_ips())
        self.iface_combo.setCurrentText(current)

    # ---------- Logs ----------
    def _open_log(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        self.log_path = os.path.join(
            LOG_DIR, f"ptp_journal_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
        self.log_file = open(self.log_path, "a", encoding="utf-8")

    def _log(self, level, msg, extra=None):
        line = f"[{fmt_ts(time.time())}] {level:<9} {msg}"
        self.log_view.appendPlainText(line)
        if self.log_file:
            record = {"ts": time.time(),
                      "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                      "level": level, "msg": msg}
            if extra:
                record.update(extra)
            self.log_file.write(json.dumps(record) + "\n")
            self.log_file.flush()

    # ---------- Écoute ----------
    def toggle_listen(self):
        if self.listener:
            self._stop_recording()
            self.listener.stop()
            self.listener.wait(2000)
            self.listener = None
            self.btn_start.setText("Démarrer l'écoute")
            self.btn_record.setEnabled(False)
            self.statusBar().showMessage("Arrêté")
            self._log("INFO", "Écoute arrêtée")
            self._close_log()
            return

        iface = self.iface_combo.currentText().strip()
        if iface.upper().startswith("TOUTES"):
            iface_ips = [ip for ip in self._local_ips()
                         if not ip.startswith("127.")]
            if not iface_ips:
                self.statusBar().showMessage("Aucune interface IPv4 trouvée")
                return
        else:
            try:
                socket.inet_aton(iface)
            except OSError:
                self.statusBar().showMessage(f"IP invalide : {iface}")
                return
            iface_ips = [iface]

        self._open_log()
        self.session_start = time.time()
        self.total_packets = 0
        self._last_pkt_count = 0
        self.listener = PtpListener(iface_ips, self)
        self.listener.packet.connect(self.on_packet)
        self.listener.error.connect(
            lambda m: (self.statusBar().showMessage(m), self._log("ERROR", m)))
        self.listener.info.connect(lambda m: self._log("INFO", m))
        self.listener.start()
        self.btn_start.setText("Arrêter")
        self.btn_record.setEnabled(True)
        self.statusBar().showMessage(
            f"Écoute {PTP_MCAST}:319/320 sur {', '.join(iface_ips)}")
        self._log("INFO",
                  f"Écoute démarrée sur {iface_ips} ({PTP_MCAST}:319/320)",
                  {"ifaces": iface_ips})

    def _close_log(self):
        if self.log_file:
            self._log("INFO", f"Journal sauvegardé : {self.log_path}")
            self.log_file.close()
            self.log_file = None

    # ---------- Enregistrement ----------
    def toggle_record(self, checked):
        if checked:
            os.makedirs(LOG_DIR, exist_ok=True)
            self.record_path = os.path.join(
                LOG_DIR,
                f"ptp_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
            self.record_file = open(self.record_path, "a", encoding="utf-8")
            self.recording = True
            self.btn_record.setText("■ Stop enregistrement")
            self.btn_record.setStyleSheet("color: #ff4444; font-weight: bold;")
            self._log("INFO", f"Enregistrement démarré : {self.record_path}")
        else:
            self._stop_recording()

    def _stop_recording(self):
        if self.recording and self.record_file:
            self._log("INFO", f"Enregistrement sauvegardé : {self.record_path}")
            self.record_file.close()
        self.recording = False
        self.record_file = None
        self.btn_record.setChecked(False)
        self.btn_record.setText("● Enregistrer")
        self.btn_record.setStyleSheet("")

    # ---------- Traitement ----------
    def on_packet(self, ev):
        self.total_packets += 1

        if self.chk_verbose.isChecked():
            p = ev["parsed"]
            if p:
                self._log("PKT",
                          f"{ev['src_ip']}:{ev['src_port']} → UDP{ev['dst_port']} "
                          f"{p['version']} {p['msg_type']} "
                          f"{ev['len']}o")
            else:
                self._log("PKT",
                          f"{ev['src_ip']}:{ev['src_port']} → UDP{ev['dst_port']} "
                          f"NON-PTP {ev['len']}o")

        if self.recording and self.record_file:
            rec = dict(ev)
            rec["time"] = datetime.fromtimestamp(ev["ts"]).strftime(
                "%Y-%m-%d %H:%M:%S.%f")[:-3]
            rec["raw"] = binascii.hexlify(ev["raw"]).decode()
            if ev["parsed"] is None:
                rec["parsed"] = None
            self.record_file.write(json.dumps(rec) + "\n")
            self.record_file.flush()

        if self.total_packets == 1:
            self._log("INFO",
                      f"Premier paquet reçu : {ev['src_ip']}:{ev['src_port']} "
                      f"→ UDP {ev['dst_port']} ({ev['len']} octets)")

        p = ev["parsed"]
        if p is None:
            try:
                self._handle_malformed(ev)
            except Exception:
                self._log("ERROR", "Exception paquet malformé:\n"
                                   + traceback.format_exc())
            if self.total_packets <= 20:
                self._log("PKT",
                          f"{ev['src_ip']}:{ev['src_port']} → UDP{ev['dst_port']} "
                          f"MALFORMED {ev['len']}o "
                          f"head={binascii.hexlify(ev['raw'][:32]).decode()}")
            return

        # Toujours logger les 20 premiers paquets pour le debug de réception
        if self.total_packets <= 20:
            self._log("PKT",
                      f"{ev['src_ip']}:{ev['src_port']} → UDP{ev['dst_port']} "
                      f"{p['version']} {p['msg_type']} {ev['len']}o "
                      f"head={binascii.hexlify(ev['raw'][:16]).decode()}")

        try:
            key = (p["version"], ev["src_ip"])
            st = self.sources.get(key)
            if st is None:
                st = self.sources[key] = SourceStats()
                self.source_meta[key] = {"domain": p["domain"], "extra": {}}
                self._log("INFO", f"Nouvelle source {p['version']} : "
                                  f"{name_or_ip(ev['src_ip'])} ({p['msg_type']})",
                          {"src_ip": ev["src_ip"], "version": p["version"],
                           "device": device_name(ev["src_ip"])})
                # Domaine non standard = device isolé des autres
                dom_ok = (p["domain"] == "0" if p["version"] == "ptpv1"
                          else p["domain"] == 0)
                if not dom_ok:
                    self._log("ALERT",
                              f"DOMAINE PTP NON STANDARD : {name_or_ip(ev['src_ip'])} "
                              f"émet en {p['version']} domaine '{p['domain']}' — "
                              f"il sera isolé des autres devices",
                              {"src_ip": ev["src_ip"], "domain": str(p["domain"])})
            elif st.reported_silent:
                st.reported_silent = False
                self._log("INFO", f"Source de retour : {name_or_ip(ev['src_ip'])}",
                          {"src_ip": ev["src_ip"]})
            meta = self.source_meta[key]
            meta["domain"] = p["domain"]

            st.update(ev, p)

            if p["version"] == "ptpv1":
                self._handle_v1(ev, p, st)
            else:
                self._handle_v2(ev, p, st)
        except Exception:
            self._log("ERROR", f"Exception traitement paquet de {ev['src_ip']}:\n"
                               + traceback.format_exc())

    def _handle_v1(self, ev, p, st):
        # UUID source (MAC-like) pour identifier le fabricant de l'émetteur
        if p.get("source_uuid"):
            meta = self.source_meta[("ptpv1", ev["src_ip"])]
            meta["extra"]["gm_clock_id"] = p["source_uuid"]
        if p["msg_type"] != "Sync":
            return
        # La courbe ne suit que le leader courant (les Sync d'un éventuel
        # concurrent restent visibles dans la table et le journal)
        is_leader = self.leader_v1 in (None, ev["src_ip"])
        if is_leader:
            self.chart.add(ev["ts"],
                           st.intervals[-1] if st.intervals else 0, "ptpv1")
        if st.intervals and is_leader:
            self._set_card(self.lbl_interval, f"{st.intervals[-1]*1000:.2f} ms")
            stats = st.interval_stats()
            if stats:
                mean, mn, mx, sd = stats
                self._set_card(self.lbl_jitter,
                               f"{mean:.2f}±{sd:.2f} ({mn:.1f}/{mx:.1f}) ms")

        # Leader = source stable qui émet les Sync. Un second émetteur
        # concurrent est une anomalie (split-brain) : ALERT une fois,
        # sans flipper la carte à chaque paquet.
        self._leader_sync_ok = True
        if self.leader_v1 is None:
            self.leader_v1 = ev["src_ip"]
            self.leader_history.append((ev["ts"], None, self.leader_v1))
            self._log("INFO",
                      f"Leader Dante détecté : {name_or_ip(self.leader_v1)}")
        elif ev["src_ip"] != self.leader_v1:
            old_st = self.sources.get(("ptpv1", self.leader_v1))
            if old_st and old_st.last_sync_ts \
                    and ev["ts"] - old_st.last_sync_ts > 5.0:
                # L'ancien leader s'est tu : vraie bascule
                old = self.leader_v1
                self.leader_v1 = ev["src_ip"]
                self.leader_history.append((ev["ts"], old, self.leader_v1))
                self._log("ALERT",
                          f"CHANGEMENT DE LEADER DANTE : {name_or_ip(old)} → "
                          f"{name_or_ip(self.leader_v1)}",
                          {"old_leader": old, "new_leader": self.leader_v1})
            elif ev["src_ip"] not in self._sync_competitors:
                self._sync_competitors.add(ev["src_ip"])
                self._log("ALERT",
                          f"SECONDE SOURCE DE SYNC PTPv1 : "
                          f"{name_or_ip(ev['src_ip'])} émet des Sync en "
                          f"concurrence du leader {name_or_ip(self.leader_v1)} "
                          f"(split-brain possible)",
                          {"src_ip": ev["src_ip"], "leader": self.leader_v1})
        self._set_card(self.lbl_leader, name_or_ip(self.leader_v1))

    def _handle_v2(self, ev, p, st):
        # Courbe bleue : intervalle entre Sync PTPv2
        if p["msg_type"] == "Sync":
            self.chart.add(ev["ts"], st.intervals[-1] if st.intervals else 0,
                           "ptpv2")
        if "gm_clock_id" not in p:
            return
        meta = self.source_meta[("ptpv2", ev["src_ip"])]
        meta["extra"] = {
            "gm_clock_id": p["gm_clock_id"], "p1": p["gm_priority1"],
            "p2": p["gm_priority2"], "class": p["gm_class"],
        }
        meta["last_announce_ts"] = ev["ts"]

        # Détection de changement des propriétés annoncées du GM
        props = (p["gm_clock_id"], p["gm_priority1"], p["gm_priority2"],
                 p["gm_class"], p.get("steps_removed"))
        prev = self._announce_props.get(ev["src_ip"])
        if prev and prev != props:
            self._log("WARN",
                      f"Propriétés GM modifiées par {name_or_ip(ev['src_ip'])} : "
                      f"gm {prev[0]}→{props[0]} p1 {prev[1]}→{props[1]} "
                      f"p2 {prev[2]}→{props[2]} class {prev[3]}→{props[3]} "
                      f"steps {prev[4]}→{props[4]}",
                      {"src_ip": ev["src_ip"], "old": list(prev),
                       "new": list(props)})
        self._announce_props[ev["src_ip"]] = props

        if self.gm_v2 != p["gm_clock_id"]:
            old = self.gm_v2
            # Un annonceur différent qui déclare un autre GM alors que le
            # précédent annonce encore = GM concurrent, pas vraie bascule
            prev_announcer_fresh = any(
                version == "ptpv2" and src != ev["src_ip"]
                and ev["ts"] - m.get("last_announce_ts", 0) < 5.0
                for (version, src), m in self.source_meta.items())
            if old and prev_announcer_fresh \
                    and ev["src_ip"] not in self._gm_competitors:
                self._gm_competitors.add(ev["src_ip"])
                self._log("ALERT",
                          f"GM PTPv2 CONCURRENT : {name_or_ip(ev['src_ip'])} "
                          f"annonce {p['gm_clock_id']} alors que {old} "
                          f"est déjà annoncé",
                          {"src_ip": ev["src_ip"], "gm": p["gm_clock_id"],
                           "current_gm": old})
            else:
                self.gm_v2 = p["gm_clock_id"]
                if old:
                    self._log("ALERT",
                              f"CHANGEMENT DE GRANDMASTER PTPv2 : {old} → "
                              f"{self.gm_v2}",
                              {"old_gm": old, "new_gm": self.gm_v2})
        manuf = oui.oui_lookup(p["gm_clock_id"])
        gm_dev = clock_id_name(p["gm_clock_id"])
        cls = p["gm_class"]
        cls_txt = PTPV2_CLOCK_CLASSES.get(cls, "?")
        self._set_card(
            self.lbl_gm,
            f"{p['gm_clock_id']}\n{gm_dev or manuf} — class {cls} ({cls_txt})\n"
            f"p1={p['gm_priority1']} p2={p['gm_priority2']}")

    def _handle_malformed(self, ev):
        ev["reason"] = "parse PTP impossible (ni v1 ni v2, ou trop court)"
        self.malformed.append(ev)
        n = len(self.malformed)
        self._set_card(self.lbl_malformed, str(n), color="#ff6666")

        row = self.tbl_malformed.rowCount()
        self.tbl_malformed.insertRow(row)
        cells = [
            fmt_ts(ev["ts"]), ev["src_ip"], str(ev["dst_port"]), str(ev["len"]),
            binascii.hexlify(ev["raw"][:32]).decode(),
        ]
        for c, val in enumerate(cells):
            self.tbl_malformed.setItem(row, c, QTableWidgetItem(val))
        self._log("MALFORMED",
                  f"Paquet malformé de {ev['src_ip']}:{ev['src_port']} "
                  f"(UDP {ev['dst_port']}, {ev['len']} o)",
                  {"src_ip": ev["src_ip"], "dst_port": ev["dst_port"],
                   "len": ev["len"], "hex": binascii.hexlify(ev["raw"]).decode()})

    # ---------- Rafraîchissement tables ----------
    def _refresh_tables(self):
        try:
            self._refresh_tables_inner()
        except Exception:
            self._log("ERROR", "Exception rafraîchissement UI:\n"
                               + traceback.format_exc())

    def _refresh_tables_inner(self):
        now = time.time()

        # Débit de paquets + alerte "aucun paquet"
        if self.listener:
            rate = self.total_packets - getattr(self, "_last_pkt_count", 0)
            self._last_pkt_count = self.total_packets
            iface_txt = self.iface_combo.currentText().strip()
            base = f"Écoute {PTP_MCAST}:319/320 sur {iface_txt}"
            if self.total_packets == 0 and now - (self.session_start or now) > 6:
                self.statusBar().showMessage(
                    f"{base} — AUCUN PAQUET REÇU. Vérifier : "
                    "pare-feu (autoriser PTPMonitor.exe), "
                    "bonne interface sélectionnée (ou TOUTES), "
                    "et tester avec Wireshark pour confirmer l'arrivée des paquets.")
                if not getattr(self, "_warned_nopkt", False):
                    self._warned_nopkt = True
                    self._log("WARN",
                              "Aucun paquet UDP 319/320 reçu après 6s — "
                              "cause probable : pare-feu ou mauvaise interface")
            else:
                self.statusBar().showMessage(
                    f"{base} — {rate} pkt/s (total {self.total_packets})")

            # Heartbeat journal toutes les 10s pour rendre l'activité visible
            last_hb = getattr(self, "_last_heartbeat", 0)
            if now - last_hb >= 10:
                self._last_heartbeat = now
                self._log("STATUS",
                          f"{self.total_packets} paquets reçus, "
                          f"{len([s for s in self.sources.values() if now - s.last <= 30])} sources actives, "
                          f"{len(self.malformed)} malformés")

        # Détection de silence : source qui se tait (>30s sans paquet)
        if self.listener:
            for (version, src), s in self.sources.items():
                if not s.reported_silent and now - s.last > 30:
                    s.reported_silent = True
                    self._log("WARN",
                              f"SOURCE SILENCIEUSE : {name_or_ip(src)} "
                              f"({version}) — aucun paquet depuis "
                              f"{now - s.last:.0f}s",
                              {"src_ip": src, "version": version,
                               "silent_for_s": round(now - s.last)})

            # Leader Dante : Sync attendu ~4x/s — alerte si >2s sans Sync
            if self.leader_v1:
                st = self.sources.get(("ptpv1", self.leader_v1))
                if st and st.last_sync_ts and now - st.last_sync_ts > 2.0:
                    if getattr(self, "_leader_sync_ok", True):
                        self._leader_sync_ok = False
                        self._log("ALERT",
                                  f"SYNC PTPv1 INTERROMPU : leader "
                                  f"{name_or_ip(self.leader_v1)} n'émet plus "
                                  f"depuis {now - st.last_sync_ts:.1f}s",
                                  {"leader": self.leader_v1})

            # GM v2 : Announce attendu ~1/s — alerte si >4s sans annonce
            for (version, src), meta in self.source_meta.items():
                if version != "ptpv2":
                    continue
                last_ann = meta.get("last_announce_ts")
                if not last_ann:
                    continue
                if now - last_ann > 4.0 and not meta.get("announce_warned"):
                    meta["announce_warned"] = True
                    self._log("ALERT",
                              f"ANNOUNCE PTPv2 INTERROMPU : {name_or_ip(src)} "
                              f"muet depuis {now - last_ann:.1f}s",
                              {"src_ip": src})
                elif now - last_ann <= 4.0 and meta.get("announce_warned"):
                    meta["announce_warned"] = False
                    self._log("INFO",
                              f"Announce PTPv2 de retour : {name_or_ip(src)}",
                              {"src_ip": src})

        active = {k: s for k, s in self.sources.items() if now - s.last <= 30}

        # Réutiliser les lignes existantes
        self.tbl_sources.setRowCount(len(active))
        for r, ((version, src), s) in enumerate(sorted(active.items())):
            meta = self.source_meta.get((version, src), {})
            clock_id = meta.get("extra", {}).get("gm_clock_id", src)
            istats = s.interval_stats()
            istr = f"{istats[0]:.1f}±{istats[3]:.1f} ms" if istats else "—"
            vals = [version, str(meta.get("domain", "?")), src,
                    device_name(src) or oui.oui_lookup(clock_id),
                    str(s.count), f"{s.rate():.2f}",
                    str(s.seq_gaps), istr, fmt_ts(s.last, with_ms=False)]
            for c, val in enumerate(vals):
                item = self.tbl_sources.item(r, c)
                if item is None:
                    item = QTableWidgetItem(val)
                    self.tbl_sources.setItem(r, c, item)
                else:
                    item.setText(val)
            # Surligner les gaps de séquence
            if s.seq_gaps:
                self.tbl_sources.item(r, 6).setForeground(QColor("#ff9944"))
        self._set_card(self.lbl_sources, str(len(active)))

    def _show_source_detail(self):
        row = self.tbl_sources.currentRow()
        if row < 0:
            return
        version = self.tbl_sources.item(row, 0).text()
        src = self.tbl_sources.item(row, 2).text()
        s = self.sources.get((version, src))
        if not s:
            return
        meta = self.source_meta.get((version, src), {})
        istats = s.interval_stats()
        lines = [
            f"Source : {src}   ({version}, domaine {meta.get('domain', '?')})",
            f"Vu : {datetime.fromtimestamp(s.first).strftime('%H:%M:%S')} → "
            f"{datetime.fromtimestamp(s.last).strftime('%H:%M:%S')}",
            f"Messages : {s.count}   taux : {s.rate():.2f}/s",
            f"Types : {dict(s.msg_types)}",
            f"Séquence : {s.seq_gaps} gaps, {s.seq_dups} doublons",
        ]
        if istats:
            mean, mn, mx, sd = istats
            lines.append(f"Intervalle Sync : moy {mean:.2f} ms, min {mn:.2f}, "
                         f"max {mx:.2f}, σ {sd:.2f} (fenêtre {len(s.intervals)})")
        extra = meta.get("extra", {})
        if extra:
            cls = extra.get('class')
            cls_txt = PTPV2_CLOCK_CLASSES.get(cls, "?")
            lines.append(f"GM : {extra.get('gm_clock_id')} "
                         f"({oui.oui_lookup(extra.get('gm_clock_id'))})  "
                         f"p1={extra.get('p1')} p2={extra.get('p2')} "
                         f"class={cls} ({cls_txt})")
        self.source_detail.setPlainText("\n".join(lines))

    def _show_malformed_detail(self):
        row = self.tbl_malformed.currentRow()
        if 0 <= row < len(self.malformed):
            self.malformed_detail.setPlainText(hexdump(self.malformed[row]["raw"]))

    def _open_malformed(self, _):
        row = self.tbl_malformed.currentRow()
        if 0 <= row < len(self.malformed):
            MalformedDialog(self.malformed[row], self).exec()

    # ---------- Exports ----------
    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Exporter les paquets malformés", "ptp_malformed.csv",
            "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "src_ip", "src_port", "dst_port",
                        "length", "hex"])
            for ev in self.malformed:
                w.writerow([
                    datetime.fromtimestamp(ev["ts"]).isoformat(),
                    ev["src_ip"], ev["src_port"], ev["dst_port"],
                    ev["len"], binascii.hexlify(ev["raw"]).decode()])
        self.statusBar().showMessage(f"Exporté : {path}")

    def save_report(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Enregistrer le rapport de session", "ptp_rapport.txt",
            "Texte (*.txt)")
        if not path:
            return
        now = time.time()
        dur = (now - self.session_start) if self.session_start else 0
        lines = [
            "=" * 60,
            "RAPPORT DE SESSION PTP MONITOR",
            f"Généré : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Durée d'écoute : {dur/60:.1f} min   Paquets : {self.total_packets}",
            "=" * 60,
            "",
            f"Leader Dante PTPv1 : {self.leader_v1 or '—'}",
            f"Grandmaster PTPv2 : {self.gm_v2 or '—'} "
            f"({oui.oui_lookup(self.gm_v2) if self.gm_v2 else ''})",
            "",
            "CHANGEMENTS DE LEADER :",
        ]
        for ts, old, new in self.leader_history:
            lines.append(f"  {fmt_ts(ts)}  {old or '(début)'} → {new}")
        if not self.leader_history:
            lines.append("  (aucun)")
        lines += ["", "SOURCES :"]
        for (version, src), s in sorted(self.sources.items()):
            meta = self.source_meta.get((version, src), {})
            istats = s.interval_stats()
            istr = (f"moy {istats[0]:.1f} min {istats[1]:.1f} max {istats[2]:.1f} "
                    f"σ {istats[3]:.1f} ms" if istats else "—")
            lines.append(
                f"  {name_or_ip(src):<46} {version:<6} dom={meta.get('domain','?')} "
                f"msgs={s.count} rate={s.rate():.2f}/s gaps={s.seq_gaps} "
                f"dup={s.seq_dups} intervalle: {istr}")
        lines += ["", f"PAQUETS MALFORMÉS : {len(self.malformed)}"]
        counts = Counter(ev["src_ip"] for ev in self.malformed)
        for src, n in counts.most_common():
            lines.append(f"  {src:<16} {n} paquets")
        if self.malformed:
            lines.append("")
            for ev in self.malformed[:50]:
                lines.append(f"  {fmt_ts(ev['ts'])} {ev['src_ip']}:{ev['src_port']} "
                             f"UDP{ev['dst_port']} {ev['len']}o "
                             f"{binascii.hexlify(ev['raw'][:24]).decode()}")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self.statusBar().showMessage(f"Rapport enregistré : {path}")
        self._log("INFO", f"Rapport enregistré : {path}")

    def closeEvent(self, e):
        self._stop_recording()
        if self.listener:
            self.listener.stop()
            self.listener.wait(2000)
        self._close_log()
        e.accept()
