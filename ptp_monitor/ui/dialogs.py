"""Dialogue détaillé d'un paquet malformé (métadonnées + hexdump)."""

from datetime import datetime

from PySide6.QtWidgets import QDialog, QPlainTextEdit, QVBoxLayout

from ..parser import hexdump


class MalformedDialog(QDialog):
    def __init__(self, event, parent=None):
        super().__init__(parent)
        self.setWindowTitle(
            f"Paquet malformé — {event['src_ip']}:{event['src_port']} "
            f"→ UDP {event['dst_port']}")
        self.resize(720, 520)
        lay = QVBoxLayout(self)
        meta = (f"Reçu : {datetime.fromtimestamp(event['ts']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n"
                f"Source : {event['src_ip']}:{event['src_port']}   "
                f"Longueur : {event['len']} octets\n"
                f"Raison : {event.get('reason', 'parse PTP impossible')}")
        info = QPlainTextEdit(meta)
        info.setReadOnly(True)
        info.setMaximumHeight(84)
        lay.addWidget(info)
        dump = QPlainTextEdit(hexdump(event["raw"]))
        dump.setReadOnly(True)
        lay.addWidget(dump)
