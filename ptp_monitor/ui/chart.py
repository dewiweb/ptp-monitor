"""Graphe temps réel des intervalles entre Sync (PTPv1 et PTPv2)."""

from collections import deque

from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QWidget

SERIES = {
    "ptpv1": QColor(80, 200, 120),   # vert — Dante
    "ptpv2": QColor(100, 160, 255),  # bleu — AES67/Ravenna
}


class IntervalChart(QWidget):
    """Graphe : intervalle entre Sync (ms) en fonction du temps,
    une courbe par version PTP."""

    def __init__(self, parent=None, max_points=1200):
        super().__init__(parent)
        self.samples = {k: deque(maxlen=max_points) for k in SERIES}
        self.setMinimumHeight(200)

    def add(self, ts, interval_s, version="ptpv1"):
        if version in self.samples:
            self.samples[version].append((ts, interval_s * 1000.0))
            self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(24, 24, 24))
        w, h = self.width(), self.height()
        margin = 46
        p.setPen(QPen(QColor(140, 140, 140)))
        p.drawText(6, 14, "Intervalle Sync (ms)")

        # Légende
        lx = w - 200
        for version, color in SERIES.items():
            p.setPen(QPen(color))
            p.drawText(lx, 14, f"■ {version}")
            lx += 70

        all_samples = [s for series in self.samples.values() for s in series]
        if len(all_samples) < 2:
            p.setPen(QPen(QColor(140, 140, 140)))
            p.drawText(margin + 10, h // 2, "En attente de données...")
            p.end()
            return

        vals = [v for _, v in all_samples]
        vmed = sorted(vals)[len(vals) // 2]
        vmax = max(max(vals), vmed * 2) * 1.1  # scale inclut les outliers
        t0 = min(s[0][0] for s in self.samples.values() if s)
        t1 = max(s[-1][0] for s in self.samples.values() if s)
        span = max(t1 - t0, 0.001)

        p.setPen(QPen(QColor(70, 70, 70)))
        p.drawLine(margin, 10, margin, h - 24)
        p.drawLine(margin, h - 24, w - 4, h - 24)
        for frac in (0, 0.5, 1.0):
            y = (h - 24) - (h - 34) * frac
            p.drawText(4, y + 4, f"{vmax * frac:.1f}")
            p.drawLine(margin, y, w - 4, y)
        p.drawText(margin + 4, h - 8, f"fenêtre {span:.0f}s")

        for version, color in SERIES.items():
            p.setPen(QPen(color, 1.5))
            prev = None
            for ts, v in self.samples[version]:
                x = margin + (w - margin - 8) * (ts - t0) / span
                y = (h - 24) - (h - 34) * min(v / vmax, 1.0)
                if prev is not None:
                    p.drawLine(prev[0], prev[1], x, y)
                prev = (x, y)
        p.end()
