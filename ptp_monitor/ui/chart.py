"""Graphe temps réel de l'intervalle entre Sync PTPv1."""

from collections import deque

from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QWidget


class IntervalChart(QWidget):
    """Graphe : intervalle entre Sync PTPv1 (ms) en fonction du temps."""

    def __init__(self, parent=None, max_points=1200):
        super().__init__(parent)
        self.samples = deque(maxlen=max_points)  # (ts, interval_ms)
        self.setMinimumHeight(200)

    def add(self, ts, interval_s):
        self.samples.append((ts, interval_s * 1000.0))
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(24, 24, 24))
        w, h = self.width(), self.height()
        margin = 46
        p.setPen(QPen(QColor(140, 140, 140)))
        p.drawText(6, 14, "Intervalle Sync (ms)")

        if len(self.samples) < 2:
            p.drawText(margin + 10, h // 2, "En attente de données...")
            p.end()
            return

        vals = [v for _, v in self.samples]
        vmed = sorted(vals)[len(vals) // 2]
        vmax = max(max(vals), vmed * 2) * 1.1  # scale inclut les outliers
        t0, t1 = self.samples[0][0], self.samples[-1][0]
        span = max(t1 - t0, 0.001)

        p.setPen(QPen(QColor(70, 70, 70)))
        p.drawLine(margin, 10, margin, h - 24)
        p.drawLine(margin, h - 24, w - 4, h - 24)
        for frac in (0, 0.5, 1.0):
            y = (h - 24) - (h - 34) * frac
            p.drawText(4, y + 4, f"{vmax * frac:.1f}")
            p.drawLine(margin, y, w - 4, y)
        p.drawText(w - 130, h - 8, f"fenêtre {span:.0f}s")

        p.setPen(QPen(QColor(80, 200, 120), 1.5))
        prev = None
        for ts, v in self.samples:
            x = margin + (w - margin - 8) * (ts - t0) / span
            y = (h - 24) - (h - 34) * min(v / vmax, 1.0)
            if prev is not None:
                p.drawLine(prev[0], prev[1], x, y)
            prev = (x, y)
        p.end()
