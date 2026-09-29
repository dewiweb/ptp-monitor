"""Statistiques par source PTP (compteurs, séquences, intervalles Sync)."""

import math
from collections import Counter, deque

from .constants import INTERVAL_WINDOW


class SourceStats:
    """Statistiques avancées pour une source PTP."""

    def __init__(self):
        self.count = 0
        self.first = 0.0
        self.last = 0.0
        self.msg_types = Counter()
        self.seq_gaps = 0
        self.seq_dups = 0
        self.last_seq = None
        self.intervals = deque(maxlen=INTERVAL_WINDOW)  # intervalles entre Sync (s)
        self.last_sync_ts = None
        self.reported_silent = False

    def update(self, ev, p):
        self.count += 1
        self.last = ev["ts"]
        if not self.first:
            self.first = ev["ts"]
        self.msg_types[p["msg_type"]] += 1

        seq = p.get("sequence_id")
        if seq is not None:
            if self.last_seq is not None:
                if seq == self.last_seq:
                    self.seq_dups += 1
                elif seq != (self.last_seq + 1) % 65536:
                    self.seq_gaps += 1
            self.last_seq = seq

        if p["msg_type"] == "Sync" and self.last_sync_ts is not None:
            self.intervals.append(ev["ts"] - self.last_sync_ts)
        if p["msg_type"] == "Sync":
            self.last_sync_ts = ev["ts"]

    def interval_stats(self):
        """Retourne (moy, min, max, écart-type) en ms, ou None."""
        if len(self.intervals) < 2:
            return None
        ms = [i * 1000 for i in self.intervals]
        mean = sum(ms) / len(ms)
        var = sum((x - mean) ** 2 for x in ms) / len(ms)
        return mean, min(ms), max(ms), math.sqrt(var)

    def rate(self):
        span = self.last - self.first
        return self.count / span if span > 1 else 0.0
