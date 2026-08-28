from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


DEFAULT_METRICS_PATH = "/var/lib/ai-agent/metrics.sqlite"

METRIC_COLUMNS = (
    "cpu_percent", "mem_available_percent", "conntrack_count",
    "wan_latency_ms", "packet_loss_percent", "lan_client_count",
)


class MetricsStore:
    def __init__(self, path: str = DEFAULT_METRICS_PATH):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, timeout=15, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._initialize()

    def _initialize(self) -> None:
        with self._lock, self.connection:
            self.connection.execute("PRAGMA journal_mode=WAL")
            # NORMAL (вместо дефолтного FULL) заметно снижает число fsync при
            # редкой записи (сэмплер раз в 10 минут) — рекомендуемая SQLite
            # комбинация с WAL; риск — потеря последней незакоммиченной
            # транзакции при внезапном отключении питания, для метрик не критично.
            self.connection.execute("PRAGMA synchronous=NORMAL")
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metrics_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    cpu_percent REAL,
                    mem_available_percent REAL,
                    conntrack_count INTEGER,
                    wan_latency_ms REAL,
                    packet_loss_percent REAL,
                    lan_client_count INTEGER
                );
                CREATE INDEX IF NOT EXISTS metrics_samples_ts ON metrics_samples(ts);
                """
            )

    def insert_sample(self, sample: dict[str, Any]) -> None:
        ts = int(sample.get("ts") or time.time())
        values = tuple(sample.get(column) for column in METRIC_COLUMNS)
        with self._lock, self.connection:
            self.connection.execute(
                f"INSERT INTO metrics_samples(ts, {', '.join(METRIC_COLUMNS)}) "
                f"VALUES (?, {', '.join('?' for _ in METRIC_COLUMNS)})",
                (ts, *values),
            )

    def recent_samples(self, metric: str, since_ts: int, until_ts: int | None = None) -> list[float]:
        if metric not in METRIC_COLUMNS:
            raise ValueError(f"unknown metric: {metric}")
        query = f"SELECT {metric} FROM metrics_samples WHERE ts >= ? AND {metric} IS NOT NULL"
        params: list[Any] = [since_ts]
        if until_ts is not None:
            query += " AND ts <= ?"
            params.append(until_ts)
        with self._lock:
            rows = self.connection.execute(query, params).fetchall()
        return [row[0] for row in rows]

    def sample_count(self, metric: str, since_ts: int) -> int:
        return len(self.recent_samples(metric, since_ts))

    def cleanup(self, retention_days: int = 14) -> int:
        cutoff = int(time.time()) - retention_days * 86400
        with self._lock, self.connection:
            cursor = self.connection.execute("DELETE FROM metrics_samples WHERE ts < ?", (cutoff,))
            return cursor.rowcount
