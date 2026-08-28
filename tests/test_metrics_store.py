from __future__ import annotations

import time
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from ai_agent.storage.metrics import MetricsStore


class MetricsStoreTests(unittest.TestCase):
    def _store(self, tmp_dir: str) -> MetricsStore:
        return MetricsStore(str(Path(tmp_dir) / "metrics.sqlite"))

    def test_insert_and_recent_samples(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            now = int(time.time())
            store.insert_sample({"ts": now, "cpu_percent": 10.0, "conntrack_count": 100})
            store.insert_sample({"ts": now, "cpu_percent": 20.0, "conntrack_count": 200})
            self.assertEqual(sorted(store.recent_samples("cpu_percent", now - 10)), [10.0, 20.0])
            self.assertEqual(store.sample_count("cpu_percent", now - 10), 2)

    def test_recent_samples_filters_by_since_ts(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            now = int(time.time())
            store.insert_sample({"ts": now - 1000, "cpu_percent": 5.0})
            store.insert_sample({"ts": now, "cpu_percent": 15.0})
            self.assertEqual(store.recent_samples("cpu_percent", now - 10), [15.0])

    def test_recent_samples_skips_null_values(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            now = int(time.time())
            store.insert_sample({"ts": now, "cpu_percent": None})
            store.insert_sample({"ts": now, "cpu_percent": 30.0})
            self.assertEqual(store.recent_samples("cpu_percent", now - 10), [30.0])

    def test_cleanup_removes_old_rows(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            now = int(time.time())
            store.insert_sample({"ts": now - 20 * 86400, "cpu_percent": 1.0})
            store.insert_sample({"ts": now, "cpu_percent": 2.0})
            removed = store.cleanup(retention_days=14)
            self.assertEqual(removed, 1)
            self.assertEqual(store.recent_samples("cpu_percent", 0), [2.0])

    def test_unknown_metric_raises(self):
        with TemporaryDirectory() as tmp:
            store = self._store(tmp)
            with self.assertRaises(ValueError):
                store.recent_samples("not_a_metric", 0)


if __name__ == "__main__":
    unittest.main()
