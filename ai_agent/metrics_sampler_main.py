from __future__ import annotations

import fcntl
import time

from .adapters import UCIAdapter, load_agent_config
from .command import CommandRunner
from .metrics import sample_current_metrics
from .storage.metrics import MetricsStore


def main() -> None:
    with open("/var/run/ai-agent-metrics-sample.lock", "w", encoding="ascii") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        config = load_agent_config(UCIAdapter(CommandRunner()))
        store = MetricsStore(config.metrics_path)
        sample = sample_current_metrics()
        sample["ts"] = int(time.time())
        store.insert_sample(sample)
        store.cleanup(retention_days=14)


if __name__ == "__main__":
    main()
