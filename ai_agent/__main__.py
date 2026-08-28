from __future__ import annotations

import logging

from .api_server import serve
from .core import build_core


def main() -> None:
    core = build_core()
    logging.basicConfig(
        level=getattr(logging, core.config.log_level, logging.INFO),
        format="ai-agent[%(process)d]: %(levelname)s %(name)s: %(message)s",
    )
    serve(core)


if __name__ == "__main__":
    main()

