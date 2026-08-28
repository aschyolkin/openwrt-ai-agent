from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .adapters import UBusAdapter, UCIAdapter
from .command import CommandRunner
from .config import AgentConfig


@dataclass
class ToolContext:
    config: AgentConfig
    runner: CommandRunner
    uci: UCIAdapter
    ubus: UBusAdapter
    http: Any
    backups: Any = None

