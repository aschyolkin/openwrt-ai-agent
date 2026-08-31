from __future__ import annotations

import re
from dataclasses import dataclass

from .llm_client import LLMClient


MUTATING_WORDS = re.compile(
    r"\b(добавь|добавить|удали|удалить|открой|открыть|закрой|закрыть|"
    r"перезапусти|перезапустить|рестарт|reload|restart|включи|включить|"
    r"выключи|выключить|измени|изменить|переключи|переключить|заблокируй|"
    r"разблокируй|восстанови|откати|rollback|установи|обнови|создай|"
    r"add|delete|remove|open|close|enable|disable|change|switch|apply)\b",
    re.IGNORECASE,
)

COMPLEX_WORDS = re.compile(
    r"\b(почему|объясни|объяснить|разберись|разобраться|проанализируй|анализ|"
    r"сравни|сравнить|причина|причины|логика|спроектируй|исследуй|"
    r"why|explain|analyze|compare|design|investigate)\b",
    re.IGNORECASE,
)

DIAGNOSTIC_WORDS = re.compile(
    r"\b(почему|разберись|разобраться|проанализируй|анализ|причина|причины|"
    r"исследуй|why|analyze|investigate)\b",
    re.IGNORECASE,
)

READ_ONLY_HINTS = re.compile(
    r"(покажи|проверь|какая|какой|какие|что работает|статус|состояние|"
    r"нагрузк|температур|правил|файрвол|firewall|nft|соединени|conntrack|"
    r"маршрут|routing|нод|node|интерфейс|interface|dns|telegram|телеграм|"
    r"discord|youtube|chatgpt|claude|github|zapret|nfqws|adguard|sing-box|"
    r"netshift|процесс|памят|диск|порт|слушает|кто ты|помощ|привет|/start|"
    r"аудит|audit|менялось|что мы дела|нормальн|обычн|аномал|baseline)",
    re.IGNORECASE,
)

# "проверь"/"статус" и т.п. сами по себе не несут темы — часто это короткое
# продолжение диалога ("проверь ещё раз"), которое молча теряет контекст
# предыдущей реплики при пословной маршрутизации. Раньше такие сообщения
# получали общий (и часто не по теме) набор из 3 tools на дешёвой модели —
# из-за этого модель однажды уверенно ответила про несуществующие ноды VPN,
# имея доступ только к sys_resource_usage/net_interfaces_status/sys_inspect.
GENERIC_CHECK_WORDS = re.compile(r"статус|состояние|покажи|проверь", re.IGNORECASE)


@dataclass(frozen=True)
class ModelRoute:
    client: LLMClient
    route: str
    reason: str
    tool_names: tuple[str, ...] | None = None


def read_only_tools_for(message: str, limit: int = 5) -> tuple[str, ...]:
    """Return a small topic-specific schema set for the inexpensive model."""
    text = str(message).casefold()
    tools: list[str] = []

    def add(*names: str) -> None:
        for name in names:
            if name not in tools:
                tools.append(name)

    if re.search(r"температур|нагрузк|cpu|памят|memory|uptime|диск", text):
        add("sys_resource_usage")
    if re.search(r"нормальн|обычн|аномал|baseline|много ли|мало ли|это много|это мало", text):
        add("sys_baseline_compare")
    if re.search(r"файрвол|firewall|nft|маршрут|routing|route|policy|процесс|порт|слуша|conntrack|соединени", text):
        add("sys_inspect")
    if re.search(r"интерфейс|interface|rx|tx|сетев", text):
        add("net_interfaces_status", "net_device_stats", "sys_inspect")
    if re.search(r"dns|домен|резолв|adguard|agh", text):
        add("net_dns_check", "agh_service_status", "agh_check_domain_blocked", "agh_config_read", "agh_diagnose_domain")
    if re.search(r"telegram|телеграм|discord|youtube|chatgpt|claude|github", text):
        add("netshift_service_health", "netshift_check_domain_routing", "net_dns_check", "singbox_connections")
    if re.search(r"netshift|sing.box|vpn|прокс|нод|node|стран[ауеы]", text):
        add("netshift_service_health", "netshift_config_show", "netshift_check_domain_routing", "singbox_active_proxies", "singbox_connections")
    if re.search(r"zapret|nfqws|dpi", text):
        add("zapret_service_status", "zapret_config_show", "zapret_dpi_check", "zapret_logs_tail")
    if re.search(r"лог|log", text):
        add("sys_logread")
    if re.search(r"backup|резервн", text):
        add("backup_list")
    if re.search(r"аудит|audit|что мен[яи]|истори[яи] измен|что дела(л|ли)|что мы дела", text):
        add("agent_audit_log")
    return tuple(tools[:limit])


def complex_read_only_tools_for(message: str) -> tuple[str, ...]:
    """Allow DeepSeek enough diagnostics without resending every mutating schema."""
    tools = list(read_only_tools_for(message, limit=8))

    def add(*names: str) -> None:
        for name in names:
            if name not in tools:
                tools.append(name)

    if DIAGNOSTIC_WORDS.search(message):
        add("sys_logread")
        if len(tools) <= 1:
            add("sys_inspect", "net_interfaces_status", "net_dns_check", "netshift_service_health")
    return tuple(tools[:8])


class ModelRouter:
    """Conservative router: unknown or potentially mutating requests use DeepSeek."""

    def __init__(self, simple_client: LLMClient, complex_client: LLMClient, max_simple_chars: int = 420):
        self.simple_client = simple_client
        self.complex_client = complex_client
        self.max_simple_chars = max_simple_chars

    def select(self, message: str) -> ModelRoute:
        normalized = " ".join(str(message).strip().split())
        if MUTATING_WORDS.search(normalized):
            return ModelRoute(self.complex_client, "complex", "mutation_marker")
        if COMPLEX_WORDS.search(normalized):
            return ModelRoute(
                self.complex_client, "complex_read_only", "analysis_marker",
                complex_read_only_tools_for(normalized),
            )
        if len(normalized) > self.max_simple_chars or "\n" in str(message):
            if READ_ONLY_HINTS.search(normalized):
                return ModelRoute(
                    self.complex_client, "complex_read_only", "long_read_only",
                    complex_read_only_tools_for(normalized),
                )
            return ModelRoute(self.complex_client, "complex", "long_or_multiline")
        if READ_ONLY_HINTS.search(normalized):
            tools = read_only_tools_for(normalized)
            if not tools and GENERIC_CHECK_WORDS.search(normalized):
                # Generic "проверь"/"статус" without any topic keyword — don't
                # guess a narrow (possibly wrong-topic) tool set on the cheap
                # model; give the strong model the full toolset instead.
                return ModelRoute(self.complex_client, "complex", "read_only_generic_check_without_topic")
            return ModelRoute(
                self.simple_client, "simple_read_only", "recognized_read_only", tools,
            )
        return ModelRoute(self.complex_client, "complex", "conservative_default")
