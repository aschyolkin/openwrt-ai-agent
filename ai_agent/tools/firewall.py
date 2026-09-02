from __future__ import annotations

import difflib
import re
from typing import Any

from ..adapters import state_hashes
from ..command import first_executable
from ..errors import ValidationError
from ..models import MutationPlan, VerificationResult
from ..registry import ExecClass, tool
from .common import port_listening, service_action

# Ports the agent will never open from WAN even with explicit user confirmation:
# router management/administration surfaces. Everything else is left to human
# review of the plan diff before it is applied, same as other mutating tools.
_FORBIDDEN_PORTS = {22, 23, 53, 80, 443, 6653, 8291, 9090}

PROTOCOLS = ("tcp", "udp", "tcp udp")


def _section_name(proto: str, port: int) -> str:
    return f"ai_agent_wan_{proto.replace(' ', '_')}_{port}"

def _protocol_value(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    return str(value or "")


def _is_wan_accept_rule(values: dict[str, Any], proto: str, port: int) -> bool:
    """Match only the exact IPv4 rule shape created by this agent."""
    return (
        values.get(".type") == "rule"
        and str(values.get("src", "")) == "wan"
        and str(values.get("target", "")) == "ACCEPT"
        and _protocol_value(values.get("proto")) == proto
        and str(values.get("dest_port", "")) == str(port)
        and str(values.get("family", "")) == "ipv4"
    )


def _existing_wan_accept_rule(sections: dict[str, dict[str, Any]], proto: str, port: int) -> str | None:
    for name, values in sections.items():
        if _is_wan_accept_rule(values, proto, port):
            return name
    return None


def _nft_rule_present(context, section: str) -> bool:
    executable = first_executable(("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"))
    result = context.runner.run([executable, "list", "ruleset"], timeout=15, max_output_bytes=1024 * 1024)
    if not result.ok:
        return False
    pattern = re.compile(r'comment\s+"!fw4:\s*' + re.escape(section) + r'"')
    return any(pattern.search(line) and "accept" in line for line in result.stdout.splitlines())


def _open_apply(context, plan: MutationPlan) -> dict[str, Any]:
    section = plan.prepared["section"]
    context.uci.create_section("firewall", section, "rule")
    context.uci.set("firewall", section, "name", section)
    context.uci.set("firewall", section, "src", "wan")
    context.uci.set("firewall", section, "proto", plan.prepared["proto"])
    context.uci.set("firewall", section, "dest_port", str(plan.prepared["port"]))
    context.uci.set("firewall", section, "target", "ACCEPT")
    context.uci.set("firewall", section, "family", "ipv4")
    context.uci.commit("firewall")
    reload_result = service_action(context, "firewall", "reload", 30)
    return {"uci": f"firewall.{section}", "reload": reload_result}


def _open_verify(context, plan: MutationPlan) -> VerificationResult:
    section = plan.prepared["section"]
    sections = context.uci.get_all("firewall")
    uci_ok = section in sections and _is_wan_accept_rule(
        sections[section], str(plan.prepared["proto"]), int(plan.prepared["port"]),
    )
    nft_ok = _nft_rule_present(context, section)
    listening = port_listening(int(plan.prepared["port"]), str(plan.prepared["proto"]))
    ok = uci_ok and nft_ok
    checks = {"uci_rule_present": uci_ok, "nft_accept_rule_present": nft_ok, "listener_present": listening}
    if not ok:
        message = "Проверка не пройдена"
    elif listening:
        message = "Порт открыт и правило активно в nftables"
    else:
        message = (
            "Правило добавлено и активно в nftables, но на этом порту на роутере никто не слушает — "
            "снаружи подключение будет отклонено, пока не запущен сервис на этом порту"
        )
    return VerificationResult(ok, checks, message)


def _open_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    context.backups.restore(backup_dir)
    service_action(context, "firewall", "reload", 30)
    section = plan.prepared["section"]
    sections = context.uci.get_all("firewall")
    removed = section not in sections
    nft_removed = not _nft_rule_present(context, section)
    ok = removed and nft_removed
    checks = {"uci_rule_removed": removed, "nft_rule_removed": nft_removed}
    return VerificationResult(ok, checks, "Откат выполнен, порт закрыт" if ok else "Откат требует ручной проверки")


@tool(
    name="firewall_open_wan_port",
    description=(
        "Открыть TCP/UDP-порт на роутере из WAN (интернета) для сервиса, запущенного на самом роутере: "
        "создаёт firewall-правило src=wan target=ACCEPT на заданный порт. Не для port-forward на устройства LAN. "
        "Правило само по себе НЕ поднимает сервис: если на порту никто не слушает, снаружи будет отказ. "
        "Для доступа к SSH роутера из интернета используй ssh_open_wan_access, а не этот tool."
    ),
    parameters={
        "type": "object",
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "proto": {"type": "string", "enum": list(PROTOCOLS)},
        },
        "required": ["port", "proto"], "additionalProperties": False,
    },
    exec_class=ExecClass.MUTATING,
    sensitivity="high",
    network_side_effect="wan_exposure",
    applier=_open_apply,
    verifier=_open_verify,
    rollback=_open_rollback,
)
def firewall_open_wan_port(context, arguments: dict[str, Any]) -> MutationPlan:
    port = int(arguments["port"])
    proto = str(arguments["proto"])
    if port in _FORBIDDEN_PORTS:
        raise ValidationError("Этот порт зарезервирован под управление роутером и не открывается из WAN", {"port": port})
    section = _section_name(proto, port)
    sections = context.uci.get_all("firewall")
    if section in sections:
        raise ValidationError("Такое правило уже существует", {"section": section})
    duplicate = _existing_wan_accept_rule(sections, proto, port)
    if duplicate:
        raise ValidationError("Порт уже открыт другим правилом", {"section": duplicate})
    listening = port_listening(port, proto)
    after_lines = [
        f"config rule '{section}'",
        f"\toption name '{section}'",
        "\toption src 'wan'",
        f"\toption proto '{proto}'",
        f"\toption dest_port '{port}'",
        "\toption target 'ACCEPT'",
        "\toption family 'ipv4'",
    ]
    diff = "".join(difflib.unified_diff(
        [], [line + "\n" for line in after_lines],
        fromfile="firewall (new rule)", tofile=f"firewall.{section} (planned)",
    ))
    targets = ["file:/etc/config/firewall"]
    summary = f"Открыть WAN-порт {port}/{proto} на роутере (новое firewall-правило {section})"
    if not listening:
        summary += (
            f". Внимание: сейчас на порту {port}/{proto} на роутере никто не слушает, поэтому одно это "
            "правило доступа не даст — нужен сервис, слушающий этот порт (для SSH используй ssh_open_wan_access)"
        )
    return MutationPlan(
        summary=summary,
        diff=diff, targets=targets, precondition_hashes=state_hashes(targets),
        prepared={"section": section, "port": port, "proto": proto, "listener_present": listening},
        uci_packages=["firewall"], services=["firewall"],
        verifier="uci_rule_present+nft_accept_rule_present",
    )


def _close_apply(context, plan: MutationPlan) -> dict[str, Any]:
    section = plan.prepared["section"]
    context.uci.delete_section("firewall", section)
    context.uci.commit("firewall")
    reload_result = service_action(context, "firewall", "reload", 30)
    return {"uci": f"firewall.{section}", "reload": reload_result}


def _close_verify(context, plan: MutationPlan) -> VerificationResult:
    section = plan.prepared["section"]
    sections = context.uci.get_all("firewall")
    removed = section not in sections
    nft_removed = not _nft_rule_present(context, section)
    ok = removed and nft_removed
    checks = {"uci_rule_removed": removed, "nft_rule_removed": nft_removed}
    return VerificationResult(ok, checks, "Порт закрыт" if ok else "Проверка не пройдена")


def _close_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    context.backups.restore(backup_dir)
    service_action(context, "firewall", "reload", 30)
    section = plan.prepared["section"]
    sections = context.uci.get_all("firewall")
    restored = section in sections
    nft_restored = _nft_rule_present(context, section)
    ok = restored and nft_restored
    checks = {"uci_rule_restored": restored, "nft_rule_restored": nft_restored}
    return VerificationResult(ok, checks, "Откат выполнен, порт снова открыт" if ok else "Откат требует ручной проверки")


@tool(
    name="firewall_close_wan_port",
    description="Закрыть WAN-порт, ранее открытый firewall_open_wan_port (удаляет соответствующее firewall-правило).",
    parameters={
        "type": "object",
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "proto": {"type": "string", "enum": list(PROTOCOLS)},
        },
        "required": ["port", "proto"], "additionalProperties": False,
    },
    exec_class=ExecClass.MUTATING,
    sensitivity="medium",
    network_side_effect="wan_exposure",
    applier=_close_apply,
    verifier=_close_verify,
    rollback=_close_rollback,
)
def firewall_close_wan_port(context, arguments: dict[str, Any]) -> MutationPlan:
    port = int(arguments["port"])
    proto = str(arguments["proto"])
    section = _section_name(proto, port)
    sections = context.uci.get_all("firewall")
    if section not in sections:
        raise ValidationError(
            "Правило с таким портом/протоколом, созданное этим агентом, не найдено", {"section": section},
        )
    values = sections[section]
    if not _is_wan_accept_rule(values, proto, port):
        raise ValidationError(
            "Секция с ожидаемым именем была изменена или принадлежит другому правилу; удаление отменено",
            {"section": section},
        )
    before_lines = [
        f"config rule '{section}'",
        *(f"\toption {key} '{val}'" for key, val in values.items() if key != ".type" and not isinstance(val, list)),
    ]
    diff = "".join(difflib.unified_diff(
        [line + "\n" for line in before_lines], [],
        fromfile=f"firewall.{section}", tofile="firewall (rule removed)",
    ))
    targets = ["file:/etc/config/firewall"]
    return MutationPlan(
        summary=f"Закрыть WAN-порт {port}/{proto}, удалить firewall-правило {section}",
        diff=diff, targets=targets, precondition_hashes=state_hashes(targets),
        prepared={"section": section, "port": port, "proto": proto},
        uci_packages=["firewall"], services=["firewall"],
        verifier="uci_rule_removed+nft_rule_removed",
    )
