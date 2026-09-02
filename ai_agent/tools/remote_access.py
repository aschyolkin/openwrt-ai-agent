from __future__ import annotations

import difflib
import time
from pathlib import Path
from typing import Any

from ..adapters import state_hashes
from ..errors import ValidationError
from ..models import MutationPlan, VerificationResult
from ..registry import ExecClass, tool
from .common import port_listening, port_owned_by_process, service_action, service_status
from .firewall import _FORBIDDEN_PORTS, _is_wan_accept_rule, _nft_rule_present, _section_name

# Opening SSH to the internet is two changes, never one: dropbear must listen on
# the port AND fw4 must accept it. A firewall rule alone yields "connection
# refused" because the stock dropbear instance is LAN-bound on 22, so this tool
# always plans both together and verifies the socket is actually listening.
DROPBEAR_SECTION = "ai_agent_wan_ssh"

_AUTHORIZED_KEYS = ("/etc/dropbear/authorized_keys", "/root/.ssh/authorized_keys")

# 22 stays LAN-only: exposing the well-known SSH port invites constant scanning,
# and the stock dropbear.main section is deliberately bound to the lan interface.
_MIN_PORT = 1025


def _authorized_key_files() -> list[str]:
    found: list[str] = []
    for path in _AUTHORIZED_KEYS:
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(line.strip() and not line.lstrip().startswith("#") for line in content.splitlines()):
            found.append(path)
    return found


def _dropbear_port_taken(sections: dict[str, dict[str, Any]], port: int) -> str | None:
    for name, values in sections.items():
        if values.get(".type") == "dropbear" and str(values.get("Port", "22")) == str(port):
            return name
    return None


def _wait_listening(port: int, attempts: int = 10, delay: float = 0.5) -> bool:
    for index in range(attempts):
        if port_owned_by_process(port, "tcp", {"dropbear"}):
            return True
        if index + 1 < attempts:
            time.sleep(delay)
    return False


def _ssh_open_apply(context, plan: MutationPlan) -> dict[str, Any]:
    port = int(plan.prepared["port"])
    firewall_section = plan.prepared["firewall_section"]
    context.uci.create_section("dropbear", DROPBEAR_SECTION, "dropbear")
    context.uci.set("dropbear", DROPBEAR_SECTION, "Port", str(port))
    context.uci.set("dropbear", DROPBEAR_SECTION, "PasswordAuth", "off")
    context.uci.set("dropbear", DROPBEAR_SECTION, "RootPasswordAuth", "off")
    context.uci.set("dropbear", DROPBEAR_SECTION, "GatewayPorts", "off")
    context.uci.commit("dropbear")
    if not plan.prepared.get("create_firewall_rule", True):
        dropbear_result = service_action(context, "dropbear", "restart", 30)
        return {"uci": [f"dropbear.{DROPBEAR_SECTION}"], "dropbear": dropbear_result,
                "firewall": {"reused": f"firewall.{firewall_section}"}}
    context.uci.create_section("firewall", firewall_section, "rule")
    context.uci.set("firewall", firewall_section, "name", firewall_section)
    context.uci.set("firewall", firewall_section, "src", "wan")
    context.uci.set("firewall", firewall_section, "proto", "tcp")
    context.uci.set("firewall", firewall_section, "dest_port", str(port))
    context.uci.set("firewall", firewall_section, "target", "ACCEPT")
    context.uci.set("firewall", firewall_section, "family", "ipv4")
    context.uci.commit("firewall")
    dropbear_result = service_action(context, "dropbear", "restart", 30)
    firewall_result = service_action(context, "firewall", "reload", 30)
    return {
        "uci": [f"dropbear.{DROPBEAR_SECTION}", f"firewall.{firewall_section}"],
        "dropbear": dropbear_result,
        "firewall": firewall_result,
    }


def _ssh_open_verify(context, plan: MutationPlan) -> VerificationResult:
    port = int(plan.prepared["port"])
    firewall_section = plan.prepared["firewall_section"]
    dropbear_sections = context.uci.get_all("dropbear")
    dropbear_port_ok = (
        DROPBEAR_SECTION in dropbear_sections
        and dropbear_sections[DROPBEAR_SECTION].get(".type") == "dropbear"
        and str(dropbear_sections[DROPBEAR_SECTION].get("Port")) == str(port)
    )
    auth_ok = dropbear_port_ok and all(
        str(dropbear_sections[DROPBEAR_SECTION].get(option, "")) == "off"
        for option in ("PasswordAuth", "RootPasswordAuth", "GatewayPorts")
    )
    firewall_sections = context.uci.get_all("firewall")
    firewall_uci_ok = firewall_section in firewall_sections and _is_wan_accept_rule(
        firewall_sections[firewall_section], "tcp", port,
    )
    nft_ok = _nft_rule_present(context, firewall_section)
    listening = _wait_listening(port)
    ok = dropbear_port_ok and auth_ok and firewall_uci_ok and nft_ok and listening
    checks = {
        "dropbear_section_present": dropbear_port_ok,
        "password_and_gateway_access_disabled": auth_ok,
        "firewall_uci_rule_present": firewall_uci_ok,
        "nft_accept_rule_present": nft_ok,
        "sshd_listening_on_port": listening,
    }
    if ok:
        message = f"SSH слушает порт {port} и открыт из интернета (вход только по ключу)"
    elif not listening:
        message = f"Firewall настроен, но dropbear не слушает порт {port} — доступа не будет"
    else:
        message = "Проверка не пройдена"
    return VerificationResult(ok, checks, message)


def _ssh_open_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    context.backups.restore(backup_dir)
    service_action(context, "dropbear", "restart", 30)
    service_action(context, "firewall", "reload", 30)
    port = int(plan.prepared["port"])
    firewall_section = plan.prepared["firewall_section"]
    dropbear_removed = DROPBEAR_SECTION not in context.uci.get_all("dropbear")
    nft_removed = not _nft_rule_present(context, firewall_section)
    not_listening = not port_listening(port, "tcp")
    ok = dropbear_removed and nft_removed and not_listening
    checks = {
        "dropbear_section_removed": dropbear_removed,
        "nft_rule_removed": nft_removed,
        "port_not_listening": not_listening,
    }
    return VerificationResult(ok, checks, "Откат выполнен, внешний SSH закрыт" if ok else "Откат требует ручной проверки")


@tool(
    name="ssh_open_wan_access",
    description=(
        "Открыть SSH-доступ к роутеру из интернета (WAN) на нестандартном порту. Делает обе необходимые части "
        "сразу: поднимает отдельный экземпляр dropbear на этом порту (только по ключу, пароли выключены) и "
        "добавляет firewall-правило src=wan ACCEPT. Используй именно этот tool для любой просьбы вида "
        "«открой SSH наружу» / «дай подключаться по ssh из внешки на порт N» — одного firewall-правила "
        "недостаточно, штатный dropbear слушает только порт 22 на LAN."
    ),
    parameters={
        "type": "object",
        "properties": {
            "port": {"type": "integer", "minimum": _MIN_PORT, "maximum": 65535},
        },
        "required": ["port"], "additionalProperties": False,
    },
    exec_class=ExecClass.MUTATING,
    sensitivity="high",
    network_side_effect="wan_exposure",
    applier=_ssh_open_apply,
    verifier=_ssh_open_verify,
    rollback=_ssh_open_rollback,
)
def ssh_open_wan_access(context, arguments: dict[str, Any]) -> MutationPlan:
    port = int(arguments["port"])
    if port in _FORBIDDEN_PORTS or port < _MIN_PORT:
        raise ValidationError(
            "Этот порт нельзя использовать для внешнего SSH; выбери свободный порт выше 1024 "
            "(порт 22 остаётся только для LAN)",
            {"port": port},
        )
    dropbear_sections = context.uci.get_all("dropbear")
    if DROPBEAR_SECTION in dropbear_sections:
        raise ValidationError(
            "Внешний SSH уже настроен этим агентом; сначала закрой его через ssh_close_wan_access",
            {"section": DROPBEAR_SECTION, "port": dropbear_sections[DROPBEAR_SECTION].get("Port")},
        )
    taken = _dropbear_port_taken(dropbear_sections, port)
    if taken:
        raise ValidationError("Этот порт уже занят другим экземпляром dropbear", {"section": taken})
    if port_listening(port, "tcp"):
        raise ValidationError("Порт уже занят другим сервисом на роутере", {"port": port})
    # Probe the service surface before touching UCI: a blocked/missing init
    # script must fail while planning, not halfway through apply with dropbear
    # and firewall already committed but never restarted.
    service_status(context, "dropbear")
    keys = _authorized_key_files()
    if not keys:
        raise ValidationError(
            "На роутере нет authorized_keys, а пароль наружу открывать нельзя: сначала добавь SSH-ключ "
            "(/etc/dropbear/authorized_keys), потом открывай внешний доступ",
        )
    firewall_section = _section_name("tcp", port)
    firewall_sections = context.uci.get_all("firewall")
    # A rule left over from a bare firewall_open_wan_port call is exactly the
    # half-open state this tool exists to fix: reuse it instead of refusing, so
    # the user gets working access in one action rather than a dead end.
    existing_rule = firewall_sections.get(firewall_section)
    if existing_rule is not None and not _is_wan_accept_rule(existing_rule, "tcp", port):
        raise ValidationError(
            "Секция firewall с таким именем занята правилом другого вида", {"section": firewall_section},
        )
    create_rule = existing_rule is None
    dropbear_lines = [
        f"config dropbear '{DROPBEAR_SECTION}'",
        f"\toption Port '{port}'",
        "\toption PasswordAuth 'off'",
        "\toption RootPasswordAuth 'off'",
        "\toption GatewayPorts 'off'",
    ]
    firewall_lines = [
        f"config rule '{firewall_section}'",
        f"\toption name '{firewall_section}'",
        "\toption src 'wan'",
        "\toption proto 'tcp'",
        f"\toption dest_port '{port}'",
        "\toption target 'ACCEPT'",
        "\toption family 'ipv4'",
    ]
    diff = "".join(difflib.unified_diff(
        [], [line + "\n" for line in dropbear_lines],
        fromfile="dropbear (new instance)", tofile=f"dropbear.{DROPBEAR_SECTION} (planned)",
    ))
    if create_rule:
        diff += "".join(difflib.unified_diff(
            [], [line + "\n" for line in firewall_lines],
            fromfile="firewall (new rule)", tofile=f"firewall.{firewall_section} (planned)",
        ))
    else:
        diff += f"# firewall.{firewall_section} уже открывает {port}/tcp из WAN — правило переиспользуется\n"
    targets = ["file:/etc/config/dropbear", "file:/etc/config/firewall"]
    return MutationPlan(
        summary=(
            f"Открыть SSH из интернета на порту {port}/tcp: отдельный dropbear (вход только по ключу, "
            f"пароли выключены) + firewall-правило {firewall_section}"
            + ("" if create_rule else " (уже существует, будет переиспользовано)")
            + f". Ключи найдены в: {', '.join(keys)}"
        ),
        diff=diff, targets=targets, precondition_hashes=state_hashes(targets),
        prepared={"port": port, "firewall_section": firewall_section, "create_firewall_rule": create_rule},
        uci_packages=["dropbear", "firewall"], services=["dropbear", "firewall"],
        verifier="dropbear_section_present+nft_accept_rule_present+sshd_listening_on_port",
    )


def _ssh_close_apply(context, plan: MutationPlan) -> dict[str, Any]:
    firewall_section = plan.prepared["firewall_section"]
    context.uci.delete_section("dropbear", DROPBEAR_SECTION)
    context.uci.commit("dropbear")
    if plan.prepared.get("firewall_rule_present"):
        context.uci.delete_section("firewall", firewall_section)
        context.uci.commit("firewall")
    dropbear_result = service_action(context, "dropbear", "restart", 30)
    firewall_result = service_action(context, "firewall", "reload", 30)
    return {"dropbear": dropbear_result, "firewall": firewall_result}


def _ssh_close_verify(context, plan: MutationPlan) -> VerificationResult:
    port = int(plan.prepared["port"])
    firewall_section = plan.prepared["firewall_section"]
    dropbear_removed = DROPBEAR_SECTION not in context.uci.get_all("dropbear")
    nft_removed = not _nft_rule_present(context, firewall_section)
    not_listening = not port_listening(port, "tcp")
    ok = dropbear_removed and nft_removed and not_listening
    checks = {
        "dropbear_section_removed": dropbear_removed,
        "nft_rule_removed": nft_removed,
        "port_not_listening": not_listening,
    }
    return VerificationResult(ok, checks, "Внешний SSH закрыт" if ok else "Проверка не пройдена")


def _ssh_close_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    context.backups.restore(backup_dir)
    service_action(context, "dropbear", "restart", 30)
    service_action(context, "firewall", "reload", 30)
    port = int(plan.prepared["port"])
    restored = DROPBEAR_SECTION in context.uci.get_all("dropbear")
    listening = _wait_listening(port)
    ok = restored and listening
    checks = {"dropbear_section_restored": restored, "port_listening": listening}
    return VerificationResult(ok, checks, "Откат выполнен, внешний SSH снова открыт" if ok else "Откат требует ручной проверки")


@tool(
    name="ssh_close_wan_access",
    description=(
        "Закрыть внешний SSH-доступ, ранее открытый ssh_open_wan_access: удаляет созданный экземпляр dropbear "
        "и соответствующее firewall-правило. Штатный SSH на порту 22 в LAN не затрагивается."
    ),
    parameters={"type": "object", "properties": {}, "additionalProperties": False},
    exec_class=ExecClass.MUTATING,
    sensitivity="medium",
    network_side_effect="wan_exposure",
    applier=_ssh_close_apply,
    verifier=_ssh_close_verify,
    rollback=_ssh_close_rollback,
)
def ssh_close_wan_access(context, arguments: dict[str, Any]) -> MutationPlan:
    dropbear_sections = context.uci.get_all("dropbear")
    if DROPBEAR_SECTION not in dropbear_sections:
        raise ValidationError("Внешний SSH-доступ этим агентом не открывался", {"section": DROPBEAR_SECTION})
    values = dropbear_sections[DROPBEAR_SECTION]
    try:
        port = int(str(values.get("Port", "0")) or 0)
    except ValueError as exc:
        raise ValidationError(
            "Секция внешнего SSH содержит некорректный порт; удаление отменено",
            {"section": DROPBEAR_SECTION},
        ) from exc
    auth_off = all(
        str(values.get(option, "")) == "off"
        for option in ("PasswordAuth", "RootPasswordAuth", "GatewayPorts")
    )
    if values.get(".type") != "dropbear" or not _MIN_PORT <= port <= 65535 or not auth_off:
        raise ValidationError(
            "Секция внешнего SSH была изменена или принадлежит другому сервису; удаление отменено",
            {"section": DROPBEAR_SECTION},
        )
    firewall_section = _section_name("tcp", port)
    firewall_sections = context.uci.get_all("firewall")
    firewall_rule = firewall_sections.get(firewall_section)
    if firewall_rule is not None and not _is_wan_accept_rule(firewall_rule, "tcp", port):
        raise ValidationError(
            "Связанная секция firewall была изменена или принадлежит другому правилу; удаление отменено",
            {"section": firewall_section},
        )
    firewall_present = firewall_rule is not None
    before_lines = [
        f"config dropbear '{DROPBEAR_SECTION}'",
        *(f"\toption {key} '{val}'" for key, val in values.items() if key != ".type" and not isinstance(val, list)),
    ]
    if firewall_present:
        before_lines.append(f"config rule '{firewall_section}'")
        before_lines.extend(
            f"\toption {key} '{val}'"
            for key, val in firewall_sections[firewall_section].items()
            if key != ".type" and not isinstance(val, list)
        )
    diff = "".join(difflib.unified_diff(
        [line + "\n" for line in before_lines], [],
        fromfile=f"dropbear.{DROPBEAR_SECTION} + firewall.{firewall_section}", tofile="(removed)",
    ))
    targets = ["file:/etc/config/dropbear", "file:/etc/config/firewall"]
    return MutationPlan(
        summary=f"Закрыть внешний SSH на порту {port}/tcp (удалить dropbear-инстанс и firewall-правило)",
        diff=diff, targets=targets, precondition_hashes=state_hashes(targets),
        prepared={"port": port, "firewall_section": firewall_section, "firewall_rule_present": firewall_present},
        uci_packages=["dropbear", "firewall"], services=["dropbear", "firewall"],
        verifier="dropbear_section_removed+nft_rule_removed+port_not_listening",
    )
