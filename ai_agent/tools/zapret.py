from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any

from ..adapters import sha256_file, state_hashes
from ..command import first_executable
from ..errors import AgentError, ValidationError
from ..models import MutationPlan, VerificationResult
from ..redaction import redact_log_network_data
from ..registry import ExecClass, tool
from .common import process_running, service_action, service_status


STRATEGIES = (
    "empty", "v1_by_StressOzz", "v2_by_StressOzz", "v3_by_StressOzz",
    "v4_by_StressOzz", "v5_by_StressOzz", "v6_by_StressOzz", "v7_by_StressOzz",
    "v9_by_StressOzz", "ALT7_by_Flowseal", "TLS_AUTO_ALT3_by_Flowseal",
)
SAFE_CONFIG_FIELDS = (
    "run_on_boot", "FWTYPE", "POSTNAT", "FLOWOFFLOAD", "INIT_APPLY_FW",
    "DISABLE_IPV4", "DISABLE_IPV6", "FILTER_TTL_EXPIRED_ICMP", "MODE_FILTER",
    "DISABLE_CUSTOM", "WS_USER", "DAEMON_LOG_ENABLE", "DAEMON_LOG_SIZE_MAX",
    "NFQWS_ENABLE", "NFQWS_PORTS_TCP", "NFQWS_PORTS_UDP", "NFQWS_TCP_PKT_OUT",
    "NFQWS_TCP_PKT_IN", "NFQWS_UDP_PKT_OUT", "NFQWS_UDP_PKT_IN",
    "NFQWS_PORTS_TCP_KEEPALIVE", "NFQWS_PORTS_UDP_KEEPALIVE",
    "AUTOHOSTLIST_RETRANS_THRESHOLD", "AUTOHOSTLIST_FAIL_THRESHOLD", "AUTOHOSTLIST_FAIL_TIME",
)


@tool(
    name="zapret_service_status",
    description="Проверить состояние zapret и наличие процесса nfqws.",
    parameters={"type": "object", "properties": {}, "additionalProperties": False},
)
def zapret_service_status(context, arguments: dict[str, Any]) -> dict[str, Any]:
    status = service_status(context, "zapret")
    status["nfqws_process"] = process_running("nfqws")
    return status


@tool(
    name="zapret_config_show",
    description="Показать allowlist безопасных параметров zapret и краткую сводку NFQWS_OPT.",
    parameters={"type": "object", "properties": {}, "additionalProperties": False},
    sensitivity="medium",
)
def zapret_config_show(context, arguments: dict[str, Any]) -> dict[str, Any]:
    values = {field: context.uci.get("zapret", "config", field, None) for field in SAFE_CONFIG_FIELDS}
    options = str(context.uci.get("zapret", "config", "NFQWS_OPT", "") or "")
    comment = re.search(r"--comment=([^\s]+)", options)
    methods = []
    for match in re.finditer(r"--dpi-desync=([^\s]+)", options):
        for method in match.group(1).split(","):
            if method not in methods:
                methods.append(method)
    return {
        "config": values,
        "strategy_comment": comment.group(1) if comment else None,
        "nfqws_opt": {"line_count": len(options.splitlines()), "desync_methods": methods[:30], "section_count": options.count("--new") + (1 if options.strip() else 0)},
        "omitted": ["raw_NFQWS_OPT", "hostlist_contents", "logs"],
    }


@tool(
    name="zapret_dpi_check",
    description="Запустить внешний zapret dwc.sh как необязательный диагностический сигнал; его вывод считается недоверенным.",
    parameters={
        "type": "object", "properties": {
            "mode": {"type": "string", "enum": ["dpi", "sites"]},
            "dns": {"type": "string", "enum": ["8.8.8.8", "1.1.1.1"]},
        },
        "required": ["mode", "dns"], "additionalProperties": False,
    },
    sensitivity="medium",
    network_side_effect="external_diagnostic_requests",
)
def zapret_dpi_check(context, arguments: dict[str, Any]) -> dict[str, Any]:
    argv = ["/opt/zapret/dwc.sh"]
    if arguments["mode"] == "sites":
        argv.append("-s")
    argv.extend(["-d", arguments["dns"]])
    result = context.runner.run(argv, timeout=180, max_output_bytes=65536)
    output = redact_log_network_data(result.stdout + ("\n" + result.stderr if result.stderr else ""))
    return {
        "mode": arguments["mode"], "dns": arguments["dns"], "completed": result.ok,
        "returncode": result.returncode, "timed_out": result.timed_out, "truncated": result.truncated,
        "output": output, "authoritative": False,
    }


@tool(
    name="zapret_logs_tail",
    description="Прочитать ограниченный хвост логов nfqws с маскированием сетевых идентификаторов и секретов.",
    parameters={
        "type": "object", "properties": {"lines": {"type": "integer", "minimum": 1, "maximum": 200}},
        "additionalProperties": False,
    },
    sensitivity="high",
)
def zapret_logs_tail(context, arguments: dict[str, Any]) -> dict[str, Any]:
    limit = arguments.get("lines", 100)
    files = sorted(Path("/tmp").glob("zapret+*.log"), key=lambda path: path.stat().st_mtime, reverse=True)
    logs = []
    for path in files[:4]:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
        except OSError:
            continue
        logs.append({"file": path.name, "lines": [redact_log_network_data(line) for line in lines]})
    return {"logs": logs}


def _parse_installed_strategy(strategy: str) -> dict[str, str]:
    if strategy not in STRATEGIES:
        raise ValidationError("Неизвестная стратегия zapret", {"strategy": strategy})
    if strategy == "empty":
        return {"MODE_FILTER": "hostlist", "NFQWS_PORTS_TCP": "80,443", "NFQWS_PORTS_UDP": "443", "NFQWS_OPT": "\t"}
    path = Path("/opt/zapret/def-cfg.sh")
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AgentError("zapret_strategy_source_missing", "Не найден установленный def-cfg.sh") from exc
    marker = re.escape(strategy)
    match = re.search(r'if \[ "\$strat" = "' + marker + r'" \]; then(?P<body>.*?)\n\s*fi', source, re.S)
    if not match:
        raise AgentError("zapret_strategy_not_installed", "Стратегия отсутствует в установленном def-cfg.sh")
    body = match.group("body")
    result = {"MODE_FILTER": "hostlist"}
    assignment = re.compile(
        r"set \$cfgname\.config\.(NFQWS_PORTS_TCP|NFQWS_PORTS_UDP|NFQWS_OPT)=(?:'(?P<single>.*?)'|\"(?P<double>.*?)\")",
        re.S,
    )
    for item in assignment.finditer(body):
        value = item.group("single") if item.group("single") is not None else item.group("double")
        result[item.group(1)] = value.replace("$strat", strategy)
    required = {"MODE_FILTER", "NFQWS_PORTS_TCP", "NFQWS_PORTS_UDP", "NFQWS_OPT"}
    if set(result) != required:
        raise AgentError("zapret_strategy_parse_failed", "Не удалось детерминированно извлечь все поля стратегии", {"found": sorted(result)})
    return result


def _zapret_verify(context, plan: MutationPlan) -> VerificationResult:
    checks: dict[str, Any] = {}
    shell = first_executable(("/bin/sh",))
    syntax = context.runner.run([shell, "-n", "/opt/zapret/config"], timeout=10)
    checks["config_syntax"] = syntax.ok
    checks["nfqws_process"] = process_running("nfqws")
    try:
        nft = first_executable(("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"))
        rules = context.runner.run([nft, "list", "ruleset"], timeout=20, max_output_bytes=1024 * 1024)
        lowered = rules.stdout.lower()
        checks["nft_rules"] = rules.ok and ("zapret" in lowered or "nfqws" in lowered or "queue num" in lowered)
    except AgentError:
        checks["nft_rules"] = False
    expected = plan.prepared.get("values", {})
    if expected:
        actual = {key: str(context.uci.get("zapret", "config", key, "") or "") for key in expected}
        checks["uci_values_match"] = actual == expected
    ok = all(bool(value) for value in checks.values())
    return VerificationResult(ok, checks, "zapret прошёл локальный verifier" if ok else "Локальный verifier zapret не пройден")


def _change_strategy_apply(context, plan: MutationPlan) -> dict[str, Any]:
    values = plan.prepared["values"]
    for key in ("MODE_FILTER", "NFQWS_PORTS_TCP", "NFQWS_PORTS_UDP", "NFQWS_OPT"):
        context.uci.set("zapret", "config", key, values[key])
    context.uci.commit("zapret")
    restart = service_action(context, "zapret", "restart", 90)
    return {"strategy": plan.prepared["strategy"], "fields": list(values), "restart": restart}


def _change_strategy_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    context.backups.restore(backup_dir)
    service_action(context, "zapret", "restart", 90)
    result = _zapret_verify(context, MutationPlan("rollback", "", [], {}, prepared={}))
    expected = plan.precondition_hashes.get("file:/etc/config/zapret")
    result.checks["uci_file_hash_restored"] = sha256_file("/etc/config/zapret") == expected
    result.ok = result.ok and result.checks["uci_file_hash_restored"]
    return result


@tool(
    name="zapret_change_strategy",
    description="Сменить стратегию zapret с полным diff MODE_FILTER, TCP/UDP-портов и NFQWS_OPT, бэкапом и verifier.",
    parameters={
        "type": "object", "properties": {"strategy": {"type": "string", "enum": list(STRATEGIES)}},
        "required": ["strategy"], "additionalProperties": False,
    },
    exec_class=ExecClass.MUTATING,
    network_side_effect="dpi_service_restart",
    applier=_change_strategy_apply,
    verifier=_zapret_verify,
    rollback=_change_strategy_rollback,
)
def zapret_change_strategy(context, arguments: dict[str, Any]) -> MutationPlan:
    strategy = arguments["strategy"]
    proposed = _parse_installed_strategy(strategy)
    current = {key: str(context.uci.get("zapret", "config", key, "") or "") for key in proposed}
    if current == proposed:
        raise ValidationError("Эта стратегия уже полностью применена", {"strategy": strategy})
    before = []
    after = []
    for key in ("MODE_FILTER", "NFQWS_PORTS_TCP", "NFQWS_PORTS_UDP", "NFQWS_OPT"):
        before.extend(f"{key}={current[key]}\n".splitlines(keepends=True))
        after.extend(f"{key}={proposed[key]}\n".splitlines(keepends=True))
    diff = "".join(difflib.unified_diff(before, after, fromfile="zapret current", tofile=f"zapret strategy {strategy}"))
    targets = ["file:/etc/config/zapret"]
    return MutationPlan(
        summary=f"Сменить стратегию zapret на {strategy} и перезапустить сервис",
        diff=diff, targets=targets, precondition_hashes=state_hashes(targets),
        prepared={"strategy": strategy, "values": proposed}, uci_packages=["zapret"],
        services=["zapret", "nfqws"], verifier="sh_syntax+nfqws_process+nft_rules+uci_values",
        rollback_data={"previous": current},
    )


def _zapret_restart_apply(context, plan: MutationPlan) -> dict[str, Any]:
    return service_action(context, "zapret", "restart", 90)


def _zapret_restart_rollback(context, plan: MutationPlan, backup_dir: str) -> VerificationResult:
    service_action(context, "zapret", "restart", 90)
    return _zapret_verify(context, plan)


@tool(
    name="zapret_restart",
    description="Перезапустить zapret после подтверждения без изменения конфигурации.",
    parameters={"type": "object", "properties": {}, "additionalProperties": False},
    exec_class=ExecClass.MUTATING,
    network_side_effect="dpi_service_restart",
    applier=_zapret_restart_apply,
    verifier=_zapret_verify,
    rollback=_zapret_restart_rollback,
)
def zapret_restart(context, arguments: dict[str, Any]) -> MutationPlan:
    targets = ["file:/etc/config/zapret"]
    return MutationPlan(
        summary="Перезапустить zapret", diff="runtime: zapret restart",
        targets=targets, precondition_hashes=state_hashes(targets),
        uci_packages=["zapret"],
        services=["zapret", "nfqws"], verifier="sh_syntax+nfqws_process+nft_rules",
    )

