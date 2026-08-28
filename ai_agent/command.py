from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess
import time
from collections.abc import Iterable

from .errors import AgentError, ValidationError
from .models import CommandResult


_DOMAIN = re.compile(r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$")
_UCI_REF = re.compile(r"^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_@\[\]-]+){0,2}$")
_SAFE_WORD = re.compile(r"^[a-zA-Z0-9_.:@/,+*=\[\]-]+$")


DEFAULT_ALLOWED_EXECUTABLES = frozenset(
    {
        "/bin/ubus", "/sbin/ubus", "/usr/bin/ubus", "/sbin/uci", "/usr/bin/uci",
        "/sbin/service", "/usr/sbin/service", "/usr/bin/service",
        "/bin/ping", "/usr/bin/ping", "/bin/traceroute", "/usr/bin/traceroute",
        "/bin/dig", "/usr/bin/dig", "/bin/nslookup", "/usr/bin/nslookup",
        "/sbin/logread", "/usr/sbin/logread", "/usr/bin/logread",
        "/bin/ps", "/usr/bin/pgrep", "/bin/sh", "/usr/sbin/nft", "/sbin/nft",
        "/usr/bin/ip", "/sbin/ip", "/bin/netstat", "/usr/bin/netstat",
        "/usr/sbin/conntrack", "/usr/bin/conntrack",
        "/bin/df", "/usr/bin/df", "/usr/bin/mount", "/bin/mount",
        "/sbin/lsmod", "/usr/bin/lsmod", "/usr/bin/apk",
        "/usr/bin/nft", "/usr/bin/netshift", "/etc/init.d/netshift",
        "/etc/init.d/sing-box", "/etc/init.d/adguardhome", "/etc/init.d/zapret",
        "/etc/init.d/firewall",
        "/opt/zapret/dwc.sh",
    }
)


def first_executable(candidates: Iterable[str]) -> str:
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise AgentError("command_unavailable", "Не найдена необходимая команда", {"candidates": list(candidates)})


class CommandRunner:
    """Fixed-argv command runner with a strict executable/argument allowlist."""

    def __init__(self, allowed: Iterable[str] | None = None, max_output_bytes: int = 65536):
        self.allowed = frozenset(allowed or DEFAULT_ALLOWED_EXECUTABLES)
        self.max_output_bytes = max(1024, min(int(max_output_bytes), 1024 * 1024))

    def _validate(self, argv: list[str]) -> None:
        if not argv or argv[0] not in self.allowed:
            raise ValidationError("Команда отсутствует в allowlist", {"executable": argv[0] if argv else ""})
        if any("\x00" in arg for arg in argv):
            raise ValidationError("NUL-байт в аргументе команды")
        exe = argv[0]
        base = os.path.basename(exe)
        args = argv[1:]

        if base == "sh":
            if len(args) != 2 or args[0] != "-n" or args[1] not in {"/opt/zapret/config"}:
                raise ValidationError("Для shell разрешена только фиксированная синтаксическая проверка")
        elif base == "uci":
            self._validate_uci(args)
        elif base in {"service", "netshift", "sing-box", "adguardhome", "zapret"} or exe.startswith("/etc/init.d/"):
            self._validate_service(exe, args)
        elif base == "ubus":
            if args != ["list"]:
                if len(args) not in {3, 4} or args[0] != "call" or not _SAFE_WORD.fullmatch(args[1]) or not _SAFE_WORD.fullmatch(args[2]):
                    raise ValidationError("Недопустимый вызов ubus")
                if len(args) == 4:
                    try:
                        payload = json.loads(args[3])
                    except json.JSONDecodeError as exc:
                        raise ValidationError("ubus payload должен быть JSON") from exc
                    if not isinstance(payload, dict):
                        raise ValidationError("ubus payload должен быть объектом")
        elif base in {"dig", "nslookup"}:
            self._validate_dns(args)
        elif base in {"ping", "traceroute"}:
            if not args or any(not _SAFE_WORD.fullmatch(arg) for arg in args):
                raise ValidationError("Недопустимые аргументы сетевой диагностики")
            host = args[-1]
            if not (_DOMAIN.fullmatch(host) or re.fullmatch(r"[0-9a-fA-F:.]+", host)):
                raise ValidationError("Недопустимый хост")
        elif base == "logread":
            if args and (len(args) != 2 or args[0] != "-e" or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", args[1])):
                raise ValidationError("logread разрешает только безопасный фильтр -e")
        elif base == "pgrep":
            if len(args) != 2 or args[0] != "-x" or args[1] not in {"sing-box", "nfqws", "AdGuardHome"}:
                raise ValidationError("Недопустимый pgrep")
        elif base == "ip":
            allowed_ip = {
                ("route", "show", "table", "all"),
                ("rule", "show"),
                ("address", "show"),
                ("link", "show"),
                ("neighbor", "show"),
            }
            if tuple(args) not in allowed_ip:
                raise ValidationError("ip разрешён только для фиксированной read-only инспекции")
        elif base == "netstat" and args != ["-lntup"]:
            raise ValidationError("netstat разрешён только для listening sockets")
        elif base == "conntrack" and args != ["-L"]:
            raise ValidationError("conntrack разрешён только для чтения таблицы (-L)")
        elif base == "df" and args != ["-h"]:
            raise ValidationError("df разрешён только в режиме -h")
        elif base in {"mount", "lsmod"} and args:
            raise ValidationError(f"{base} не принимает аргументы")
        elif base == "apk":
            self._validate_apk(args)
        elif base == "nft":
            if args != ["list", "ruleset"]:
                raise ValidationError("nft разрешён только в read-only режиме list ruleset")
        elif exe == "/opt/zapret/dwc.sh":
            if args not in (["-d", "8.8.8.8"], ["-d", "1.1.1.1"], ["-s", "-d", "8.8.8.8"], ["-s", "-d", "1.1.1.1"]):
                raise ValidationError("Недопустимые аргументы dwc.sh")

    @staticmethod
    def _validate_apk(args: list[str]) -> None:
        package = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,127}")
        if args == ["info"]:
            return
        if len(args) == 3 and args[:2] == ["info", "-e"] and package.fullmatch(args[2]):
            return
        if len(args) == 2 and args[0] in {"add", "del"} and package.fullmatch(args[1]):
            return
        raise ValidationError("Недопустимая команда apk")

    @staticmethod
    def _validate_uci(args: list[str]) -> None:
        if not args:
            raise ValidationError("Не указана операция UCI")
        if args[:2] == ["-q", "get"]:
            args = args[1:]
        verb = args[0]
        if verb in {"get", "show", "changes", "export", "commit", "revert"}:
            if len(args) not in {1, 2} or (len(args) == 2 and not _UCI_REF.fullmatch(args[1])):
                raise ValidationError("Недопустимая ссылка UCI")
        elif verb in {"set", "add_list", "delete_list"}:
            if len(args) != 2 or "=" not in args[1]:
                raise ValidationError("Недопустимое изменение UCI")
            ref, _value = args[1].split("=", 1)
            if not _UCI_REF.fullmatch(ref):
                raise ValidationError("Недопустимая ссылка UCI")
        elif verb == "import":
            if len(args) != 2 or not re.fullmatch(r"[a-zA-Z0-9_-]+", args[1]):
                raise ValidationError("Недопустимый UCI import")
        elif verb == "delete":
            # Only a whole named section ("pkg.section"), never a bare package
            # ("pkg") — that would wipe the entire config file.
            if len(args) != 1 or "." not in args[0] or not _UCI_REF.fullmatch(args[0]):
                raise ValidationError("Недопустимая ссылка UCI для delete")
        else:
            raise ValidationError("Операция UCI отсутствует в allowlist", {"verb": verb})

    @staticmethod
    def _validate_service(executable: str, args: list[str]) -> None:
        service_name = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}")
        allowed_verbs = {"status", "running", "enabled", "start", "stop", "restart", "reload", "enable", "disable"}
        if os.path.basename(executable) == "service":
            if len(args) != 2 or not service_name.fullmatch(args[0]) or args[1] not in allowed_verbs:
                raise ValidationError("Недопустимая команда service")
        elif os.path.basename(executable) == "netshift":
            if args not in (["status"], ["reload"]):
                raise ValidationError("Недопустимая команда netshift")
        elif len(args) != 1 or args[0] not in allowed_verbs:
            raise ValidationError("Недопустимая команда init.d")

    @staticmethod
    def _validate_dns(args: list[str]) -> None:
        if not args or any(not _SAFE_WORD.fullmatch(arg) for arg in args):
            raise ValidationError("Недопустимые аргументы DNS")
        domains = [arg for arg in args if not arg.startswith(('@', '+', '-')) and arg not in {"A", "AAAA"}]
        if not domains or not _DOMAIN.fullmatch(domains[-1]):
            raise ValidationError("Недопустимое доменное имя")

    def run(
        self,
        argv: list[str],
        timeout: float = 15.0,
        max_output_bytes: int | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        argv = [str(arg) for arg in argv]
        self._validate(argv)
        timeout = max(0.2, min(float(timeout), 180.0))
        limit = max(1024, min(int(max_output_bytes or self.max_output_bytes), 1024 * 1024))
        input_bytes = input_text.encode("utf-8") if input_text is not None else None
        if input_bytes is not None and len(input_bytes) > 1024 * 1024:
            raise ValidationError("stdin команды превышает безопасный лимит")
        if input_bytes is not None and not (os.path.basename(argv[0]) == "uci" and argv[1:2] == ["import"]):
            raise ValidationError("stdin разрешён только для UCI import")
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
        if input_bytes is not None:
            assert process.stdin is not None
            process.stdin.write(input_bytes)
            process.stdin.close()
        assert process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        for pipe, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
        size = 0
        timed_out = False
        truncated = False
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0 and process.poll() is None:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
            events = selector.select(max(0.01, min(max(remaining, 0.0), 0.25)))
            for key, _mask in events:
                data = key.fileobj.read(8192)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                take = max(0, limit - size)
                if take:
                    chunks[key.data].append(data[:take])
                    size += min(len(data), take)
                if len(data) > take:
                    truncated = True
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
            if process.poll() is not None and not events:
                for key in list(selector.get_map().values()):
                    data = key.fileobj.read(8192)
                    if data:
                        take = max(0, limit - size)
                        chunks[key.data].append(data[:take])
                        size += min(len(data), take)
                        truncated = truncated or len(data) > take
                    selector.unregister(key.fileobj)
        returncode = process.wait()
        decode = lambda parts: b"".join(parts).decode("utf-8", "replace")
        process.stdout.close()
        process.stderr.close()
        selector.close()
        return CommandResult(argv, returncode, decode(chunks["stdout"]), decode(chunks["stderr"]), timed_out, truncated)
