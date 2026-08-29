from __future__ import annotations

import argparse
import json
import socket
import sys
import uuid
from typing import Any


def request(socket_path: str, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = json.dumps({"method": method, "params": params or {}}, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(190)
        client.connect(socket_path)
        client.sendall(payload)
        chunks = []
        total = 0
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"\n" in chunk or total > 2 * 1024 * 1024:
                break
    return json.loads(b"".join(chunks).split(b"\n", 1)[0].decode("utf-8"))


def print_response(response: dict[str, Any], as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(response, ensure_ascii=False, indent=2))
        return
    for warning in response.get("warnings", []):
        print(f"ПРЕДУПРЕЖДЕНИЕ: {warning}", file=sys.stderr)
    if response.get("message"):
        print(response["message"])
    if response.get("status") == "awaiting_confirmation":
        plan = response.get("plan", {})
        print(f"\nПлан: {plan.get('summary', '')}")
        if plan.get("diff"):
            print(plan["diff"])
        print(f"Action ID: {response['action_id']}")
    elif not response.get("ok", False):
        print(f"Ошибка [{response.get('error', 'unknown')}]: {response.get('message', '')}", file=sys.stderr)
    elif not response.get("message"):
        print(json.dumps(response, ensure_ascii=False, indent=2))


def maybe_confirm(socket_path: str, session_id: str, response: dict[str, Any], as_json: bool) -> dict[str, Any]:
    if response.get("status") != "awaiting_confirmation" or not sys.stdin.isatty():
        return response
    approved = input("Применить изменение? [y/N] ").strip().lower() in {"y", "yes", "д", "да"}
    result = request(socket_path, "confirm", {"session_id": session_id, "action_id": response["action_id"], "approve": approved})
    print_response(result, as_json)
    if result.get("state") == "rollback_pending":
        rollback = input("Verifier не пройден. Выполнить откат? [y/N] ").strip().lower() in {"y", "yes", "д", "да"}
        result = request(socket_path, "rollback", {"session_id": session_id, "action_id": response["action_id"], "approve": rollback})
        print_response(result, as_json)
    return result


def interactive(socket_path: str, session_id: str, as_json: bool) -> int:
    print(f"ai-agent session {session_id}. Ctrl-D для выхода.")
    while True:
        try:
            message = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not message:
            continue
        response = request(socket_path, "chat", {"session_id": session_id, "message": message})
        print_response(response, as_json)
        maybe_confirm(socket_path, session_id, response, as_json)


def main() -> None:
    parser = argparse.ArgumentParser(description="CLI для локального OpenWrt AI-agent")
    parser.add_argument("--socket", default="/var/run/ai-agent.sock")
    parser.add_argument("--json", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    chat = subparsers.add_parser("chat")
    chat.add_argument("message", nargs="*")
    chat.add_argument("--session")
    subparsers.add_parser("health")
    subparsers.add_parser("cleanup")
    history = subparsers.add_parser("history")
    history.add_argument("session")
    history.add_argument("--limit", type=int, default=100)
    debug = subparsers.add_parser("uci-show")
    debug.add_argument("package")
    confirm = subparsers.add_parser("confirm")
    confirm.add_argument("session")
    confirm.add_argument("action")
    confirm.add_argument("--yes", action="store_true")
    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("session")
    rollback.add_argument("action")
    rollback.add_argument("--yes", action="store_true")
    reverify = subparsers.add_parser("reverify")
    reverify.add_argument("session")
    reverify.add_argument("action")
    args = parser.parse_args()
    command = args.command or "chat"
    try:
        if command == "health":
            print_response(request(args.socket, "health"), args.json)
            return
        if command == "cleanup":
            print_response(request(args.socket, "cleanup_backups"), args.json)
            return
        if command == "history":
            print_response(request(args.socket, "history", {"session_id": args.session, "limit": args.limit}), True if not args.json else args.json)
            return
        if command == "uci-show":
            print_response(request(args.socket, "debug_uci", {"package": args.package}), args.json)
            return
        if command == "reverify":
            result = request(args.socket, command, {"session_id": args.session, "action_id": args.action})
            print_response(result, args.json)
            return
        if command in {"confirm", "rollback"}:
            result = request(args.socket, command, {"session_id": args.session, "action_id": args.action, "approve": args.yes})
            print_response(result, args.json)
            return
        session_id = args.session or uuid.uuid4().hex
        message = " ".join(args.message).strip()
        if not message:
            raise SystemExit(interactive(args.socket, session_id, args.json))
        response = request(args.socket, "chat", {"session_id": session_id, "message": message})
        print_response(response, args.json)
        maybe_confirm(args.socket, session_id, response, args.json)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Не удалось обратиться к ai-agent: {exc}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
