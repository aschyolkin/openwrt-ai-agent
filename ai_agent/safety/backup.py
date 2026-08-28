from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Any

from ..adapters import UCIAdapter, sha256_file
from ..errors import AgentError
from ..models import MutationPlan


class BackupStore:
    def __init__(self, root: str, uci: UCIAdapter):
        self.root = Path(root)
        self.uci = uci
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def create(self, action_id: str, tool_name: str, plan: MutationPlan) -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        directory = self.root / f"{stamp}_{action_id}"
        directory.mkdir(mode=0o700)
        manifest: dict[str, Any] = {
            "action_id": action_id,
            "tool_name": tool_name,
            "created_at": int(time.time()),
            "state": "applying",
            "files": [],
            "uci": [],
        }
        for package in plan.uci_packages:
            exported = self.uci.export(package)
            export_name = f"{package}.export"
            self._write_private(directory / export_name, exported)
            raw_path = Path("/etc/config") / package
            raw_name = f"{package}.config.bak"
            if raw_path.is_file():
                shutil.copy2(raw_path, directory / raw_name)
                os.chmod(directory / raw_name, 0o600)
                raw_hash = sha256_file(str(raw_path))
            else:
                raw_name = ""
                raw_hash = "missing"
            manifest["uci"].append({"package": package, "export": export_name, "raw": raw_name, "sha256": raw_hash})
        for index, source in enumerate(plan.backup_files):
            path = Path(source)
            if not path.is_file():
                manifest["files"].append({"path": source, "backup": "", "sha256": "missing"})
                continue
            backup_name = f"file-{index}.bak"
            shutil.copy2(path, directory / backup_name)
            os.chmod(directory / backup_name, 0o600)
            manifest["files"].append({"path": source, "backup": backup_name, "sha256": sha256_file(source)})
        self.write_meta(str(directory), manifest)
        return str(directory)

    @staticmethod
    def _write_private(path: Path, content: str) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

    def read_meta(self, directory: str) -> dict[str, Any]:
        try:
            return json.loads((Path(directory) / "meta.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AgentError("invalid_backup", f"Повреждён meta.json в {directory}") from exc

    def write_meta(self, directory: str, meta: dict[str, Any]) -> None:
        target = Path(directory) / "meta.json"
        temporary = Path(directory) / ".meta.json.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(meta, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)

    def update_state(self, directory: str, state: str, extra: dict[str, Any] | None = None) -> None:
        meta = self.read_meta(directory)
        meta["state"] = state
        meta["updated_at"] = int(time.time())
        if extra:
            meta.update(extra)
        self.write_meta(directory, meta)

    def restore(self, directory: str) -> dict[str, Any]:
        meta = self.read_meta(directory)
        restored: list[str] = []
        base = Path(directory)
        for entry in meta.get("uci", []):
            package = entry["package"]
            export_text = (base / entry["export"]).read_text(encoding="utf-8")
            self.uci.import_text(package, export_text)
            if entry.get("raw"):
                destination = Path("/etc/config") / package
                shutil.copy2(base / entry["raw"], destination)
                os.chmod(destination, 0o600)
            restored.append(f"uci:{package}")
        for entry in meta.get("files", []):
            if not entry.get("backup"):
                continue
            destination = Path(entry["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(base / entry["backup"], destination)
            restored.append(str(destination))
        return {"restored": restored}

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for directory in sorted(self.root.iterdir(), reverse=True):
            if not directory.is_dir():
                continue
            try:
                meta = self.read_meta(str(directory))
            except AgentError:
                meta = {"state": "invalid", "action_id": directory.name}
            entries.append({
                "directory": directory.name,
                "action_id": meta.get("action_id"),
                "tool_name": meta.get("tool_name"),
                "state": meta.get("state"),
                "created_at": meta.get("created_at"),
            })
            if len(entries) >= limit:
                break
        return entries

    def cleanup(self, retention_days: int) -> int:
        cutoff = time.time() - max(1, retention_days) * 86400
        removed = 0
        for directory in self.root.iterdir():
            if directory.is_dir() and directory.stat().st_mtime < cutoff:
                shutil.rmtree(directory)
                removed += 1
        return removed

