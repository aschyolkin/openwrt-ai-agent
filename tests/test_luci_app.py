import json
import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "luci-app-ai-agent"
BACKEND = APP / "root/usr/libexec/ai-agent-luci"
VIEW = APP / "htdocs/luci-static/resources/view/ai-agent/overview.js"


class LuciAppTests(unittest.TestCase):
    def test_menu_and_acl_are_minimal_and_secret_free(self):
        menu = json.loads(
            (APP / "root/usr/share/luci/menu.d/luci-app-ai-agent.json").read_text()
        )
        entry = menu["admin/services/ai-agent"]
        self.assertEqual(entry["action"], {"type": "view", "path": "ai-agent/overview"})
        self.assertEqual(entry["depends"]["acl"], ["luci-app-ai-agent"])

        acl = json.loads(
            (APP / "root/usr/share/rpcd/acl.d/luci-app-ai-agent.json").read_text()
        )["luci-app-ai-agent"]
        self.assertEqual(acl["read"]["file"], {
            "/usr/libexec/ai-agent-luci": ["exec"],
        })
        self.assertEqual(acl["read"]["uci"], ["ai-agent"])
        self.assertEqual(acl["write"]["uci"], ["ai-agent"])
        rendered = json.dumps(acl)
        self.assertNotIn("secrets.env", rendered)
        self.assertNotIn("telegram.env", rendered)

    def test_backend_accepts_only_fixed_status_and_restart_targets(self):
        self.assertEqual(stat.S_IMODE(BACKEND.stat().st_mode), 0o755)
        source = BACKEND.read_text()
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)

        invalid = subprocess.run(
            [str(BACKEND), "restart", "dropbear"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(json.loads(invalid.stdout)["error"], "invalid_target")

        status = subprocess.run(
            [str(BACKEND), "status"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(status.returncode, 0)
        payload = json.loads(status.stdout)
        self.assertEqual(set(payload["services"]), {"core", "telegram"})

    def test_view_exposes_only_supported_nonsecret_uci_options(self):
        source = VIEW.read_text()
        for option in (
            "enable",
            "model_routing_enabled",
            "simple_model_id",
            "complex_model_id",
            "log_level",
            "request_timeout_seconds",
            "confirm_ttl_seconds",
            "backup_retention_days",
            "max_tool_loop_iterations",
            "conversation_max_chars",
            "tool_context_max_chars",
            "command_output_limit",
            "log_monitor_interval_hours",
        ):
            self.assertIn("'%s'" % option, source)
        self.assertNotIn("TELEGRAM_BOT_TOKEN", source)
        self.assertNotIn("YANDEX_AI_STUDIO_API_KEY", source)
        self.assertNotIn("secrets_path", source)
        self.assertIn("gpt:\\/\\/", source)

    def test_main_installer_installs_all_luci_runtime_files(self):
        installer = (ROOT / "install.sh").read_text()
        for target in (
            "/www/luci-static/resources/view/ai-agent/overview.js",
            "/usr/share/luci/menu.d/luci-app-ai-agent.json",
            "/usr/share/rpcd/acl.d/luci-app-ai-agent.json",
            "/usr/libexec/ai-agent-luci",
        ):
            self.assertIn(target, installer)


if __name__ == "__main__":
    unittest.main()
