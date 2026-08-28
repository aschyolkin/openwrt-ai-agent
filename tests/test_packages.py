from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ai_agent.errors import ValidationError
from ai_agent.models import CommandResult
from ai_agent.tools.packages import (
    _install_apply,
    _install_rollback,
    _install_verify,
    _remove_apply,
    _remove_rollback,
    _remove_verify,
    sys_package_install,
    sys_package_remove,
)


class FakeRunner:
    def __init__(self):
        self.installed = False
        self.calls = []

    def run(self, argv, **_kwargs):
        self.calls.append(argv)
        if argv[1:3] == ["info", "-e"]:
            return CommandResult(argv, 0 if self.installed else 1, "", "")
        if argv[1] == "add":
            self.installed = True
            return CommandResult(argv, 0, "installed\n", "")
        if argv[1] == "del":
            self.installed = False
            return CommandResult(argv, 0, "removed\n", "")
        raise AssertionError(argv)


class PackageToolTests(unittest.TestCase):
    def setUp(self):
        self.runner = FakeRunner()
        self.context = SimpleNamespace(runner=self.runner)
        self.apk = patch("ai_agent.tools.packages._apk", return_value="/usr/bin/apk")
        self.apk.start()

    def tearDown(self):
        self.apk.stop()

    def test_install_plan_apply_verify_and_rollback(self):
        plan = sys_package_install(self.context, {"package": "coreutils-whoami"})
        self.assertIn("coreutils-whoami", plan.summary)
        self.assertEqual(plan.prepared["manager"], "apk")
        applied = _install_apply(self.context, plan)
        self.assertEqual(applied["returncode"], 0)
        self.assertTrue(_install_verify(self.context, plan).ok)
        self.assertTrue(_install_rollback(self.context, plan, "unused").ok)
        self.assertFalse(self.runner.installed)

    def test_rejects_invalid_or_already_installed_package(self):
        with self.assertRaises(ValidationError):
            sys_package_install(self.context, {"package": "bad;reboot"})
        self.runner.installed = True
        with self.assertRaises(ValidationError):
            sys_package_install(self.context, {"package": "coreutils-whoami"})

    def test_remove_plan_apply_verify_and_rollback(self):
        self.runner.installed = True
        plan = sys_package_remove(self.context, {"package": "coreutils-whoami"})
        self.assertIn("Удалить", plan.summary)
        removed = _remove_apply(self.context, plan)
        self.assertEqual(removed["returncode"], 0)
        self.assertTrue(_remove_verify(self.context, plan).ok)
        self.assertTrue(_remove_rollback(self.context, plan, "unused").ok)
        self.assertTrue(self.runner.installed)

    def test_remove_rejects_missing_package(self):
        with self.assertRaises(ValidationError):
            sys_package_remove(self.context, {"package": "coreutils-whoami"})


if __name__ == "__main__":
    unittest.main()
