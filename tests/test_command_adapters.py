from __future__ import annotations

import os
import unittest

from ai_agent.adapters import parse_uci_show
from ai_agent.command import CommandRunner
from ai_agent.errors import ValidationError


class CommandRunnerTests(unittest.TestCase):
    def test_fixed_allowlist(self):
        runner = CommandRunner(allowed={"/bin/echo"})
        result = runner.run(["/bin/echo", "ok"])
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout.strip(), "ok")
        with self.assertRaises(ValidationError):
            runner.run(["/bin/sh", "-c", "id"])

    def test_output_limit_kills_producer(self):
        if not os.path.exists("/usr/bin/yes"):
            self.skipTest("yes unavailable")
        runner = CommandRunner(allowed={"/usr/bin/yes"}, max_output_bytes=1024)
        result = runner.run(["/usr/bin/yes"], timeout=2)
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.stdout.encode()), 1024)


class UCIParserTests(unittest.TestCase):
    def test_parse_sections_and_lists(self):
        parsed = parse_uci_show("demo", "demo.main=config\ndemo.main.enabled='1'\ndemo.main.node='A'\ndemo.main.node='B'\n")
        self.assertEqual(parsed["main"][".type"], "config")
        self.assertEqual(parsed["main"]["node"], ["A", "B"])


if __name__ == "__main__":
    unittest.main()

