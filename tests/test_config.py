from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from ai_agent.config import AgentConfig, DEFAULT_COMPLEX_MODEL, ensure_private_directory, load_env_file


class AgentConfigTests(unittest.TestCase):
    def test_legacy_model_id_remains_a_complex_model_fallback(self):
        config = AgentConfig.from_mapping({"model_id": "legacy-model"})

        self.assertEqual(config.complex_model_id, "legacy-model")

    def test_explicit_complex_model_wins_over_legacy_option(self):
        config = AgentConfig.from_mapping({
            "model_id": "legacy-model",
            "complex_model_id": "current-model",
        })

        self.assertEqual(config.complex_model_id, "current-model")
        self.assertEqual(AgentConfig.from_mapping({}).complex_model_id, DEFAULT_COMPLEX_MODEL)

    def test_env_file_is_parsed_without_evaluating_shell_syntax(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "service.env"
            path.write_text(
                "# comment\nTOKEN=plain-value\nCOMMAND=$(must-not-run)\n",
                encoding="utf-8",
            )
            values = load_env_file(path)

        self.assertEqual(values["TOKEN"], "plain-value")
        self.assertEqual(values["COMMAND"], "$(must-not-run)")

    def test_private_directory_permissions_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state"

            ensure_private_directory(str(path))

            self.assertTrue(path.is_dir())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
