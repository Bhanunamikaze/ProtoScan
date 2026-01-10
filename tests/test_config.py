from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from protoscan.config import DEFAULT_CONFIG, load_config


class ConfigLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write(self, relative: str, data: dict) -> Path:
        path = self.project_root / relative
        path.write_text(json.dumps(data))
        return path

    def test_uses_defaults_when_no_files_present(self) -> None:
        config = load_config(self.project_root)
        self.assertEqual(config.project_root, self.project_root.resolve())
        self.assertEqual(config.severity, DEFAULT_CONFIG["severity"])
        self.assertEqual(config.ignore, [])
        self.assertTrue(config.cache_enabled)

    def test_merges_default_file(self) -> None:
        self._write(
            ".protoscanrc.json",
            {"severity": "high", "ignore": ["node_modules"]},
        )
        config = load_config(self.project_root)
        self.assertEqual(config.severity, "high")
        self.assertEqual(config.ignore, ["node_modules"])

    def test_cli_overrides_take_precedence(self) -> None:
        self._write(
            ".protoscanrc.json",
            {"severity": "high", "cache_enabled": True},
        )
        config = load_config(
            self.project_root,
            overrides={"severity": "critical", "cache_enabled": False},
        )
        self.assertEqual(config.severity, "critical")
        self.assertFalse(config.cache_enabled)

    def test_additional_config_file(self) -> None:
        self._write(
            ".protoscanrc.json",
            {"runtime_hints": ["node"]},
        )
        custom = self._write(
            "custom.json",
            {"runtime_hints": ["deno"], "ignore": ["dist"]},
        )
        config = load_config(self.project_root, config_path=custom)
        self.assertEqual(config.runtime_hints, ["deno"])
        self.assertEqual(config.ignore, ["dist"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
