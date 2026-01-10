from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import unittest

from protoscan.cli import main

FIXTURE_DIR = Path(__file__).resolve().parents[0] / "fixtures" / "browser_bundle"


class BrowserFixtureTests(unittest.TestCase):
    def test_browser_sources_detected(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["scan", "--project", str(FIXTURE_DIR), "--format", "json"])
        self.assertEqual(exit_code, 0)
        report = json.loads(buf.getvalue())
        source_kinds = {item["kind"] for item in report["sourceFindings"]}
        self.assertIn("browser.url.searchParams", source_kinds)
        self.assertIn("browser.storage", source_kinds)
        sink_kinds = {item["kind"] for item in report["sinkFindings"]}
        self.assertIn("sink.object.spread", sink_kinds)
        self.assertIn("sink.dynamic.property.assignment", sink_kinds)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
