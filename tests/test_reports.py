from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import unittest

from protoscan.cli import main
from protoscan.reporters import render_sarif


class ReportFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data_dir = Path(__file__).resolve().parents[0] / "data"
        self.project_root = str(self.data_dir.resolve())

    def _run_cli(self, fmt: str) -> str:
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["scan", "--project", str(self.data_dir), "--format", fmt])
        return buf.getvalue().replace(self.project_root, "PROJECT_ROOT").strip()

    def _fixture(self, name: str) -> str:
        return (self.data_dir / name).read_text().strip()

    def test_json_fixture_matches(self) -> None:
        output = self._run_cli("json")
        self.assertEqual(output, self._fixture("sample-report.json"))

    def test_sarif_fixture_matches(self) -> None:
        output = self._run_cli("sarif")
        self.assertEqual(output, self._fixture("sample-report.sarif"))

    def test_human_fixture_matches(self) -> None:
        output = self._run_cli("human")
        self.assertEqual(output, self._fixture("sample-report.txt"))

    def test_html_fixture_matches(self) -> None:
        output = self._run_cli("html")
        self.assertEqual(output, self._fixture("sample-report.html"))

    def test_csv_fixture_matches(self) -> None:
        output = self._run_cli("csv")
        self.assertEqual(output, self._fixture("sample-report.csv"))

    def test_sink_only_sarif_entries(self) -> None:
        report = {
            "flowChains": [],
            "sinkFindings": [
                {"path": "file.js", "line": 10, "kind": "sink.object.assign", "source": None}
            ],
            "dependencyReport": {"findings": []},
        }
        sarif = json.loads(render_sarif(report))
        results = sarif["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "sink.object.assign")
        self.assertEqual(results[0]["level"], "error")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
