from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from protoscan.dependency_analysis import analyze_dependencies, _clear_advisory_cache


class DependencyAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_package_json(self, deps: dict) -> None:
        package = {
            "name": "app",
            "version": "1.0.0",
            "dependencies": deps,
        }
        (self.root / "package.json").write_text(json.dumps(package))

    def _write_lock(self, data: dict) -> None:
        (self.root / "package-lock.json").write_text(json.dumps(data))

    def test_detects_direct_vulnerability(self) -> None:
        self._write_package_json({"lodash": "4.17.20"})
        report = analyze_dependencies(self.root)
        self.assertIn("lodash", report.direct_dependencies)
        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertEqual(finding.name, "lodash")
        self.assertEqual(finding.via, "direct")
        self.assertEqual(finding.project, ".")

    def test_detects_transitive_vulnerability_from_lockfile(self) -> None:
        self._write_package_json({"express": "^4.18.0"})
        lock = {
            "name": "app",
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "dependencies": {
                        "lodash": {"version": "4.17.20"}
                    },
                }
            },
        }
        self._write_lock(lock)
        report = analyze_dependencies(self.root)
        self.assertIn("lodash", report.transitive_dependencies)
        names = {finding.name for finding in report.findings}
        self.assertIn("lodash", names)
        transitive = [f for f in report.findings if f.name == "lodash"][0]
        self.assertEqual(transitive.via, "transitive")
        self.assertEqual(transitive.project, ".")

    def test_detects_nested_project(self) -> None:
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "package.json").write_text(json.dumps({
            "name": "nested-app",
            "version": "1.0.0",
            "dependencies": {"lodash": "4.17.20"}
        }))
        report = analyze_dependencies(self.root)
        names = {finding.name for finding in report.findings}
        self.assertIn("lodash", names)
        finding = [f for f in report.findings if f.name == "lodash"][0]
        self.assertEqual(finding.project, "nested")

    def test_uses_custom_advisory_database(self) -> None:
        custom_db = self.root / "advisories.json"
        custom_db.write_text(
            json.dumps(
                [
                    {
                        "name": "left-pad",
                        "spec": "<2.0.0",
                        "severity": "low",
                        "cves": ["CVE-1970-0001"],
                        "reference": "https://example.com/left-pad",
                    }
                ]
            )
        )
        self._write_package_json({"left-pad": "1.0.0"})
        with patch.dict(os.environ, {"PROTOSCAN_VULN_DB": str(custom_db)}):
            _clear_advisory_cache()
            report = analyze_dependencies(self.root)
        self.assertTrue(any(f.name == "left-pad" for f in report.findings))
        _clear_advisory_cache()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
