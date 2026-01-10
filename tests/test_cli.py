from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
import zipfile

from protoscan.cli import main


class CLIScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write(self, relative: str, contents: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    def test_scan_outputs_dependency_source_sink_and_gadget_reports(self) -> None:
        package = {
            "name": "app",
            "version": "1.0.0",
            "dependencies": {"lodash": "4.17.20"},
        }
        self._write("package.json", json.dumps(package))
        self._write(
            "server.js",
            """
            const app = require('express')();
            const child_process = require('child_process');
            const schema = { validate: (input) => input };
            function requireAuth() {}
            app.post('/api/user', (req, res) => {
              requireAuth();
              const data = schema.validate(req.body);
              Object.assign(target, data);
              child_process.exec('ls');
            });
            """,
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["scan", "--project", str(self.root)])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buf.getvalue())
        self.assertIn("dependencyReport", payload)
        findings = payload["dependencyReport"]["findings"]
        self.assertTrue(any(item["name"] == "lodash" for item in findings))
        self.assertIn("sourceFindings", payload)
        source_kinds = {item["kind"] for item in payload["sourceFindings"]}
        self.assertIn("http.request.body", source_kinds)
        self.assertIn("sinkFindings", payload)
        sink_kinds = {item["kind"] for item in payload["sinkFindings"]}
        self.assertIn("sink.object.assign", sink_kinds)
        self.assertIn("gadgetFindings", payload)
        gadget_kinds = {item["kind"] for item in payload["gadgetFindings"]}
        self.assertIn("gadget.rce.child_process.exec", gadget_kinds)
        self.assertIn("flowChains", payload)
        chain = payload["flowChains"][0]
        self.assertEqual(chain["severity"], "high")
        self.assertIsNotNone(chain["gadget"])
        self.assertEqual(chain["gadget"]["kind"], "gadget.rce.child_process.exec")
        self.assertTrue(chain["metadata"]["requiresAuth"])
        self.assertFalse(chain["metadata"]["hasSchemaValidation"])
        self.assertEqual(chain["route"], {"method": "POST", "path": "/api/user"})
        self.assertGreaterEqual(len(chain["exploitSteps"]), 3)
        self.assertTrue(chain["description"])
        self.assertIn("payload", chain["validation"].lower())
        self.assertIn("__proto__", chain["exploitExample"])

    def test_scan_can_emit_sarif(self) -> None:
        self._write(
            "server.js",
            """
            const app = require('express')();
            app.post('/api/user', (req, res) => {
              Object.assign(target, req.body);
            });
            """,
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["scan", "--project", str(self.root), "--format", "sarif"])
        self.assertEqual(exit_code, 0)
        sarif = json.loads(buf.getvalue())
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "ProtoScan")
        self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 1)

    def test_output_argument_writes_file(self) -> None:
        self._write(
            "server.js",
            """
            const app = require('express')();
            app.post('/api/user', (req, res) => {
              Object.assign(target, req.body);
            });
            """,
        )
        output_path = self.root / "report.html"
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(
                [
                    "scan",
                    "--project",
                    str(self.root),
                    "--format",
                    "json",
                    "--output",
                    "html",
                    str(output_path),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertTrue(output_path.exists())
        self.assertIn("<html", output_path.read_text().lower())

    def test_bundle_argument_writes_zip(self) -> None:
        self._write(
            "server.js",
            """
            const app = require('express')();
            app.post('/api/user', (req, res) => {
              Object.assign(target, req.body);
            });
            """,
        )
        bundle_path = self.root / "reports.zip"
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(
                [
                    "scan",
                    "--project",
                    str(self.root),
                    "--bundle",
                    str(bundle_path),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertTrue(bundle_path.exists())
        with zipfile.ZipFile(bundle_path) as zf:
            names = zf.namelist()
            self.assertIn("report.json", names)
            self.assertIn("report.sarif", names)

if __name__ == "__main__":  # pragma: no cover
    unittest.main()
