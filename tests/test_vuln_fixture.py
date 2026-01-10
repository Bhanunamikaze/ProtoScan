from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import unittest

from protoscan.cli import main

FIXTURE_DIR = Path(__file__).resolve().parents[0] / "fixtures" / "vuln_app"


class VulnerabilityFixtureTests(unittest.TestCase):
    def _scan(self) -> dict:
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["scan", "--project", str(FIXTURE_DIR), "--format", "json"])
        self.assertEqual(exit_code, 0)
        return json.loads(buf.getvalue())

    def test_dependency_cves_detected(self) -> None:
        report = self._scan()
        findings = {item["name"] for item in report["dependencyReport"]["findings"]}
        for name in ["lodash", "qs", "minimist", "merge", "deep-extend"]:
            self.assertIn(name, findings)

    def test_sources_sinks_and_gadgets_detected(self) -> None:
        report = self._scan()
        kinds = {item["kind"] for item in report["sourceFindings"]}
        for expected in [
            "http.request.body",
            "cli.process.argv",
            "websocket.onMessage",
            "config.process.env",
        ]:
            self.assertIn(expected, kinds)
        sink_kinds = {item["kind"] for item in report["sinkFindings"]}
        for expected in [
            "sink.object.assign",
            "sink.package.merge",
            "sink.parser.qs",
            "sink.json.parse.reviver",
            "sink.loop.assign",
            "sink.constructor.prototype",
            "sink.lodash.set",
            "sink.lodash.defaultsDeep",
        ]:
            self.assertIn(expected, sink_kinds)
        gadget_kinds = {item["kind"] for item in report["gadgetFindings"]}
        for expected in [
            "gadget.rce.child_process.exec",
            "gadget.rce.vm.runInNewContext",
            "gadget.template.ejs.render",
        ]:
            self.assertIn(expected, gadget_kinds)

    def test_flow_chains_present(self) -> None:
        report = self._scan()
        self.assertGreater(len(report["flowChains"]), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
