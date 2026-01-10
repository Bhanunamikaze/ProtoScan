from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import unittest

from protoscan.cli import main


FIXTURE_DIR = Path(__file__).resolve().parents[0] / "fixtures" / "runtime_gadgets"


class RuntimeGadgetFixtureTests(unittest.TestCase):
    def test_node_and_deno_gadgets_detected(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["scan", "--project", str(FIXTURE_DIR), "--format", "json"])
        self.assertEqual(exit_code, 0)
        report = json.loads(buf.getvalue())
        gadget_kinds = {item["kind"] for item in report["gadgetFindings"]}
        self.assertIn("gadget.http.node.request", gadget_kinds)
        self.assertIn("gadget.https.node.request", gadget_kinds)
        self.assertIn("gadget.deno.run", gadget_kinds)
        self.assertIn("gadget.deno.command", gadget_kinds)
        self.assertIn("gadget.deno.temp", gadget_kinds)
        self.assertIn("gadget.deno.fs", gadget_kinds)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
