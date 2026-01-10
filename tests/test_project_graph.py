from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from protoscan.project_graph import build_project_graph


class ProjectGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_collects_exports_and_imports(self) -> None:
        controller = self.root / "controller.js"
        service = self.root / "service.js"
        service.write_text(
            """
            export function updateUser(data) {
                return data;
            }
            """
        )
        controller.write_text(
            """
            import { updateUser } from "./service.js";
            export function handler(req) {
                return updateUser(req.body);
            }
            """
        )
        graph = build_project_graph(self.root)
        self.assertIn(service.resolve(), graph.exports)
        self.assertIn("updateUser", graph.exports[service.resolve()])
        self.assertIn(controller.resolve(), graph.imports)
        found = any(str(dest).endswith("service.js") for _, dest in graph.imports[controller.resolve()])
        self.assertTrue(found)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
