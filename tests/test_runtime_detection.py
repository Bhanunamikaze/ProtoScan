from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from protoscan.runtime_detection import detect_runtime


class RuntimeDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write(self, relative: str, contents: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    def test_detects_node_framework_and_build_tool(self) -> None:
        package = {
            "dependencies": {"express": "^4.18.0", "react": "18"},
            "devDependencies": {"webpack": "^5"},
        }
        self._write("package.json", json.dumps(package))
        self._write("webpack.config.js", "module.exports = {}")
        meta = detect_runtime(self.root)
        self.assertIn("node", meta.runtimes)
        self.assertIn("browser", meta.runtimes)
        self.assertIn("Express.js", meta.frameworks)
        self.assertIn("Webpack", meta.build_tools)

    def test_detects_deno_and_typescript(self) -> None:
        self._write("deno.json", "{}")
        self._write("tsconfig.json", json.dumps({}))
        meta = detect_runtime(self.root)
        self.assertIn("deno", meta.runtimes)
        self.assertIn("typescript", meta.runtimes)

    def test_detects_bun_and_browser_via_files(self) -> None:
        self._write("bun.lockb", "")
        self._write("public/index.html", "<script>window.app()</script>")
        meta = detect_runtime(self.root)
        self.assertIn("bun", meta.runtimes)
        self.assertIn("browser", meta.runtimes)

    def test_detects_multiple_subprojects(self) -> None:
        api_pkg = {"dependencies": {"express": "^4.18.0"}}
        frontend_pkg = {"dependencies": {"react": "18.0.0"}}
        self._write("services/api/package.json", json.dumps(api_pkg))
        self._write("frontend/package.json", json.dumps(frontend_pkg))
        meta = detect_runtime(self.root)
        project_map = {project.path: project for project in meta.projects}
        self.assertIn("services/api", project_map)
        self.assertIn("frontend", project_map)
        self.assertIn("node", project_map["services/api"].runtimes)
        self.assertIn("browser", meta.runtimes)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
