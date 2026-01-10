from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from protoscan.source_detection import find_sources


class SourceDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write(self, relative: str, contents: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    def test_detects_http_config_and_browser_sources(self) -> None:
        server_js = """
        const http = require('http');
        const fs = require('fs');
        const express = require('express');
        const minimist = require('minimist');

        http.createServer((req, res) => {
          const body = req.body;
          const query = req.query;
          console.log(process.env.SECRET, process.argv);
          const cfg = require('./config.json');
          const local = fs.readFileSync('./local.yaml');
          const args = minimist(process.argv.slice(2));
        });

        const ws = require('ws');
        ws.on('message', () => {});
        """
        client_js = """
        function client() {
          const url = new URLSearchParams(window.location.search);
          const token = localStorage.getItem('token');
          window.addEventListener('message', () => {});
        }
        """
        self._write("server.js", server_js)
        self._write("client.js", client_js)

        findings = find_sources(self.root)
        kinds = {finding.kind for finding in findings}
        self.assertIn("http.request.body", kinds)
        self.assertIn("http.request.query", kinds)
        self.assertIn("config.process.env", kinds)
        self.assertIn("cli.process.argv", kinds)
        self.assertIn("config.file.require", kinds)
        self.assertIn("config.file.readFile", kinds)
        self.assertIn("cli.parser.minimist", kinds)
        self.assertIn("websocket.onMessage", kinds)
        self.assertIn("browser.url.searchParams", kinds)
        self.assertIn("browser.storage", kinds)
        self.assertIn("browser.window.message", kinds)

    def test_detects_nested_location_access(self) -> None:
        client_js = """
        const search = window.location.search;
        const hash = document.location.hash;
        const base = window.location;
        """
        self._write("client2.js", client_js)
        findings = find_sources(self.root)
        kinds = {finding.kind for finding in findings}
        self.assertIn("browser.location", kinds)
        self.assertIn("browser.location.search", kinds)
        self.assertIn("browser.location.hash", kinds)

    def test_detects_client_parser_fixture_sources(self) -> None:
        fixture = Path(__file__).resolve().parents[0] / "fixtures" / "client_parsers"
        findings = find_sources(fixture)
        kinds = {finding.kind for finding in findings}
        self.assertIn("browser.parser.component-querystring", kinds)
        self.assertIn("browser.parser.analytics-utils", kinds)
        self.assertIn("browser.parser.arg-js", kinds)
        self.assertIn("browser.parser.can-deparam", kinds)
        self.assertIn("browser.parser.jquery-bbq", kinds)
        self.assertIn("browser.parser.purl", kinds)
        self.assertIn("browser.url.parse", kinds)
        self.assertIn("browser.url.searchParams", kinds)
        self.assertIn("browser.location.hash", kinds)
        self.assertIn("browser.location.href", kinds)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
