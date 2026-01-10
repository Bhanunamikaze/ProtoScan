from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from protoscan.dataflow import build_flow_chains
from protoscan.gadget_detection import GadgetFinding
from protoscan.sink_detection import SinkFinding
from protoscan.source_detection import SourceFinding


class DataFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write(self, relative: str, contents: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def _line(self, path: Path, needle: str) -> int:
        for idx, line in enumerate(path.read_text().splitlines(), 1):
            if needle in line:
                return idx
        raise AssertionError(f"{needle!r} not found in {path}")

    def test_connects_source_and_sink_in_same_file(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            app.post('/api/user', (req, res) => {
              const data = req.body;
              Object.assign(target, data);
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=3,
            column=28,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=4,
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, data)",
        )
        chains = build_flow_chains(self.root, [source], [sink], [])
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].source, source)
        self.assertEqual(chains[0].sink, sink)
        self.assertEqual(chains[0].route, ("POST", "/api/user"))
        self.assertGreaterEqual(len(chains[0].exploit_steps), 2)

    def test_ignores_unrelated_variables(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            app.post('/api/user', (req, res) => {
              const unrelated = {};
              Object.assign(target, unrelated);
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=3,
            column=28,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=4,
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, unrelated)",
        )
        chains = build_flow_chains(self.root, [source], [sink], [])
        self.assertEqual(chains, [])

    def test_attaches_gadget_and_severity(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            app.post('/api/user', (req, res) => {
              const data = req.body;
              Object.assign(target, data);
              require('child_process').exec('ls');
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=3,
            column=28,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=4,
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, data)",
        )
        gadget = GadgetFinding(
            path=path,
            line=5,
            column=15,
            kind="gadget.rce.child_process.exec",
            snippet="require('child_process').exec('ls')",
        )
        chains = build_flow_chains(self.root, [source], [sink], [gadget])
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertIsNotNone(chain.gadget)
        self.assertEqual(chain.gadget, gadget)
        self.assertEqual(chain.severity, "critical")

    def test_schema_validation_downgrades_severity(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            const schema = { validate: (input) => input };
            app.post('/api/user', (req, res) => {
              const data = schema.validate(req.body, { stripUnknown: true });
              Object.assign(target, data);
              require('child_process').exec('ls');
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=4,
            column=36,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=5,
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, data)",
        )
        gadget = GadgetFinding(
            path=path,
            line=6,
            column=15,
            kind="gadget.rce.child_process.exec",
            snippet="require('child_process').exec('ls')",
        )
        chains = build_flow_chains(self.root, [source], [sink], [gadget])
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertEqual(chain.severity, "high")
        self.assertTrue(chain.metadata["hasSchemaValidation"])
        self.assertFalse(chain.metadata["requiresAuth"])

    def test_payload_variants_include_proto_find_guidance(self) -> None:
        path = self._write(
            "client.js",
            """
            const app = require('express')();
            const analytics = require('analytics-utils');
            app.get('/client/widget', (req, res) => {
              const params = req.query;
              Object.assign(window.config, params);
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=self._line(path, "req.query"),
            column=20,
            kind="browser.parser.analytics-utils",
            snippet="req.query",
        )
        sink = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign"),
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(window.config, params)",
        )
        chains = build_flow_chains(self.root, [source], [sink], [])
        self.assertEqual(len(chains), 1)
        labels = {variant.get("label") for variant in chains[0].payload_variants}
        self.assertIn("Parameter rotation (proto-find)", labels)
        self.assertIn("analytics-utils queue poisoning", labels)

    def test_schema_validation_without_strip_option_is_not_sanitized(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            const schema = { validate: (input) => input };
            app.post('/api/user', (req, res) => {
              const data = schema.validate(req.body);
              Object.assign(target, data);
              require('child_process').exec('ls');
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=self._line(path, "req.body"),
            column=36,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign"),
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, data)",
        )
        gadget = GadgetFinding(
            path=path,
            line=self._line(path, "child_process"),
            column=15,
            kind="gadget.rce.child_process.exec",
            snippet="require('child_process').exec('ls')",
        )
        chains = build_flow_chains(self.root, [source], [sink], [gadget])
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertEqual(chain.severity, "critical")
        self.assertFalse(chain.metadata["hasSchemaValidation"])

    def test_safe_parse_without_strip_option_is_not_sanitized(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            const schema = { safeParse: (input) => input };
            app.post('/api/user', (req, res) => {
              const data = schema.safeParse(req.body);
              Object.assign(target, data);
              require('child_process').exec('ls');
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=self._line(path, "req.body"),
            column=36,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign"),
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, data)",
        )
        gadget = GadgetFinding(
            path=path,
            line=self._line(path, "child_process"),
            column=15,
            kind="gadget.rce.child_process.exec",
            snippet="require('child_process').exec('ls')",
        )
        chains = build_flow_chains(self.root, [source], [sink], [gadget])
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertEqual(chain.severity, "critical")
        self.assertFalse(chain.metadata["hasSchemaValidation"])

    def test_safe_parse_with_strip_unknown_is_sanitized(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            const schema = { safeParse: (input) => input };
            app.post('/api/user', (req, res) => {
              const data = schema.safeParse(req.body, { stripUnknown: true });
              Object.assign(target, data);
              require('child_process').exec('ls');
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=self._line(path, "req.body"),
            column=36,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign"),
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, data)",
        )
        gadget = GadgetFinding(
            path=path,
            line=self._line(path, "child_process"),
            column=15,
            kind="gadget.rce.child_process.exec",
            snippet="require('child_process').exec('ls')",
        )
        chains = build_flow_chains(self.root, [source], [sink], [gadget])
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertEqual(chain.severity, "high")
        self.assertTrue(chain.metadata["hasSchemaValidation"])

    def test_requires_auth_downgrades_severity(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            function requireAuth() {}
            app.post('/api/user', (req, res) => {
              requireAuth();
              const data = req.body;
              Object.assign(target, data);
              require('child_process').exec('ls');
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=5,
            column=28,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=6,
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, data)",
        )
        gadget = GadgetFinding(
            path=path,
            line=7,
            column=15,
            kind="gadget.rce.child_process.exec",
            snippet="require('child_process').exec('ls')",
        )
        chains = build_flow_chains(self.root, [source], [sink], [gadget])
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertEqual(chain.severity, "high")
        self.assertTrue(chain.metadata["requiresAuth"])
        self.assertFalse(chain.metadata["hasSchemaValidation"])

    def test_destructuring_propagates_taint(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            app.post('/api/user', (req, res) => {
              const { settings } = req.body;
              const { profile: account } = settings;
              Object.assign(target, account);
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=self._line(path, "req.body"),
            column=28,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign"),
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, account)",
        )
        chains = build_flow_chains(self.root, [source], [sink], [])
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertEqual(chain.route, ("POST", "/api/user"))

    def test_routes_are_not_cross_linked(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            function requireAuth() {}
            app.post('/api/user', (req, res) => {
              requireAuth();
              const data = schema.validate(req.body);
              Object.assign(target, data);
            });

            app.post('/api/settings', (req, res) => {
              const cfg = req.body;
              Object.assign(settings, cfg);
            });
            """,
        )
        user_body_line = self._line(path, "schema.validate(req.body")
        settings_body_line = self._line(path, "const cfg = req.body")
        source_user = SourceFinding(
            path=path,
            line=user_body_line,
            column=15,
            kind="http.request.body",
            snippet="req.body",
        )
        source_settings = SourceFinding(
            path=path,
            line=settings_body_line,
            column=15,
            kind="http.request.body",
            snippet="req.body",
        )
        sink_user = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign(target, data)"),
            column=5,
            kind="sink.object.assign",
            snippet="Object.assign(target, data)",
        )
        chains = build_flow_chains(self.root, [source_user, source_settings], [sink_user], [])
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].source.line, user_body_line)

    def test_prefers_http_source_when_multiple_sources_share_sink(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            const runtimeConfig = {};
            app.post('/api/user', (req, res) => {
              Object.assign(target, runtimeConfig);
            });
            """,
        )
        config_source = SourceFinding(
            path=path,
            line=self._line(path, "runtimeConfig ="),
            column=5,
            kind="config.process.env",
            snippet="runtimeConfig",
        )
        http_source = SourceFinding(
            path=path,
            line=self._line(path, "app.post"),
            column=28,
            kind="http.request.body",
            snippet="runtimeConfig",
        )
        sink = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign"),
            column=3,
            kind="sink.object.assign",
            snippet="Object.assign(target, runtimeConfig)",
        )
        chains = build_flow_chains(self.root, [config_source, http_source], [sink], [])
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].source.kind, "http.request.body")

    def test_bracket_property_access_propagates_taint(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            app.post('/api/user', (req, res) => {
              const payload = req.body["settings"];
              Object.assign(target, payload);
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=self._line(path, "req.body"),
            column=28,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign"),
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, payload)",
        )
        chains = build_flow_chains(self.root, [source], [sink], [])
        self.assertEqual(len(chains), 1)

    def test_class_field_propagates_taint(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            app.post('/api/user', (req, res) => {
              class Handler {
                payload = req.body;
                send() {
                  Object.assign(target, this.payload);
                }
              }
              new Handler().send();
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=self._line(path, "req.body"),
            column=28,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign"),
            column=11,
            kind="sink.object.assign",
            snippet="Object.assign(target, this.payload)",
        )
        chains = build_flow_chains(self.root, [source], [sink], [])
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].route, ("POST", "/api/user"))

    def test_arrow_function_implicit_return_propagates_taint(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            const pickBody = (req) => req.body;
            app.post('/api/user', (req, res) => {
              const data = pickBody(req);
              Object.assign(target, data);
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=self._line(path, "(req) => req.body"),
            column=31,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign"),
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, data)",
        )
        chains = build_flow_chains(self.root, [source], [sink], [])
        self.assertEqual(len(chains), 1)

    def test_client_gadget_metadata_is_flagged(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            app.post('/api/dom', (req, res) => {
              const payload = req.body;
              Object.assign(target, payload);
              DOMPurify.sanitize(payload.html);
            });
            """
        )
        source = SourceFinding(
            path=path,
            line=self._line(path, "req.body"),
            column=28,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign"),
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, payload)",
        )
        gadget = GadgetFinding(
            path=path,
            line=self._line(path, "DOMPurify.sanitize"),
            column=15,
            kind="gadget.client.dom.dompurify",
            snippet="DOMPurify.sanitize(payload.html)",
        )
        chains = build_flow_chains(self.root, [source], [sink], [gadget])
        self.assertEqual(len(chains), 1)
        metadata = chains[0].metadata
        self.assertTrue(metadata["clientGadget"])
        self.assertIn("DOM", metadata.get("gadgetImpact", ""))
        self.assertIn("ALLOWED", metadata.get("gadgetRequirement", ""))

    def test_property_write_marks_parent_tainted(self) -> None:
        path = self._write(
            "app.js",
            """
            const app = require('express')();
            app.post('/api/user', (req, res) => {
              const outgoing = {};
              outgoing.user = req.body.user;
              Object.assign(target, outgoing);
            });
            """,
        )
        source = SourceFinding(
            path=path,
            line=self._line(path, "req.body"),
            column=28,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=path,
            line=self._line(path, "Object.assign"),
            column=15,
            kind="sink.object.assign",
            snippet="Object.assign(target, outgoing)",
        )
        chains = build_flow_chains(self.root, [source], [sink], [])
        self.assertEqual(len(chains), 1)

    def test_links_across_files_via_exported_function(self) -> None:
        controller = self._write(
            "controller.js",
            """
            const app = require('express')();
            const service = require('./service');

            app.post('/api/user', (req, res) => {
              const payload = req.body;
              service.updateUser(payload);
            });
            """,
        )
        service = self._write(
            "service.js",
            """
            function updateUser(data) {
              Object.assign(target, data);
            }

            module.exports = { updateUser };
            """,
        )
        source = SourceFinding(
            path=controller,
            line=self._line(controller, "req.body"),
            column=5,
            kind="http.request.body",
            snippet="req.body",
        )
        sink = SinkFinding(
            path=service,
            line=self._line(service, "Object.assign"),
            column=3,
            kind="sink.object.assign",
            snippet="Object.assign(target, data)",
        )
        chains = build_flow_chains(self.root, [source], [sink], [])
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertEqual(chain.source.path, controller)
        self.assertEqual(chain.sink.path, service)
        self.assertEqual(chain.route, ("POST", "/api/user"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
