from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from protoscan.sink_detection import find_sinks


class SinkDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write(self, relative: str, contents: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    def test_detects_merge_and_dynamic_sinks(self) -> None:
        code = """
        const _ = require('lodash');
        const merge = require('merge');
        const qs = require('qs');
        const setValue = require('set-value');
        const dotProp = require('dot-prop');
        const ini = require('ini');
        const toml = require('@iarna/toml');
        const target = {};
        Object.assign(target, req.body);
        const combined = { ...defaults, ...req.body };
        const deep = merge({}, req.body);
        const lodashMerge = _.merge({}, req.body);
        _.set(target, "__proto__.polluted", true);
        setValue(target, "__proto__.polluted", true);
        dotProp.set(target, "__proto__.polluted", true);
        _.defaultsDeep(target, req.body);
        const params = qs.parse(raw);
        const iniConfig = ini.parse(raw);
        const tomlConfig = toml.parse(raw);
        const parsed = JSON.parse(raw, (key, value) => value);
        Object.defineProperty(target, key, { value: 1 });
        Reflect.set(target, userKey, value);
        target[userKey] = value;
        """
        self._write("sinks.js", code)
        findings = find_sinks(self.root)
        kinds = {finding.kind for finding in findings}
        self.assertIn("sink.object.assign", kinds)
        self.assertIn("sink.object.spread", kinds)
        self.assertIn("sink.package.merge", kinds)
        self.assertIn("sink.lodash.merge", kinds)
        self.assertIn("sink.parser.qs", kinds)
        self.assertIn("sink.json.parse.reviver", kinds)
        self.assertIn("sink.dynamic.defineProperty", kinds)
        self.assertIn("sink.dynamic.reflectSet", kinds)
        self.assertIn("sink.dynamic.property.assignment", kinds)
        self.assertIn("sink.lodash.set", kinds)
        self.assertIn("sink.lodash.defaultsDeep", kinds)
        self.assertIn("sink.path.setValue", kinds)
        self.assertIn("sink.path.dotProp", kinds)
        self.assertIn("sink.parser.ini", kinds)
        self.assertIn("sink.parser.toml", kinds)

    def test_detects_for_in_loop_sink(self) -> None:
        code = """
        const dest = {};
        const source = {};
        for (const key in source) {
          dest[key] = source[key];
        }
        """
        self._write("loop.js", code)
        findings = find_sinks(self.root)
        kinds = {finding.kind for finding in findings}
        self.assertIn("sink.loop.assign", kinds)

    def test_detects_client_side_parsers(self) -> None:
        code = """
        const $ = require('jquery');
        const can = { deparam: () => ({}) };
        const Arg = { parse: () => ({}) };
        const paramsParse = require('analytics-utils').paramsParse;
        const query = require('querystring');
        $.deparam(window.location.search);
        jQuery.deparam(window.location.hash);
        $.bbq.getState();
        jQuery.query.get('foo');
        can.deparam(window.location.search);
        Arg.parse(location.search);
        paramsParse('?__proto__[test]=1');
        purl(window.location.href);
        """
        self._write("client.js", code)
        findings = find_sinks(self.root)
        kinds = {finding.kind for finding in findings}
        self.assertIn("sink.browser.parser", kinds)

    def test_ignores_loop_with_hasown(self) -> None:
        code = """
        const dest = {};
        const source = {};
        for (const key in source) {
          if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
          dest[key] = source[key];
        }
        """
        self._write("safeLoop.js", code)
        findings = find_sinks(self.root)
        kinds = {finding.kind for finding in findings}
        self.assertNotIn("sink.loop.assign", kinds)

    def test_detects_constructor_prototype_assignment(self) -> None:
        code = """
        function Unsafe(obj) {
          obj.constructor.prototype.evil = true;
        }
        """
        self._write("ctor.js", code)
        findings = find_sinks(self.root)
        kinds = {finding.kind for finding in findings}
        self.assertIn("sink.constructor.prototype", kinds)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
