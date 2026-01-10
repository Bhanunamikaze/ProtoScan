from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from protoscan.gadget_detection import find_gadgets


class GadgetDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write(self, relative: str, contents: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    def test_detects_rce_and_template_gadgets(self) -> None:
        code = """
        const child_process = require('child_process');
        child_process.exec('ls');
        execSync('pwd');
        const vm = require('vm');
        vm.runInNewContext('code', {});
        const ejs = require('ejs');
        ejs.render('hi', data);
        new Function('return 1');
        eval(userInput);
        """
        self._write("gadgets.js", code)
        findings = find_gadgets(self.root)
        kinds = {finding.kind for finding in findings}
        self.assertIn("gadget.rce.child_process.exec", kinds)
        self.assertIn("gadget.rce.child_process.execSync", kinds)
        self.assertIn("gadget.rce.vm.runInNewContext", kinds)
        self.assertIn("gadget.template.ejs.render", kinds)
        self.assertIn("gadget.rce.function.constructor", kinds)
        self.assertIn("gadget.rce.eval", kinds)

    def test_detects_dom_and_http_gadgets(self) -> None:
        code = """
        const axios = require('axios');
        const http = require('http');
        const https = require('https');
        const tls = require('tls');
        const { Worker } = require('worker_threads');
        const DOMPurify = require('dompurify');
        const sanitizeHtml = require('sanitize-html');
        document.body.innerHTML = userHtml;
        axios.get('/api', { proxy: config.proxy });
        fetch('/resource');
        http.request({ hostname: pollutedHost });
        https.get({ hostname: pollutedHost });
        tls.connect({ host: pollutedHost });
        new Worker('./job.js', { env: pollutedEnv });
        DOMPurify.sanitize(userHtml);
        sanitizeHtml(userHtml);
        analytics.track('event', payload);
        dataLayer.push({ event: 'gtm.js' });
        gtag('config', 'UA-123');
        BOOMR.init({});
        utag.view('page');
        wistiaEmbeds.push({ id: 'video' });
        """
        self._write("dom.js", code)
        findings = find_gadgets(self.root)
        kinds = {finding.kind for finding in findings}
        self.assertIn("gadget.dom.innerHTML", kinds)
        self.assertIn("gadget.http.axios", kinds)
        self.assertIn("gadget.http.fetch", kinds)
        self.assertIn("gadget.http.node.request", kinds)
        self.assertIn("gadget.https.node.request", kinds)
        self.assertIn("gadget.tls.connect", kinds)
        self.assertIn("gadget.runtime.worker_threads.worker", kinds)
        self.assertIn("gadget.client.dom.dompurify", kinds)
        self.assertIn("gadget.client.dom.sanitizeHtml", kinds)
        self.assertIn("gadget.client.analytics.segment", kinds)
        self.assertIn("gadget.client.analytics.gtm", kinds)
        self.assertIn("gadget.client.analytics.google", kinds)
        self.assertIn("gadget.client.analytics.akamai", kinds)
        self.assertIn("gadget.client.analytics.tealium", kinds)
        self.assertIn("gadget.client.media.wistia", kinds)

    def test_detects_react_vue_and_jquery_gadgets(self) -> None:
        code = """
        const React = require('react');
        const ReactDOM = require('react-dom');
        ReactDOM.render(React.createElement(App, props), document.getElementById('root'));
        ReactDOM.hydrate(React.createElement('div', props), document.body);
        const app = new Vue({ template: polluted });
        Vue.createApp({ template: polluted }).mount('#app');
        if (props.isAdmin) { dangerous(); }
        const { role } = this.props;
        if (this.$props.permissions) { dangerous(); }
        const { isAuthenticated } = this.$props;
        $(selector).html(payload);
        jQuery(selector).append(payload);
        """
        self._write("ui.js", code)
        findings = find_gadgets(self.root)
        kinds = {finding.kind for finding in findings}
        self.assertIn("gadget.ui.react.render", kinds)
        self.assertIn("gadget.ui.react.hydrate", kinds)
        self.assertIn("gadget.ui.react.createElement", kinds)
        self.assertIn("gadget.ui.vue.instance", kinds)
        self.assertIn("gadget.ui.vue.createApp", kinds)
        self.assertIn("gadget.ui.jquery.html", kinds)
        self.assertIn("gadget.ui.jquery.append", kinds)
        self.assertIn("gadget.ui.react.props.auth", kinds)
        self.assertIn("gadget.ui.vue.props.auth", kinds)

    def test_detects_ppmap_fingerprinted_gadgets(self) -> None:
        code = """
        window.embedly('card', payload);
        filterXSS(payload.html);
        ko.applyBindings({});
        _.template('tpl');
        Marionette.View.extend({ template: payload.tpl });
        recaptcha.render('captcha');
        Sprint('#app').html(payload.html);
        window[SwiftypeObject || '_st']('install');
        utag.view(payload.meta);
        twq('track', 'Purchase', payload.meta);
        Zepto('#target').html(payload.html);
        Popper.createPopper(button, tooltip);
        pendo.initialize({ visitor: payload.visitor });
        i18next.init({});
        Demandbase.Config = Demandbase.Config || {};
        analyticsGtagManager({ containerId: 'GTM-123' });
        mutiny.track('event', payload.meta);
        AMP.push({ type: 'custom' });
        goog.require('goog.html.sanitizer.HtmlSanitizer');
        """
        self._write("fingerprints.js", code)
        findings = find_gadgets(self.root)
        kinds = {finding.kind for finding in findings}
        self.assertIn("gadget.client.media.embedly", kinds)
        self.assertIn("gadget.client.dom.filterXSS", kinds)
        self.assertIn("gadget.client.ui.knockout", kinds)
        self.assertIn("gadget.template.lodash", kinds)
        self.assertIn("gadget.client.ui.marionette", kinds)
        self.assertIn("gadget.client.security.recaptcha", kinds)
        self.assertIn("gadget.client.dom.sprint", kinds)
        self.assertIn("gadget.client.analytics.swiftype", kinds)
        self.assertIn("gadget.client.analytics.twitter", kinds)
        self.assertIn("gadget.client.ui.zepto", kinds)
        self.assertIn("gadget.client.ui.popper", kinds)
        self.assertIn("gadget.client.analytics.pendo", kinds)
        self.assertIn("gadget.client.i18n.i18next", kinds)
        self.assertIn("gadget.client.analytics.demandbase", kinds)
        self.assertIn("gadget.client.analytics.analyticsjsPlugin", kinds)
        self.assertIn("gadget.client.analytics.mutiny", kinds)
        self.assertIn("gadget.client.dom.amp", kinds)
        self.assertIn("gadget.client.framework.closure", kinds)

    def test_client_fixture_contains_segment_and_dompurify(self) -> None:
        fixture = Path(__file__).resolve().parents[0] / "fixtures" / "client_gadgets"
        findings = find_gadgets(fixture)
        kinds = {finding.kind for finding in findings}
        self.assertIn("gadget.client.dom.dompurify", kinds)
        self.assertIn("gadget.client.analytics.segment", kinds)
        self.assertIn("gadget.client.dom.sanitizeHtml", kinds)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
