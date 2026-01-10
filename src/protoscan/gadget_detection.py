"""Gadget detection for prototype pollution exploit chains."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from .ast_utils import (
    MAX_FILES,
    identifier_name,
    iter_source_files,
    node_text,
    parser_for_extension,
    walk,
)
from .client_fingerprints import client_gadget_rules

CALL_MEMBER_RULES = [
    {"object": "child_process", "property": "exec", "kind": "gadget.rce.child_process.exec"},
    {"object": "child_process", "property": "execSync", "kind": "gadget.rce.child_process.execSync"},
    {"object": "child_process", "property": "spawn", "kind": "gadget.rce.child_process.spawn"},
    {"object": "child_process", "property": "fork", "kind": "gadget.rce.child_process.fork"},
    {"object": "vm", "property": "runInNewContext", "kind": "gadget.rce.vm.runInNewContext"},
    {"object": "vm", "property": "runInContext", "kind": "gadget.rce.vm.runInContext"},
    {"object": "ejs", "property": "render", "kind": "gadget.template.ejs.render"},
    {"object": "pug", "property": "render", "kind": "gadget.template.pug.render"},
    {"object": "handlebars", "property": "compile", "kind": "gadget.template.handlebars.compile"},
    {"object": "mustache", "property": "render", "kind": "gadget.template.mustache.render"},
    {"object": "fs", "property": "readFileSync", "kind": "gadget.fs.readFileSync"},
    {"object": "axios", "property": "get", "kind": "gadget.http.axios"},
    {"object": "axios", "property": "post", "kind": "gadget.http.axios"},
    {"object": "axios", "property": "request", "kind": "gadget.http.axios"},
    {"object": "http", "property": "request", "kind": "gadget.http.node.request"},
    {"object": "http", "property": "get", "kind": "gadget.http.node.request"},
    {"object": "https", "property": "request", "kind": "gadget.https.node.request"},
    {"object": "https", "property": "get", "kind": "gadget.https.node.request"},
    {"object": "tls", "property": "connect", "kind": "gadget.tls.connect"},
    {"object": "Deno", "property": "run", "kind": "gadget.deno.run"},
    {"object": "Deno", "property": "Command", "kind": "gadget.deno.command"},
    {"object": "Deno", "property": "makeTempDir", "kind": "gadget.deno.temp"},
    {"object": "Deno", "property": "makeTempDirSync", "kind": "gadget.deno.temp"},
    {"object": "Deno", "property": "makeTempFile", "kind": "gadget.deno.temp"},
    {"object": "Deno", "property": "makeTempFileSync", "kind": "gadget.deno.temp"},
    {"object": "Deno", "property": "open", "kind": "gadget.deno.fs"},
    {"object": "Deno", "property": "openSync", "kind": "gadget.deno.fs"},
    {"object": "Deno", "property": "writeFile", "kind": "gadget.deno.fs"},
    {"object": "Deno", "property": "writeFileSync", "kind": "gadget.deno.fs"},
    {"object": "Deno", "property": "writeTextFile", "kind": "gadget.deno.fs"},
    {"object": "Deno", "property": "writeTextFileSync", "kind": "gadget.deno.fs"},
    {"object": "Deno", "property": "mkdir", "kind": "gadget.deno.fs"},
    {"object": "Deno", "property": "mkdirSync", "kind": "gadget.deno.fs"},
    {"object": "DOMPurify", "property": "sanitize", "kind": "gadget.client.dom.dompurify"},
    {"object": "analytics", "kind": "gadget.client.analytics.segment"},
    {"object": "dataLayer", "property": "push", "kind": "gadget.client.analytics.gtm"},
    {"object": "google_tag_manager", "kind": "gadget.client.analytics.gtm"},
    {"object": "BOOMR", "kind": "gadget.client.analytics.akamai"},
    {"object": "utag", "kind": "gadget.client.analytics.tealium"},
    {"object": "_satellite", "kind": "gadget.client.analytics.adobe"},
    {"object": "wistiaEmbeds", "property": "push", "kind": "gadget.client.media.wistia"},
    {"object": "wistiaEmbeds", "property": "init", "kind": "gadget.client.media.wistia"},
    {"object": "ReactDOM", "property": "render", "kind": "gadget.ui.react.render"},
    {"object": "ReactDOM", "property": "hydrate", "kind": "gadget.ui.react.hydrate"},
    {"object": "React", "property": "createElement", "kind": "gadget.ui.react.createElement"},
    {"object": "Vue", "property": "createApp", "kind": "gadget.ui.vue.createApp"},
]

CALL_IDENTIFIER_RULES = {
    "exec": "gadget.rce.child_process.exec",
    "execSync": "gadget.rce.child_process.execSync",
    "spawn": "gadget.rce.child_process.spawn",
    "fork": "gadget.rce.child_process.fork",
    "eval": "gadget.rce.eval",
    "setTimeout": "gadget.timer.setTimeout",
    "fetch": "gadget.http.fetch",
    "sanitizeHtml": "gadget.client.dom.sanitizeHtml",
    "gtag": "gadget.client.analytics.google",
    "ga": "gadget.client.analytics.google",
}

NEW_IDENTIFIER_RULES = {
    "Function": "gadget.rce.function.constructor",
    "Vue": "gadget.ui.vue.instance",
    "Worker": "gadget.runtime.worker_threads.worker",
    "Deno.Command": "gadget.deno.command",
}

IDENTIFIER_REFERENCE_RULES: Dict[str, str] = {}

MEMBER_REFERENCE_RULES: List[Dict[str, str]] = []

DOM_SINKS = {
    "innerHTML": "gadget.dom.innerHTML",
    "outerHTML": "gadget.dom.outerHTML",
    "insertAdjacentHTML": "gadget.dom.insertAdjacentHTML",
}

JQUERY_ROOTS = {"$", "jQuery"}
JQUERY_DOM_METHODS = {
    "html": "gadget.ui.jquery.html",
    "append": "gadget.ui.jquery.append",
    "prepend": "gadget.ui.jquery.prepend",
    "before": "gadget.ui.jquery.before",
    "after": "gadget.ui.jquery.after",
    "text": "gadget.ui.jquery.text",
}

SENSITIVE_AUTH_PROPS = {
    "isAdmin",
    "admin",
    "role",
    "roles",
    "isAuthenticated",
    "authenticated",
    "auth",
    "hasAccess",
    "allowAdmin",
    "permissions",
    "permission",
}

REACT_PROP_BASES = {"props", "this.props", "state", "this.state", "context", "this.context"}
VUE_PROP_BASES = {"this.$props", "this.$data", "this.$options", "this.$root", "this.$store", "$props", "$data", "$store"}


def _register_client_fingerprints() -> None:
    for entry in client_gadget_rules():
        kind = entry.get("kind")
        if not isinstance(kind, str):
            continue
        for identifier in entry.get("callIdentifiers", []) or []:
            if isinstance(identifier, str):
                CALL_IDENTIFIER_RULES.setdefault(identifier, kind)
        for member in entry.get("callMembers", []) or []:
            obj = member.get("object")
            if not isinstance(obj, str):
                continue
            prop = member.get("property")
            rule = {"object": obj, "kind": kind}
            if isinstance(prop, str):
                rule["property"] = prop  # type: ignore[assignment]
            if rule not in CALL_MEMBER_RULES:
                CALL_MEMBER_RULES.append(rule)
        for identifier in entry.get("newIdentifiers", []) or []:
            if isinstance(identifier, str):
                NEW_IDENTIFIER_RULES.setdefault(identifier, kind)
        for identifier in entry.get("identifierReferences", []) or []:
            if isinstance(identifier, str):
                IDENTIFIER_REFERENCE_RULES.setdefault(identifier, kind)
        for member in entry.get("memberReferences", []) or []:
            obj = member.get("object")
            if not isinstance(obj, str):
                continue
            prop = member.get("property")
            rule = {"object": obj, "kind": kind}
            if isinstance(prop, str):
                rule["property"] = prop  # type: ignore[assignment]
            MEMBER_REFERENCE_RULES.append(rule)


_register_client_fingerprints()


def _is_jquery_chain(node, source: bytes) -> bool:
    if node is None:
        return False
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        return _is_jquery_chain(func, source)
    if node.type == "member_expression":
        return _is_jquery_chain(node.child_by_field_name("object"), source)
    name = identifier_name(node, source)
    return bool(name and name in JQUERY_ROOTS)


def _jquery_method_kind(object_node, prop: str, source: bytes) -> str | None:
    if prop not in JQUERY_DOM_METHODS:
        return None
    if _is_jquery_chain(object_node, source):
        return JQUERY_DOM_METHODS[prop]
    return None


def _matches_context(base: str | None, contexts) -> bool:
    if not base:
        return False
    for context in contexts:
        if base == context or base.startswith(f"{context}."):
            return True
    return False


def _react_vue_context(base: str | None) -> str | None:
    if _matches_context(base, REACT_PROP_BASES):
        return "react"
    if _matches_context(base, VUE_PROP_BASES):
        return "vue"
    return None


@dataclass(frozen=True, slots=True)
class GadgetFinding:
    """Represents a gadget that could be triggered via pollution."""

    path: Path
    line: int
    column: int
    kind: str
    snippet: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "path": str(self.path),
            "line": self.line,
            "column": self.column,
            "kind": self.kind,
            "snippet": self.snippet,
        }


def _emit(findings: List[GadgetFinding], path: Path, node, source: bytes, kind: str) -> None:
    snippet = node_text(node, source).strip()
    line, column = node.start_point
    findings.append(
        GadgetFinding(
            path=path,
            line=line + 1,
            column=column + 1,
            kind=kind,
            snippet=snippet,
        )
    )


def _handle_call_expression(findings, path, node, source: bytes) -> None:
    func = node.child_by_field_name("function")
    if func is None:
        return
    if func.type == "identifier":
        name = identifier_name(func, source)
        if not name:
            return
        rule = CALL_IDENTIFIER_RULES.get(name)
        if rule:
            _emit(findings, path, node, source, rule)
            return
    if func.type == "member_expression":
        object_node = func.child_by_field_name("object")
        base = identifier_name(object_node, source)
        prop = identifier_name(func.child_by_field_name("property"), source)
        base_root = base.split(".")[0] if base else None
        if base_root:
            for rule in CALL_MEMBER_RULES:
                obj = rule.get("object")
                if not obj:
                    continue
                if base_root != obj and base != obj:
                    continue
                expected_prop = rule.get("property")
                if expected_prop and prop != expected_prop:
                    continue
                _emit(findings, path, node, source, rule["kind"])
                return
        if prop:
            jquery_kind = _jquery_method_kind(object_node, prop, source)
            if jquery_kind:
                _emit(findings, path, node, source, jquery_kind)
                return


def _handle_new_expression(findings, path, node, source: bytes) -> None:
    constructor = node.child_by_field_name("constructor")
    if constructor is None:
        return
    name = identifier_name(constructor, source)
    if not name:
        return
    rule = NEW_IDENTIFIER_RULES.get(name)
    if rule:
        _emit(findings, path, node, source, rule)


def _handle_assignment_expression(findings, path, node, source: bytes) -> None:
    left = node.child_by_field_name("left")
    if left is None or left.type != "member_expression":
        return
    prop = identifier_name(left.child_by_field_name("property"), source)
    if not prop:
        return
    kind = DOM_SINKS.get(prop)
    if kind:
        _emit(findings, path, node, source, kind)


def _match_member_reference(base: str | None, prop: str | None) -> str | None:
    if not base:
        return None
    for rule in MEMBER_REFERENCE_RULES:
        obj = rule.get("object")
        if obj and base != obj:
            continue
        expected = rule.get("property")
        if expected and expected != prop:
            continue
        return rule.get("kind")
    return None


def _handle_member_expression(findings, path, node, source: bytes) -> None:
    prop = identifier_name(node.child_by_field_name("property"), source)
    base = identifier_name(node.child_by_field_name("object"), source)
    kind = _match_member_reference(base, prop)
    if kind:
        _emit(findings, path, node, source, kind)
    if not prop or prop not in SENSITIVE_AUTH_PROPS:
        return
    context = _react_vue_context(base)
    if context == "react":
        _emit(findings, path, node, source, "gadget.ui.react.props.auth")
    elif context == "vue":
        _emit(findings, path, node, source, "gadget.ui.vue.props.auth")


def _handle_react_vue_destructuring(findings, path, node, source: bytes) -> None:
    pattern = node.child_by_field_name("name")
    value = node.child_by_field_name("value")
    if pattern is None or value is None or pattern.type != "object_pattern":
        return
    base = identifier_name(value, source)
    context = _react_vue_context(base)
    if not context:
        return
    for child in pattern.named_children:
        key = None
        if child.type == "shorthand_property_identifier_pattern":
            key = identifier_name(child, source)
        elif child.type == "pair_pattern":
            key = identifier_name(child.child_by_field_name("key"), source)
            if key and key in SENSITIVE_AUTH_PROPS:
                kind = "gadget.ui.react.props.auth" if context == "react" else "gadget.ui.vue.props.auth"
                _emit(findings, path, child, source, kind)


def _handle_identifier_reference(findings, path, node, source: bytes) -> None:
    name = identifier_name(node, source)
    if not name:
        return
    kind = IDENTIFIER_REFERENCE_RULES.get(name)
    if kind:
        _emit(findings, path, node, source, kind)


def find_gadgets(project_root: Path, max_files: int = MAX_FILES) -> List[GadgetFinding]:
    """Locate gadget usage across the project."""

    root = project_root.expanduser().resolve()
    findings: List[GadgetFinding] = []
    for index, path in enumerate(iter_source_files(root)):
        if index >= max_files:
            break
        parser = parser_for_extension(path.suffix.lower())
        if not parser:
            continue
        try:
            source_bytes = path.read_bytes()
        except OSError:
            continue
        tree = parser.parse(source_bytes)
        for node in walk(tree.root_node):
            if node.type == "call_expression":
                _handle_call_expression(findings, path, node, source_bytes)
            elif node.type == "new_expression":
                _handle_new_expression(findings, path, node, source_bytes)
            elif node.type == "assignment_expression":
                _handle_assignment_expression(findings, path, node, source_bytes)
            elif node.type == "member_expression":
                _handle_member_expression(findings, path, node, source_bytes)
            elif node.type == "variable_declarator":
                _handle_react_vue_destructuring(findings, path, node, source_bytes)
            elif node.type == "identifier":
                _handle_identifier_reference(findings, path, node, source_bytes)
    return findings
