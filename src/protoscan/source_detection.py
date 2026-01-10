"""Pollution source detection using tree-sitter AST traversal."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from .ast_utils import (
    MAX_FILES,
    collect_module_bindings,
    first_argument_literal,
    identifier_name,
    iter_source_files,
    node_text,
    parser_for_extension,
    walk,
)

HTTP_MEMBER_RULES = {
    "body": {"bases": {"req", "request", "ctx", "context"}, "kind": "http.request.body"},
    "query": {"bases": {"req", "request", "ctx", "context"}, "kind": "http.request.query"},
    "params": {"bases": {"req", "request", "ctx", "context"}, "kind": "http.request.params"},
    "headers": {"bases": {"req", "request", "ctx", "context"}, "kind": "http.request.headers"},
    "cookies": {"bases": {"req", "request", "ctx", "context"}, "kind": "http.request.cookies"},
}

CONFIG_MEMBER_RULES = {
    "env": {"bases": {"process"}, "kind": "config.process.env"},
    "argv": {"bases": {"process"}, "kind": "cli.process.argv"},
}

BROWSER_MEMBER_RULES = {
    "location": {"bases": {"window", "document"}, "kind": "browser.location"},
    "search": {"bases": {"location"}, "kind": "browser.location.search"},
    "hash": {"bases": {"location"}, "kind": "browser.location.hash"},
    "href": {"bases": {"location"}, "kind": "browser.location.href"},
    "getItem": {"bases": {"localStorage", "sessionStorage"}, "kind": "browser.storage"},
}

CALL_MEMBER_RULES = [
    {"object": "http", "property": "createServer", "kind": "http.server.createServer"},
    {"object": "fs", "property": "readFileSync", "kind": "config.file.readFile"},
    {
        "object": "ws",
        "property": "on",
        "kind": "websocket.onMessage",
        "argument_literals": {"message"},
    },
    {
        "object": "window",
        "property": "addEventListener",
        "kind": "browser.window.message",
        "argument_literals": {"message"},
    },
    {"object": "window", "property": "URLSearchParams", "kind": "browser.url.searchParams"},
    {"object": "window", "property": "URL", "kind": "browser.url.parse"},
]

CALL_IDENTIFIER_RULES = {
    "URLSearchParams": "browser.url.searchParams",
    "minimist": "cli.parser.minimist",
    "yargs": "cli.parser.yargs",
    "URL": "browser.url.parse",
}

CLIENT_PARSER_IDENTIFIER_RULES = {
    "deparam": "browser.parser.jquery-deparam",
    "paramsParse": "browser.parser.analytics-utils",
    "parseParams": "browser.parser.analytics-utils",
    "parseQueryString": "browser.parser.component-querystring",
    "parseQS": "browser.parser.component-querystring",
    "purl": "browser.parser.purl",
    "parse_str": "browser.parser.parse-str",
}

CLIENT_PARSER_MODULES = {
    "analytics-utils": "browser.parser.analytics-utils",
    "analytics-utils/src/paramsParse": "browser.parser.analytics-utils",
    "arg.js": "browser.parser.arg-js",
    "arg-js": "browser.parser.arg-js",
    "arg": "browser.parser.arg-js",
    "aurelia-path": "browser.parser.aurelia-path",
    "aurelia/path": "browser.parser.aurelia-path",
    "backbone-query-parameters": "browser.parser.backbone-query-parameters",
    "can-deparam": "browser.parser.can-deparam",
    "canjs-deparam": "browser.parser.can-deparam",
    "component-querystring": "browser.parser.component-querystring",
    "component/querystring": "browser.parser.component-querystring",
    "component_querystring": "browser.parser.component-querystring",
    "davis.js": "browser.parser.davis-js",
    "davis-js": "browser.parser.davis-js",
    "jquery-deparam": "browser.parser.jquery-deparam",
    "jquery-bbq": "browser.parser.jquery-bbq",
    "jquery.ba-bbq": "browser.parser.jquery-bbq",
    "jquery-parseparam": "browser.parser.jquery-parseparam",
    "jquery-query-object": "browser.parser.jquery-query-object",
    "jquery-sparkle": "browser.parser.jquery-sparkle",
    "mootools-more": "browser.parser.mootools-more",
    "mutiny": "browser.parser.mutiny",
    "parse_str": "browser.parser.parse-str",
    "purl": "browser.parser.purl",
    "swiftype-site-search": "browser.parser.swiftype-site-search",
    "v4fire-core": "browser.parser.v4fire-core",
    "yui": "browser.parser.yui3",
    "yui3": "browser.parser.yui3",
}

CLIENT_PARSER_MEMBER_RULES = [
    {"object": "$", "property": "deparam", "kind": "browser.parser.jquery-deparam"},
    {"object": "jQuery", "property": "deparam", "kind": "browser.parser.jquery-deparam"},
    {"object": "$.bbq", "property": "getState", "kind": "browser.parser.jquery-bbq"},
    {"object": "jQuery.bbq", "property": "getState", "kind": "browser.parser.jquery-bbq"},
    {"object": "$.query", "property": "get", "kind": "browser.parser.jquery-query-object"},
    {"object": "$.query", "property": "load", "kind": "browser.parser.jquery-query-object"},
    {"object": "jQuery.query", "property": "get", "kind": "browser.parser.jquery-query-object"},
    {"object": "jQuery.query", "property": "load", "kind": "browser.parser.jquery-query-object"},
    {"object": "can", "property": "deparam", "kind": "browser.parser.can-deparam"},
    {"object": "Arg", "property": "parse", "kind": "browser.parser.arg-js"},
]

ALL_MEMBER_RULES = CALL_MEMBER_RULES + CLIENT_PARSER_MEMBER_RULES

REQUIRE_CONFIG_EXTENSIONS = (".json", ".yaml", ".yml")


@dataclass(frozen=True, slots=True)
class SourceFinding:
    """Represents a detected pollution source."""

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


def _emit_finding(
    findings: List[SourceFinding],
    path: Path,
    node,
    source: bytes,
    kind: str,
) -> None:
    snippet = node_text(node, source).strip()
    line, column = node.start_point
    findings.append(
        SourceFinding(
            path=path,
            line=line + 1,
            column=column + 1,
            kind=kind,
            snippet=snippet,
        )
    )


def _matches_member_rule(base: str | None, prop: str | None, rules: Dict[str, Dict[str, object]]) -> str | None:
    if not base or not prop:
        return None
    rule = rules.get(prop)
    if not rule:
        return None
    base_tokens = base.split(".")
    for token in base_tokens:
        if token in rule["bases"]:
            return rule["kind"]  # type: ignore[return-value]
    return None


def _handle_member_expression(findings, path, node, source: bytes) -> None:
    base = identifier_name(node.child_by_field_name("object"), source)
    prop = identifier_name(node.child_by_field_name("property"), source)
    kind = _matches_member_rule(base, prop, HTTP_MEMBER_RULES)
    if kind:
        _emit_finding(findings, path, node, source, kind)
        return
    kind = _matches_member_rule(base, prop, CONFIG_MEMBER_RULES)
    if kind:
        _emit_finding(findings, path, node, source, kind)
        return
    kind = _matches_member_rule(base, prop, BROWSER_MEMBER_RULES)
    if kind:
        _emit_finding(findings, path, node, source, kind)
        return


def _handle_require_call(findings, path, node, source: bytes) -> bool:
    literal = first_argument_literal(node, source)
    if not literal:
        return False
    if literal.endswith(REQUIRE_CONFIG_EXTENSIONS):
        _emit_finding(findings, path, node, source, "config.file.require")
        return True
    return False


def _handle_call_expression(findings, path, node, source: bytes, bindings: Dict[str, str]) -> None:
    func = node.child_by_field_name("function")
    if func is None:
        return
    if func.type == "identifier":
        name = identifier_name(func, source)
        if not name:
            return
        if name == "require":
            if _handle_require_call(findings, path, node, source):
                return
        rule = CALL_IDENTIFIER_RULES.get(name)
        if rule:
            _emit_finding(findings, path, node, source, rule)
            return
        parser_rule = CLIENT_PARSER_IDENTIFIER_RULES.get(name)
        if parser_rule:
            _emit_finding(findings, path, node, source, parser_rule)
            return
        module_name = bindings.get(name)
        if module_name:
            parser_kind = CLIENT_PARSER_MODULES.get(module_name)
            if parser_kind:
                _emit_finding(findings, path, node, source, parser_kind)
            return
    if func.type == "member_expression":
        base = identifier_name(func.child_by_field_name("object"), source)
        prop = identifier_name(func.child_by_field_name("property"), source)
        base_root = base.split(".")[0] if base else None
        if base and prop:
            for rule in ALL_MEMBER_RULES:
                if prop != rule["property"]:
                    continue
                if base == rule["object"] or base_root == rule["object"]:
                    if "argument_literals" in rule:
                        literal = first_argument_literal(node, source)
                        if literal not in rule["argument_literals"]:
                            continue
                    _emit_finding(findings, path, node, source, rule["kind"])
                    return
        module_name = None
        if base:
            module_name = bindings.get(base)
            if not module_name and base_root:
                module_name = bindings.get(base_root)
        if module_name:
            parser_kind = CLIENT_PARSER_MODULES.get(module_name)
            if parser_kind:
                _emit_finding(findings, path, node, source, parser_kind)
                return


def _handle_new_expression(findings, path, node, source: bytes, bindings: Dict[str, str]) -> None:
    constructor = node.child_by_field_name("constructor")
    if constructor is None:
        return
    name = identifier_name(constructor, source)
    if not name:
        return
    rule = CALL_IDENTIFIER_RULES.get(name) or CALL_IDENTIFIER_RULES.get(name.split(".")[-1])
    if rule:
        _emit_finding(findings, path, node, source, rule)
        return
    parser_rule = CLIENT_PARSER_IDENTIFIER_RULES.get(name)
    if parser_rule:
        _emit_finding(findings, path, node, source, parser_rule)
        return
    module_name = bindings.get(name)
    if not module_name and "." in name:
        module_name = bindings.get(name.split(".")[0])
    if module_name:
        parser_kind = CLIENT_PARSER_MODULES.get(module_name)
        if parser_kind:
            _emit_finding(findings, path, node, source, parser_kind)
            return


def find_sources(project_root: Path, max_files: int = MAX_FILES) -> List[SourceFinding]:
    """Detect user-controlled sources across the project."""

    root = project_root.expanduser().resolve()
    findings: List[SourceFinding] = []
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
        bindings = collect_module_bindings(tree, source_bytes)
        for node in walk(tree.root_node):
            if node.type == "member_expression":
                _handle_member_expression(findings, path, node, source_bytes)
            elif node.type == "call_expression":
                _handle_call_expression(findings, path, node, source_bytes, bindings)
            elif node.type == "new_expression":
                _handle_new_expression(findings, path, node, source_bytes, bindings)
    return findings
