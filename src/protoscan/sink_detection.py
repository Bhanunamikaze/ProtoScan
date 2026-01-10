"""Unsafe operation (sink) detection leveraging tree-sitter ASTs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from .ast_utils import (
    MAX_FILES,
    collect_module_bindings,
    identifier_name,
    iter_source_files,
    node_text,
    parser_for_extension,
    walk,
)

CALL_MEMBER_RULES = [
    {"object": "Object", "property": "assign", "kind": "sink.object.assign"},
    {"object": "Object", "property": "defineProperty", "kind": "sink.dynamic.defineProperty"},
    {"object": "Object", "property": "setPrototypeOf", "kind": "sink.prototype.setPrototypeOf"},
    {"object": "Reflect", "property": "set", "kind": "sink.dynamic.reflectSet"},
    {"object": "_", "property": "merge", "kind": "sink.lodash.merge"},
    {"object": "_", "property": "defaults", "kind": "sink.lodash.defaults"},
    {"object": "_", "property": "extend", "kind": "sink.lodash.extend"},
    {"object": "$", "property": "extend", "kind": "sink.jquery.extend"},
    {"object": "lodash", "property": "merge", "kind": "sink.lodash.merge"},
    {"object": "qs", "property": "parse", "kind": "sink.parser.qs"},
    {"object": "querystring", "property": "parse", "kind": "sink.parser.querystring"},
    {"object": "JSON", "property": "parse", "kind": "sink.json.parse.reviver", "min_args": 2},
    {"object": "_", "property": "set", "kind": "sink.lodash.set"},
    {"object": "lodash", "property": "set", "kind": "sink.lodash.set"},
    {"object": "_", "property": "setWith", "kind": "sink.lodash.set"},
    {"object": "lodash", "property": "setWith", "kind": "sink.lodash.set"},
    {"object": "_", "property": "defaultsDeep", "kind": "sink.lodash.defaultsDeep"},
    {"object": "lodash", "property": "defaultsDeep", "kind": "sink.lodash.defaultsDeep"},
    {"object": "dotProp", "property": "set", "kind": "sink.path.dotProp", "module": "dot-prop"},
    {"object": "ini", "property": "parse", "kind": "sink.parser.ini", "module": "ini"},
    {"object": "ini", "property": "decode", "kind": "sink.parser.ini", "module": "ini"},
    {"object": "toml", "property": "parse", "kind": "sink.parser.toml", "module": "toml"},
    {"object": "toml", "property": "parse", "kind": "sink.parser.toml", "module": "@iarna/toml"},
    {"object": "$", "property": "deparam", "kind": "sink.browser.parser"},
    {"object": "jQuery", "property": "deparam", "kind": "sink.browser.parser"},
    {"object": "$.bbq", "property": "getState", "kind": "sink.browser.parser"},
    {"object": "jQuery.bbq", "property": "getState", "kind": "sink.browser.parser"},
    {"object": "$.query", "property": "get", "kind": "sink.browser.parser"},
    {"object": "$.query", "property": "load", "kind": "sink.browser.parser"},
    {"object": "jQuery.query", "property": "get", "kind": "sink.browser.parser"},
    {"object": "jQuery.query", "property": "load", "kind": "sink.browser.parser"},
    {"object": "can", "property": "deparam", "kind": "sink.browser.parser"},
    {"object": "Arg", "property": "parse", "kind": "sink.browser.parser"},
]

CALL_IDENTIFIER_RULES = {
    "merge": "sink.package.merge",
    "deepmerge": "sink.package.deepmerge",
    "extend": "sink.package.extend",
    "defaults": "sink.package.defaults",
    "structuredClone": "sink.clone.structuredClone",
    "setValue": "sink.path.setValue",
    "setDeep": "sink.path.setValue",
    "dset": "sink.path.setValue",
    "deparam": "sink.browser.parser",
    "parseParams": "sink.browser.parser",
    "parseParam": "sink.browser.parser",
    "parseString": "sink.browser.parser",
    "parse_str": "sink.browser.parser",
    "parseQuery": "sink.browser.parser",
    "parseQS": "sink.browser.parser",
    "paramsParse": "sink.browser.parser",
    "purl": "sink.browser.parser",
    "queryObject": "sink.browser.parser",
}

MODULE_IDENTIFIER_RULES = {
    "set-value": "sink.path.setValue",
    "setvalue": "sink.path.setValue",
    "dset": "sink.path.setValue",
    "ini": "sink.parser.ini",
    "@iarna/toml": "sink.parser.toml",
    "toml": "sink.parser.toml",
}

SPREAD_PARENT_TYPES = {"object", "object_pattern"}
LOOP_SINK_KIND = "sink.loop.assign"


@dataclass(frozen=True, slots=True)
class SinkFinding:
    """Represents an unsafe sink operation."""

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


def _emit(findings: List[SinkFinding], path: Path, node, source: bytes, kind: str) -> None:
    snippet = node_text(node, source).strip()
    line, column = node.start_point
    findings.append(
        SinkFinding(
            path=path,
            line=line + 1,
            column=column + 1,
            kind=kind,
            snippet=snippet,
        )
    )


def _call_target(node, source: bytes) -> tuple[str | None, str | None, str]:
    if node.type == "identifier":
        return identifier_name(node, source), None, "identifier"
    if node.type == "member_expression":
        obj = identifier_name(node.child_by_field_name("object"), source)
        prop = identifier_name(node.child_by_field_name("property"), source)
        root = obj.split(".")[0] if obj else None
        return root, prop, "member"
    return None, None, "unknown"


def _string_literal_value(node, source: bytes) -> str | None:
    if node is None:
        return None
    if node.type in {"string", "template_string"}:
        text = node_text(node, source).strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"', "`"}:
            return text[1:-1]
        return text
    if node.type == "string_fragment":
        return node_text(node, source)
    return None


def _matches_member_object(base: str | None, rule: Dict[str, object], bindings: Dict[str, str]) -> bool:
    if base == rule["object"]:
        return True
    module = rule.get("module")
    if module and base:
        module_name = bindings.get(base)
        if module_name == module:
            return True
    return False


def _handle_call_expression(findings, path, node, source: bytes, bindings: Dict[str, str]) -> None:
    func = node.child_by_field_name("function")
    if func is None:
        return
    base, prop, kind = _call_target(func, source)
    if kind == "identifier" and base:
        rule = CALL_IDENTIFIER_RULES.get(base)
        if rule:
            _emit(findings, path, node, source, rule)
            return
        module_name = bindings.get(base)
        if module_name:
            module_rule = MODULE_IDENTIFIER_RULES.get(module_name)
            if module_rule:
                _emit(findings, path, node, source, module_rule)
                return
    if kind == "member" and base and prop:
        for rule in CALL_MEMBER_RULES:
            if prop != rule["property"]:
                continue
            if not _matches_member_object(base, rule, bindings):
                continue
            min_args = rule.get("min_args")
            if min_args:
                args = node.child_by_field_name("arguments")
                if not args or len(args.named_children) < min_args:
                    continue
            if (
                rule["object"] == "Object"
                and rule["property"] == "defineProperty"
                and not _define_property_dynamic(node, source)
            ):
                continue
            _emit(findings, path, node, source, rule["kind"])  # type: ignore[arg-type]
            return


def _define_property_dynamic(node, source: bytes) -> bool:
    args = node.child_by_field_name("arguments")
    if args is None or len(args.named_children) < 2:
        return False
    key_node = args.named_children[1]
    return key_node.type not in {"string", "template_string"}


def _handle_assignment_expression(findings, path, node, source: bytes) -> None:
    left = node.child_by_field_name("left")
    if left is None or left.type != "subscript_expression":
        if left is not None and left.type == "member_expression":
            text = node_text(left, source)
            if ".constructor.prototype" in text or "Object.prototype" in text:
                _emit(findings, path, node, source, "sink.constructor.prototype")
        return
    index = left.child_by_field_name("index")
    if index is None or index.type in {"string", "number", "template_string"}:
        return
    _emit(findings, path, node, source, "sink.dynamic.property.assignment")


def _handle_spread(findings, path, node, source: bytes) -> None:
    parent = node.parent
    if parent is None or parent.type not in SPREAD_PARENT_TYPES:
        return
    _emit(findings, path, node, source, "sink.object.spread")


def _loop_has_guard(body, source: bytes) -> bool:
    snippet = node_text(body, source)
    lowered = snippet.lower()
    if "hasownproperty" in lowered or "object.hasown" in lowered or "hasown(" in lowered:
        return True
    return False


def _handle_for_in_statement(findings, path, node, source: bytes) -> None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    body = node.child_by_field_name("body")
    if left is None or right is None or body is None:
        return
    key_var = None
    if left.type == "identifier":
        key_var = identifier_name(left, source)
    elif left.type == "variable_declarator":
        key_var = identifier_name(left.child_by_field_name("name"), source)
    if not key_var:
        return
    if _loop_has_guard(body, source):
        return
    for child in walk(body):
        if child.type != "assignment_expression":
            continue
        left_expr = child.child_by_field_name("left")
        if left_expr is None or left_expr.type != "subscript_expression":
            continue
        index = left_expr.child_by_field_name("index")
        if identifier_name(index, source) != key_var:
            continue
        _emit(findings, path, child, source, LOOP_SINK_KIND)
        break


def find_sinks(project_root: Path, max_files: int = MAX_FILES) -> List[SinkFinding]:
    """Detect unsafe merge and dynamic property sinks."""

    root = project_root.expanduser().resolve()
    findings: List[SinkFinding] = []
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
            if node.type == "call_expression":
                _handle_call_expression(findings, path, node, source_bytes, bindings)
            elif node.type == "assignment_expression":
                _handle_assignment_expression(findings, path, node, source_bytes)
            elif node.type == "spread_element":
                _handle_spread(findings, path, node, source_bytes)
            elif node.type == "for_in_statement":
                _handle_for_in_statement(findings, path, node, source_bytes)
    return findings
