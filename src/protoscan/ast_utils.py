"""Shared helper functions for AST-based detectors."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, Iterator, List

from tree_sitter import Language, Parser
from tree_sitter_javascript import language as javascript_language
from tree_sitter_typescript import language_tsx, language_typescript


SUPPORTED_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".tsx"}
MAX_FILES = 400

_JS_LANGUAGE = Language(javascript_language())
_TS_LANGUAGE = Language(language_typescript())
_TSX_LANGUAGE = Language(language_tsx())

JS_PARSER = Parser()
JS_PARSER.language = _JS_LANGUAGE
TS_PARSER = Parser()
TS_PARSER.language = _TS_LANGUAGE
TSX_PARSER = Parser()
TSX_PARSER.language = _TSX_LANGUAGE


def node_text(node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def identifier_name(node, source: bytes) -> str | None:
    if node is None:
        return None
    if node.type in {
        "identifier",
        "property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
        "private_property_identifier",
    }:
        return node_text(node, source)
    if node.type == "this":
        return "this"
    if node.type == "assignment_pattern":
        return identifier_name(node.child_by_field_name("left"), source)
    if node.type == "object_assignment_pattern":
        left = node.child_by_field_name("left")
        if left:
            return identifier_name(left, source)
    if node.type == "member_expression":
        obj = identifier_name(node.child_by_field_name("object"), source)
        prop = identifier_name(node.child_by_field_name("property"), source)
        if obj and prop:
            return f"{obj}.{prop}"
        return obj or prop
    if node.type == "subscript_expression":
        obj = identifier_name(node.child_by_field_name("object"), source)
        index_node = node.child_by_field_name("index")
        prop = None
        if index_node is not None:
            if index_node.type in {"string", "template_string"}:
                prop = node_text(index_node, source).strip().strip("\"'`")
            elif index_node.type == "number":
                prop = node_text(index_node, source).strip()
            else:
                prop = identifier_name(index_node, source)
        if obj and prop:
            return f"{obj}.{prop}"
        return obj
    return None


def first_argument_literal(node, source: bytes) -> str | None:
    args = node.child_by_field_name("arguments")
    if args is None:
        return None
    for child in args.named_children:
        if child.type in {"string", "template_string"}:
            text = node_text(child, source).strip()
            text = text.strip("\"'`")
            return text
    return None


def walk(node) -> Iterator:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def parser_for_extension(ext: str) -> Parser | None:
    if ext in {".ts", ".mts"}:
        return TS_PARSER
    if ext == ".tsx":
        return TSX_PARSER
    if ext in {".js", ".mjs", ".cjs", ".jsx"}:
        return JS_PARSER
    return None


def iter_source_files(root: Path, extensions: Iterable[str] | None = None) -> List[Path]:
    extensions = set(extensions or SUPPORTED_EXTENSIONS)
    candidates: List[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in extensions:
            candidates.append(path)
    return sorted(candidates)


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


def _binding_names(node, source: bytes) -> List[str]:
    if node is None:
        return []
    name = identifier_name(node, source)
    if name:
        return [name]
    names: List[str] = []
    if node.type == "object_pattern":
        for child in node.named_children:
            if child.type in {
                "shorthand_property_identifier_pattern",
                "identifier",
                "property_identifier",
            }:
                alias = identifier_name(child, source)
                if alias:
                    names.append(alias)
            elif child.type == "pair_pattern":
                value_node = child.child_by_field_name("value")
                alias = identifier_name(value_node, source)
                if alias:
                    names.append(alias)
            elif child.type == "object_assignment_pattern":
                left = child.child_by_field_name("left")
                alias = identifier_name(left, source)
                if alias:
                    names.append(alias)
            elif child.type == "assignment_pattern":
                left = child.child_by_field_name("left")
                alias = identifier_name(left, source)
                if alias:
                    names.append(alias)
    return names


def collect_module_bindings(tree, source: bytes) -> Dict[str, str]:
    bindings: Dict[str, str] = {}
    for node in walk(tree.root_node):
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if value is None or value.type != "call_expression":
                continue
            func = value.child_by_field_name("function")
            if func is None or identifier_name(func, source) != "require":
                continue
            args = value.child_by_field_name("arguments")
            if not args or not args.named_children:
                continue
            literal = _string_literal_value(args.named_children[0], source)
            if not literal:
                continue
            for alias in _binding_names(name_node, source):
                bindings[alias] = literal
        elif node.type == "import_statement":
            source_node = node.child_by_field_name("source")
            if source_node is None:
                source_node = next(
                    (child for child in node.children if child.type in {"string", "template_string"}),
                    None,
                )
            literal = _string_literal_value(source_node, source)
            if not literal:
                continue
            clause = node.child_by_field_name("import_clause")
            if clause is None:
                clause = next((child for child in node.children if child.type == "import_clause"), None)
            if clause is None:
                continue
            for child in clause.named_children:
                if child.type == "identifier":
                    alias = identifier_name(child, source)
                    if alias:
                        bindings[alias] = literal
                elif child.type == "namespace_import":
                    identifier_node = child.child_by_field_name("name")
                    if identifier_node is None:
                        identifier_node = next(
                            (c for c in child.children if c.type == "identifier"),
                            None,
                        )
                    alias = identifier_name(identifier_node, source)
                    if alias:
                        bindings[alias] = literal
                elif child.type == "named_imports":
                    for spec in child.named_children:
                        if spec.type != "import_specifier":
                            continue
                        alias_node = spec.child_by_field_name("alias") or spec.child_by_field_name("name")
                        alias = identifier_name(alias_node, source)
                        if alias:
                            bindings[alias] = literal
    return bindings
