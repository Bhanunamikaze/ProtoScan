"""Report renderers for the CLI output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple
from textwrap import dedent


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "ProtoScan"
TOOL_URL = "https://github.com/Bhanunamikaze/ProtoScan"

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}
SINK_SEVERITY = {
    "sink.object.assign": "high",
    "sink.lodash.merge": "high",
    "sink.package.merge": "high",
    "sink.object.spread": "medium",
    "sink.dynamic.property.assignment": "medium",
    "sink.loop.assign": "high",
    "sink.constructor.prototype": "high",
    "sink.lodash.set": "high",
    "sink.lodash.defaultsDeep": "high",
    "sink.browser.parser": "medium",
}
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def render_json(report: Dict[str, object]) -> str:
    return json.dumps(report, indent=2)


def _sarif_location(path: str, line: int) -> Dict[str, object]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": line},
        }
    }


def _chain_sink_positions(report: Dict[str, object]) -> set[tuple[str, int]]:
    positions = set()
    def sev_key(chain: Dict[str, object]) -> int:
        sev = str(chain.get("severity", "medium")).strip().lower()
        return SEVERITY_RANK.get(sev, 1)

    sorted_chains: List[Dict[str, object]] = sorted(
        report.get("flowChains", []),
        key=sev_key,
        reverse=True,
    )
    for row_index, chain in enumerate(sorted_chains):
        sink = chain.get("sink")
        if sink and sink.get("path") and sink.get("line"):
            positions.add((sink["path"], sink["line"]))
    return positions


def _sarif_chain_results(report: Dict[str, object]) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for chain in report.get("flowChains", []):
        gadget = chain.get("gadget")
        sink = chain.get("sink")
        source = chain.get("source")
        rule_id = (gadget or {}).get("kind") or sink.get("kind")
        level = SEVERITY_TO_SARIF_LEVEL.get(chain.get("severity", "medium"), "warning")
        description = chain.get("description") or "Prototype pollution chain detected"
        message = " → ".join(chain.get("exploitSteps", [])) or description
        locations = []
        if source:
            locations.append(_sarif_location(source.get("path"), source.get("line")))
        if sink and sink.get("path") != source.get("path"):
            locations.append(_sarif_location(sink.get("path"), sink.get("line")))
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": locations,
                "properties": {
                    "severity": chain.get("severity"),
                    "route": chain.get("route"),
                    "metadata": chain.get("metadata"),
                    "description": description,
                    "validation": chain.get("validation"),
                    "exploitExample": chain.get("exploitExample"),
                    "payloadVariants": chain.get("payloadVariants"),
                },
            }
        )
    return results


def _sarif_dependency_results(report: Dict[str, object]) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    deps = report.get("dependencyReport", {}).get("findings", [])
    for finding in deps:
        level = "warning" if finding.get("severity") in {"high", "critical"} else "note"
        text = f"{finding.get('name')} {finding.get('installedVersion')} satisfies {finding.get('spec')}"
        results.append(
            {
                "ruleId": f"dependency:{finding.get('name')}",
                "level": level,
                "message": {"text": text},
                "properties": {
                    "severity": finding.get("severity"),
                    "cves": finding.get("cves"),
                    "via": finding.get("via"),
                },
            }
        )
    return results


def _sarif_sink_results(report: Dict[str, object], used_positions: set[tuple[str, int]]) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for sink in report.get("sinkFindings", []):
        path = sink.get("path")
        line = sink.get("line")
        if not path or not line:
            continue
        if (path, line) in used_positions:
            continue
        severity = SINK_SEVERITY.get(sink.get("kind"), "medium")
        level = SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")
        message = f"Potential sink {sink.get('kind')} reachable without validated gadget"
        results.append(
            {
                "ruleId": sink.get("kind"),
                "level": level,
                "message": {"text": message},
                "locations": [_sarif_location(path, line)],
                "properties": {
                    "severity": severity,
                    "source": sink.get("source"),
                },
            }
        )
    return results


def render_sarif(report: Dict[str, object]) -> str:
    results: List[Dict[str, object]] = []
    chain_results = _sarif_chain_results(report)
    results.extend(chain_results)
    sink_positions = _chain_sink_positions(report)
    results.extend(_sarif_sink_results(report, sink_positions))
    results.extend(_sarif_dependency_results(report))

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URL,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "runtimeDetection": report.get("runtimeDetection"),
                            "dependencySummary": {
                                "totalFindings": len(report.get("dependencyReport", {}).get("findings", []))
                            },
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_human(report: Dict[str, object]) -> str:
    lines = []
    lines.append(f"Project: {report.get('projectRoot')}")
    runtimes = ", ".join(report.get("runtimeDetection", {}).get("runtimes", []))
    lines.append(f"Runtimes: {runtimes or 'unknown'}")
    runtime_projects = report.get("runtimeDetection", {}).get("projects", [])
    if runtime_projects:
        lines.append("Runtime Projects:")
        for project in runtime_projects:
            parts: List[str] = []
            if project.get("runtimes"):
                parts.append("runtimes=" + ", ".join(project["runtimes"]))
            if project.get("frameworks"):
                parts.append("frameworks=" + ", ".join(project["frameworks"]))
            if project.get("build_tools"):
                parts.append("build_tools=" + ", ".join(project["build_tools"]))
            if parts:
                lines.append(f"  - {project.get('path', '.')} ({'; '.join(parts)})")
    dep_findings = report.get("dependencyReport", {}).get("findings", [])
    lines.append(f"Dependency Findings: {len(dep_findings)}")
    chains = report.get("flowChains", [])
    lines.append(f"Exploit Chains: {len(chains)}")
    for chain in chains:
        route = chain.get("route")
        route_str = f"{route['method']} {route['path']}" if route else "unknown route"
        steps = " → ".join(chain.get("exploitSteps", []))
        lines.append(f"- [{chain.get('severity').upper()}] {route_str}: {steps}")
        if chain.get("description"):
            lines.append(f"    desc: {chain['description']}")
        if chain.get("validation"):
            lines.append(f"    validate: {chain['validation']}")
        if chain.get("exploitExample"):
            lines.append(f"    payload: {chain['exploitExample']}")
        variants = chain.get("payloadVariants") or []
        if variants:
            summary = ", ".join(variant.get("label", "payload") for variant in variants[:3])
            lines.append(f"    payload variants: {summary}")
    return "\n".join(lines)


def render_html(report: Dict[str, object]) -> str:
    def esc(value: str) -> str:
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    severity_colors = {
        "critical": "#f44336",
        "high": "#ff9800",
        "medium": "#ffeb3b",
        "low": "#8bc34a",
    }
    severity_counts: Dict[str, int] = {}
    column_defs: List[Tuple[str, str, str]] = [
        ("severity", "Severity", "severity"),
        ("gadgetDomain", "Gadget Domain", "domain"),
        ("title", "Vuln Title", "value"),
        ("route", "Route", "value"),
        ("source", "Source", "value"),
        ("sink", "Sink", "value"),
        ("gadget", "Gadget", "value"),
        ("steps", "Steps", "presence"),
        ("description", "Description", "presence"),
        ("validation", "Validation", "presence"),
        ("payload", "Payload", "presence"),
    ]
    filter_types = {col: filter_type for col, _, filter_type in column_defs}
    value_filter_values: Dict[str, Dict[str, str]] = {
        col: {} for col, _, filter_type in column_defs if filter_type == "value"
    }
    category_labels = {
        "server": "Server",
        "browser": "Browser",
        "cli": "CLI",
        "cdn": "CDN",
        "config": "Config",
        "generic": "Generic",
    }

    project_root: Path | None = None
    project_root_raw = str(report.get("projectRoot") or "").strip()
    if project_root_raw:
        try:
            project_root = Path(project_root_raw).resolve()
        except OSError:
            project_root = None

    def normalize_filter_value(value: str) -> str:
        return (value or "").strip()

    def register_value_option(column: str, display_value: str) -> str:
        normalized = normalize_filter_value(display_value)
        if not normalized:
            return ""
        value_filter_values[column][normalized] = display_value
        return normalized
    sink_titles = {
        "sink.object.assign": "Prototype Pollution via Object.assign",
        "sink.object.spread": "Prototype Pollution via object spread",
        "sink.dynamic.property.assignment": "Prototype Pollution via dynamic property write",
        "sink.dynamic.defineProperty": "Prototype Pollution via Object.defineProperty",
        "sink.dynamic.reflectSet": "Prototype Pollution via Reflect.set",
        "sink.prototype.setPrototypeOf": "Prototype Pollution via Object.setPrototypeOf",
        "sink.constructor.prototype": "Prototype Pollution via constructor prototype write",
        "sink.loop.assign": "Prototype Pollution via unsafe merge loop",
        "sink.lodash.merge": "Prototype Pollution via lodash.merge",
        "sink.lodash.defaults": "Prototype Pollution via lodash.defaults",
        "sink.lodash.defaultsDeep": "Prototype Pollution via lodash.defaultsDeep",
        "sink.lodash.extend": "Prototype Pollution via lodash.extend",
        "sink.lodash.set": "Prototype Pollution via lodash.set",
        "sink.jquery.extend": "Prototype Pollution via $.extend",
        "sink.package.merge": "Prototype Pollution via merge package",
        "sink.package.deepmerge": "Prototype Pollution via deepmerge",
        "sink.package.extend": "Prototype Pollution via extend package",
        "sink.package.defaults": "Prototype Pollution via defaults package",
        "sink.path.dotProp": "Prototype Pollution via dot-prop",
        "sink.path.setValue": "Prototype Pollution via set-value style helper",
        "sink.json.parse.reviver": "Prototype Pollution via JSON.parse reviver",
        "sink.parser.qs": "Prototype Pollution via qs.parse",
        "sink.parser.querystring": "Prototype Pollution via querystring.parse",
        "sink.parser.ini": "Prototype Pollution via ini parser",
        "sink.parser.toml": "Prototype Pollution via toml parser",
        "sink.clone.structuredClone": "Prototype Pollution via structuredClone",
        "sink.path.dset": "Prototype Pollution via dset helper",
    }
    runtime_projects = report.get("runtimeDetection", {}).get("projects", [])
    runtime_items: List[str] = []
    for project in runtime_projects:
        details: List[str] = []
        runtimes = project.get("runtimes") or []
        frameworks = project.get("frameworks") or []
        tools = project.get("build_tools") or []
        if runtimes:
            details.append(f"Runtimes: {', '.join(esc(item) for item in runtimes)}")
        if frameworks:
            details.append(f"Frameworks: {', '.join(esc(item) for item in frameworks)}")
        if tools:
            details.append(f"Build tools: {', '.join(esc(item) for item in tools)}")
        detail_text = " | ".join(details) or "No build/runtime hints detected."
        runtime_items.append(f"<li><strong>{esc(project.get('path', '.'))}</strong> – {detail_text}</li>")
    runtime_list_html = "".join(runtime_items) or "<li>No runtime signatures detected.</li>"

    def friendly_title(kind: str) -> str:
        if not kind:
            return "Prototype Pollution chain"
        if kind in sink_titles:
            return sink_titles[kind]
        if kind.startswith("sink."):
            suffix = kind.split(".", 1)[1]
            label = suffix.replace(".", " ").replace("_", " ")
            label = " ".join(word for word in label.split())
            if label:
                return f"Prototype Pollution via {label.title()}"
        return f"Prototype Pollution ({kind})"

    def html_sev_key(chain: Dict[str, object]) -> int:
        sev = str(chain.get("severity", "medium")).strip().lower()
        return SEVERITY_RANK.get(sev, 1)

    def render_header_cell(column: str, label: str, filter_type: str) -> str:
        options: List[str] = ['<option value="__all__" selected>All</option>']
        if filter_type == "severity":
            for value in ("critical", "high", "medium", "low"):
                options.append(f'<option value="{value}">{value.title()}</option>')
        elif filter_type == "domain":
            options.append('<option value="client">Client</option>')
            options.append('<option value="server">Server</option>')
        elif filter_type == "presence":
            options.append('<option value="has">Has data</option>')
            options.append('<option value="empty">No data</option>')
        elif filter_type == "value":
            values = value_filter_values.get(column, {})
            for normalized, display in sorted(values.items(), key=lambda item: item[1].lower()):
                options.append(f'<option value="{esc(normalized)}">{esc(display)}</option>')
        else:
            options.append('<option value="__all__">All</option>')
        select_html = (
            f'<select class="header-filter" '
            f'id="filter-{esc(column)}" '
            f'data-filter-col="{esc(column)}" '
            f'onchange="applyRowFilters()">'
            + "".join(options)
            + "</select>"
        )
        return f'<th data-col="{esc(column)}"><div class="header-label">{esc(label)}</div>{select_html}</th>'

    def render_payload_cell(row_index: int, variants: List[Dict[str, object]], fallback: str) -> str:
        if not variants:
            if not fallback:
                return "&mdash;"
            return f'<pre class="payload-block">{esc(fallback)}</pre>'
        category_set = []
        for variant in variants:
            category = str(variant.get("category") or "generic")
            if category not in category_set:
                category_set.append(category)
        filter_html = ""
        if len(category_set) > 1:
            options = ['<option value="all">All channels</option>']
            for category in category_set:
                label = category_labels.get(category, category.title())
                options.append(f'<option value="{esc(category)}">{esc(label)}</option>')
            filter_html = (
                '<div class="payload-filter">'
                '<label>Channel</label>'
                f'<select data-payload-filter>{"".join(options)}</select>'
                "</div>"
            )
        tab_buttons: List[str] = []
        panels: List[str] = []
        for idx, variant in enumerate(variants):
            tab_id = f"payload-{row_index}-{idx}"
            category = str(variant.get("category") or "generic")
            label = variant.get("label") or "Payload"
            payload_text = esc(str(variant.get("payload") or ""))
            notes = esc(str(variant.get("notes") or ""))
            steps = variant.get("steps") or []
            alternates = variant.get("alternates") or []
            cat_label = category_labels.get(category, category.title())
            tab_buttons.append(
                f'<button type="button" class="payload-tab" data-payload-tab="{tab_id}" data-category="{esc(category)}">{esc(label)}</button>'
            )
            steps_html = (
                "<ol class=\"steps-list\">"
                + "".join(f"<li>{esc(step)}</li>" for step in steps)
                + "</ol>"
                if steps
                else ""
            )
            alt_html = (
                "<div class=\"payload-alt\"><strong>Alternates:</strong> "
                + ", ".join(esc(str(item)) for item in alternates)
                + "</div>"
                if alternates
                else ""
            )
            panels.append(
                f'<div class="payload-panel" data-payload-panel="{tab_id}" data-category="{esc(category)}">'
                f'<div class="payload-panel-header"><span class="badge badge-tag">{esc(cat_label)}</span> {esc(label)}</div>'
                f'<pre class="payload-block">{payload_text}</pre>'
                f'<div class="payload-note">{notes}</div>'
                f"{steps_html}"
                f"{alt_html}"
                "</div>"
            )
        return (
            '<div class="payload-tabs">'
            f"{filter_html}"
            f'<div class="payload-tab-list">{"".join(tab_buttons)}</div>'
            f'{"".join(panels)}'
            "</div>"
        )

    def relative_path_text(path_value: str) -> str:
        if not path_value:
            return ""
        if not project_root:
            return path_value
        try:
            return str(Path(path_value).resolve().relative_to(project_root))
        except (ValueError, OSError):
            return path_value

    def render_location_cell(entry: Dict[str, object], fallback_label: str) -> tuple[str, str]:
        path_value = str(entry.get("path") or "")
        rel_path = relative_path_text(path_value)
        line = entry.get("line")
        column = entry.get("column")
        snippet = (entry.get("snippet") or "").strip()
        kind = str(entry.get("kind") or fallback_label or "").strip()
        path_display = rel_path or path_value or "Unknown file"
        if isinstance(line, int) and line > 0:
            line_info = f"line {line}"
        else:
            line_info = "line ?"
        if isinstance(column, int) and column > 0:
            line_info = f"{line_info}, col {column}"
        meta_bits = []
        if kind:
            meta_bits.append(kind)
        meta_bits.append(line_info)
        meta_text = " @ ".join(meta_bits) if meta_bits else line_info
        preview = snippet.replace("\n", " ").strip()
        if len(preview) > 240:
            preview = preview[:237] + "..."
        snippet_html = (
            f'<pre class="code-snippet">{esc(preview)}</pre>' if preview else ""
        )
        inner_html = (
            '<div class="code-location">'
            f'<div class="code-path">{esc(path_display)}</div>'
            f'<div class="code-meta">{esc(meta_text)}</div>'
            f"{snippet_html}"
            "</div>"
        )
        filter_text = f"{path_display}:{line or ''}".strip(":")
        return inner_html, filter_text or "Unknown"

    chains_rows = []
    sorted_chains = sorted(
        report.get("flowChains", []),
        key=html_sev_key,
        reverse=True,
    )
    for row_index, chain in enumerate(sorted_chains):
        route = chain.get("route") or {}
        steps = chain.get("exploitSteps", [])
        steps_html = "".join(f"<li>{esc(step)}</li>" for step in steps) or "<li>Not available</li>"
        source = chain.get("source") or {}
        sink = chain.get("sink") or {}
        gadget = chain.get("gadget") or {}
        metadata = chain.get("metadata") or {}
        sev = str(chain.get("severity", "medium")).lower()
        method = (route.get("method") or "").strip()
        path = (route.get("path") or "").strip()
        route_text = f"{method} {path}".strip() or "Unknown route"
        sink_kind = sink.get("kind", "")
        title = friendly_title(sink_kind)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        gadget_kind = gadget.get("kind", "") or "No gadget"
        gadget_label = esc(gadget_kind)
        is_client = bool(metadata.get("clientGadget"))
        if is_client:
            gadget_label = f"<span class=\"badge badge-client\">Client Gadget</span> {gadget_label}"
        gadget_notes: List[str] = []
        if metadata.get("gadgetImpact"):
            gadget_notes.append(f"<div class=\"gadget-note\"><strong>Impact:</strong> {esc(metadata['gadgetImpact'])}</div>")
        if metadata.get("gadgetRequirement"):
            gadget_notes.append(f"<div class=\"gadget-note\"><strong>Requirement:</strong> {esc(metadata['gadgetRequirement'])}</div>")
        gadget_inner = f"{gadget_label}{''.join(gadget_notes)}" or "&mdash;"
        client_attr = "true" if is_client else "false"
        column_inner: Dict[str, str] = {}
        column_filter_values_map: Dict[str, str] = {}

        def set_cell(column: str, inner_html: str, *, display_text: str = "") -> None:
            filter_type = filter_types.get(column)
            text_value = display_text or ""
            filter_value = ""
            if filter_type == "value":
                filter_value = register_value_option(column, text_value)
            elif filter_type == "presence":
                filter_value = text_value or "empty"
            else:
                filter_value = normalize_filter_value(text_value)
            column_inner[column] = inner_html
            column_filter_values_map[column] = filter_value

        set_cell(
            "severity",
            f"<span class=\"badge badge-{esc(sev)}\">{esc(sev.upper())}</span>",
            display_text=sev,
        )
        if gadget_kind and gadget_kind != "No gadget":
            gadget_domain_label = "Client" if is_client else "Server"
            gadget_domain_value = "client" if is_client else "server"
            set_cell("gadgetDomain", esc(gadget_domain_label), display_text=gadget_domain_value)
        else:
            set_cell("gadgetDomain", "&mdash;", display_text="")
        set_cell("title", esc(title), display_text=title)
        set_cell("route", esc(route_text), display_text=route_text)
        source_inner, source_filter = render_location_cell(source, "source")
        set_cell("source", source_inner, display_text=source_filter)
        sink_inner, sink_filter = render_location_cell(sink, sink_kind or "sink")
        set_cell("sink", sink_inner, display_text=sink_filter)
        set_cell("gadget", gadget_inner, display_text=gadget_kind)
        steps_inner = f"<ol class=\"steps-list\">{steps_html}</ol>" if steps else "&mdash;"
        set_cell("steps", steps_inner, display_text="has" if steps else "empty")
        description_text = (chain.get("description", "") or "").strip()
        description_inner = esc(description_text) if description_text else "&mdash;"
        set_cell("description", description_inner, display_text="has" if description_text else "empty")
        validation_text = (chain.get("validation", "") or "").strip()
        validation_inner = esc(validation_text) if validation_text else "&mdash;"
        set_cell("validation", validation_inner, display_text="has" if validation_text else "empty")
        payload_variants = chain.get("payloadVariants") or []
        payload_fallback = (chain.get("exploitExample", "") or "").strip()
        column_inner["payload"] = render_payload_cell(row_index, payload_variants, payload_fallback)
        column_filter_values_map["payload"] = "has" if (payload_variants or payload_fallback) else "empty"

        row_cells = []
        for column, _, _ in column_defs:
            inner_html = column_inner.get(column, "&mdash;")
            filter_value = column_filter_values_map.get(column, "")
            row_cells.append(
                f"<td data-col=\"{esc(column)}\" data-filter-value=\"{esc(filter_value)}\">{inner_html}</td>"
            )
        row_html = (
            "<tr "
            + f"data-severity=\"{esc(sev)}\" "
            + f"data-client=\"{client_attr}\" "
            + f"style=\"background:{severity_colors.get(sev, '#fff3e0')}20\">"
            + "".join(row_cells)
            + "</tr>"
        )
        chains_rows.append(row_html)
    dependency_rows = []
    for finding in report.get("dependencyReport", {}).get("findings", []):
        dependency_rows.append(
            "<tr>"
            f"<td>{esc(finding.get('name', ''))}</td>"
            f"<td>{esc(finding.get('installedVersion', ''))}</td>"
            f"<td>{esc(finding.get('spec', ''))}</td>"
            f"<td>{esc(', '.join(finding.get('cves', []) or []))}</td>"
            f"<td>{esc(finding.get('severity', ''))}</td>"
            "</tr>"
        )
    header_cells_html = "".join(
        render_header_cell(column, label, filter_type) for column, label, filter_type in column_defs
    )
    html = dedent(f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Prototype Pollution Report</title>
  <style>
    :root {{ color-scheme: light; }}
    body {{
      font-family: "Segoe UI", Roboto, Arial, sans-serif;
      margin: 2rem;
      background: #f4f6fa;
      color: #111;
    }}
    h1, h2 {{ color: #1a237e; }}
    table {{
      border-collapse: collapse;
      width: 100%;
      margin-bottom: 2rem;
      background: #fff;
      border-radius: 10px;
      overflow: hidden;
      box-shadow: 0 2px 6px rgba(0,0,0,0.08);
      table-layout: fixed;
    }}
    th, td {{
      border-bottom: 1px solid #e0e0e0;
      padding: 0.65rem;
      text-align: left;
      vertical-align: top;
      white-space: normal;
      word-break: break-word;
    }}
    th {{
      background: #eef1f7;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }}
    .chains-table thead .filter-row th {{
      background: #fff;
    }}
    .chains-table td {{
      font-size: 0.9rem;
      line-height: 1.4;
    }}
    code {{
      background: #f0f0f0;
      padding: 2px 4px;
      border-radius: 4px;
      font-size: 0.8rem;
    }}
    .summary {{
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
      margin-bottom: 1.5rem;
    }}
    .runtime-details {{
      margin-bottom: 1.5rem;
    }}
    .runtime-list {{
      list-style: none;
      padding-left: 0;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }}
    .runtime-list li {{
      background: #fff;
      border-radius: 8px;
      padding: 0.6rem 0.8rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.08);
      font-size: 0.9rem;
    }}
    .card {{
      background: #fff;
      padding: 1rem 1.5rem;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
      min-width: 140px;
      flex: 1;
    }}
    .card h3 {{
      margin: 0;
      font-size: 0.9rem;
      color: #607d8b;
      text-transform: uppercase;
    }}
    .card .value {{
      font-size: 1.8rem;
      margin: 0.25rem 0 0;
      font-weight: 600;
    }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 999px;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
      color: #fff;
    }}
    .badge-client {{
      background: #3f51b5;
      margin-right: 0.35rem;
    }}
    .badge-critical {{ background: #f44336; }}
    .badge-high {{ background: #ff9800; }}
    .badge-medium {{ background: #ffb300; color:#111; }}
    .badge-low {{ background: #8bc34a; color:#111; }}
    .gadget-note {{
      font-size: 0.78rem;
      color: #37474f;
      margin-top: 0.2rem;
    }}
    .chains-table th {{
      background: #f5f5f5;
      vertical-align: top;
    }}
    .header-label {{
      font-size: 0.78rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #4e4e4e;
    }}
    .header-filter {{
      width: 100%;
      margin-top: 0.4rem;
      border-radius: 6px;
      padding: 0.35rem 0.5rem;
      border: 1px solid #c5c5c5;
      background: #fff;
      font-size: 0.85rem;
    }}
    .header-filter:focus {{
      outline: none;
      border-color: #1976d2;
      box-shadow: 0 0 0 2px rgba(25, 118, 210, 0.15);
    }}
    .heatmap {{
      display: flex;
      gap: 1rem;
      margin-bottom: 1rem;
    }}
    .heatmap-cell {{
      flex: 1;
      padding: 0.75rem;
      border-radius: 8px;
      color: #fff;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: inset 0 0 12px rgba(0,0,0,0.08);
    }}
    .heat-critical {{ background: #c62828; }}
    .heat-high {{ background: #ef6c00; }}
    .heat-medium {{ background: #fdd835; color:#111; }}
    .heat-low {{ background: #558b2f; }}
    .table-container {{
      overflow-x: auto;
      border-radius: 10px;
      background: #fff;
      box-shadow: 0 2px 6px rgba(0,0,0,0.08);
    }}
    .table-container table {{
      min-width: 960px;
      margin: 0;
      box-shadow: none;
    }}
    .column-controls {{
      margin: 1rem 0;
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      align-items: center;
      font-size: 0.9rem;
    }}
    .column-controls label {{
      font-weight: normal;
    }}
    .steps-list {{
      margin: 0;
      padding-left: 1.2rem;
    }}
    .steps-list li {{
      margin-bottom: 0.35rem;
    }}
    .payload-block {{
      background: #f4f4f4;
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      overflow-x: auto;
      font-family: "SFMono-Regular", Consolas, monospace;
      font-size: 0.8rem;
      white-space: pre-wrap;
    }}
    .code-location {{
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }}
    .code-path {{
      font-weight: 600;
      font-size: 0.85rem;
    }}
    .code-meta {{
      font-size: 0.8rem;
      color: #37474f;
    }}
    .code-snippet {{
      background: #f9f9f9;
      border: 1px dashed #d0d0d0;
      padding: 0.35rem 0.5rem;
      border-radius: 6px;
    }}
    .payload-tabs {{
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }}
    .payload-filter {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.85rem;
    }}
    .payload-tab-list {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }}
    .payload-tab {{
      border: 1px solid #d0d0d0;
      background: #fff;
      border-radius: 999px;
      padding: 0.25rem 0.9rem;
      cursor: pointer;
      font-size: 0.8rem;
      transition: background 0.2s ease;
    }}
    .payload-tab.active {{
      background: #1a73e8;
      color: #fff;
      border-color: #1a73e8;
    }}
    .payload-panel {{
      display: none;
      border: 1px solid #e3e3e3;
      border-radius: 8px;
      padding: 0.5rem 0.75rem;
      background: #fafafa;
    }}
    .payload-panel.active {{
      display: block;
    }}
    .payload-panel-header {{
      font-size: 0.85rem;
      font-weight: 600;
      margin-bottom: 0.4rem;
      display: flex;
      align-items: center;
      gap: 0.35rem;
    }}
    .payload-note {{
      font-size: 0.8rem;
      color: #37474f;
      margin: 0.4rem 0;
    }}
    .payload-alt {{
      font-size: 0.78rem;
      color: #555;
      margin-top: 0.3rem;
    }}
    .badge-tag {{
      background: #546e7a;
    }}
  </style>
</head>
<body>
  <h1>Prototype Pollution Scan</h1>
  <p><strong>Project:</strong> {esc(report.get('projectRoot', ''))}</p>
  <p><strong>Runtimes:</strong> {esc(', '.join(report.get('runtimeDetection', {}).get('runtimes', [])))}</p>

  <p>Download other formats: <a href=\"report.json\">JSON</a> · <a href=\"report.sarif\">SARIF</a> · <a href=\"report.csv\">CSV</a></p>

  <section class="summary">
    <div class="card">
      <h3>Total Chains</h3>
      <p class="value">{len(chains_rows)}</p>
    </div>
    {"".join(f'<div class="card"><h3>{esc(level.title())}</h3><p class="value">{count}</p></div>' for level, count in severity_counts.items()) or '<div class="card"><h3>Chains</h3><p class="value">0</p></div>'}
  </section>

  <section class="runtime-details">
    <h2>Runtime Detection</h2>
    <ul class="runtime-list">
      {runtime_list_html}
    </ul>
  </section>

  <div class="heatmap">
    {"".join(f'<div class=\"heatmap-cell heat-{esc(level)}\"><span>{esc(level.title())}</span><strong>{count}</strong></div>' for level, count in severity_counts.items()) or '<div class=\"heatmap-cell\"><span>No Data</span></div>'}
  </div>

  <div class="column-controls">
    <strong>Columns:</strong>
    {"".join(f'<label><input type=\"checkbox\" data-col=\"{esc(col)}\" checked onchange=\"toggleColumn(this)\"> {esc(label)}</label>' for col, label, _ in column_defs)}
  </div>

  <h2>Exploit Chains ({len(chains_rows)})</h2>
  <div class="table-container">
    <table class="chains-table">
      <thead>
        <tr>{header_cells_html}</tr>
      </thead>
      <tbody>
        {''.join(chains_rows) or f'<tr><td colspan="{len(column_defs)}">None</td></tr>'}
      </tbody>
    </table>
  </div>

  <h2>Dependency Findings ({len(dependency_rows)})</h2>
  <table>
    <thead>
      <tr><th>Package</th><th>Version</th><th>Spec</th><th>CVEs</th><th>Severity</th></tr>
    </thead>
    <tbody>
      {''.join(dependency_rows) or '<tr><td colspan="5">None</td></tr>'}
    </tbody>
  </table>
  <script>
  function collectColumnFilters() {{
    const filters = {{}};
    document.querySelectorAll('.header-filter').forEach(select => {{
      const column = select.getAttribute('data-filter-col');
      if (!column) {{
        return;
      }}
      filters[column] = select.value || '__all__';
    }});
    return filters;
  }}
  function applyRowFilters() {{
    const filters = collectColumnFilters();
    document.querySelectorAll('tbody tr[data-severity]').forEach(row => {{
      let visible = true;
      for (const [column, value] of Object.entries(filters)) {{
        if (!value || value === '__all__') {{
          continue;
        }}
        const cell = row.querySelector('td[data-col=\"' + column + '\"]');
        if (!cell) {{
          continue;
        }}
        const cellValue = cell.getAttribute('data-filter-value') || '';
        if (cellValue !== value) {{
          visible = false;
          break;
        }}
      }}
      row.style.display = visible ? '' : 'none';
    }});
  }}
  function toggleColumn(cb) {{
    const column = cb.getAttribute('data-col');
    document.querySelectorAll('[data-col=\"' + column + '\"]').forEach(cell => {{
      cell.style.display = cb.checked ? '' : 'none';
    }});
  }}
  function initPayloadTabs() {{
    document.querySelectorAll('.payload-tabs').forEach(container => {{
      const buttons = Array.from(container.querySelectorAll('[data-payload-tab]'));
      const panels = Array.from(container.querySelectorAll('[data-payload-panel]'));
      const filter = container.querySelector('[data-payload-filter]');
      if (!buttons.length) {{
        return;
      }}
      function activate(targetId) {{
        buttons.forEach(button => {{
          button.classList.toggle('active', button.getAttribute('data-payload-tab') === targetId);
        }});
        panels.forEach(panel => {{
          panel.classList.toggle('active', panel.getAttribute('data-payload-panel') === targetId);
        }});
      }}
      buttons.forEach(button => {{
        button.addEventListener('click', () => activate(button.getAttribute('data-payload-tab')));
      }});
      if (filter) {{
        filter.addEventListener('change', () => {{
          const value = filter.value;
          let firstVisible = null;
          buttons.forEach(button => {{
            const matches = value === 'all' ? true : button.getAttribute('data-category') === value;
            button.style.display = matches ? '' : 'none';
            if (matches && !firstVisible) {{
              firstVisible = button;
            }}
          }});
          if (firstVisible) {{
            activate(firstVisible.getAttribute('data-payload-tab'));
          }}
        }});
      }}
      activate(buttons[0].getAttribute('data-payload-tab'));
    }});
  }}
  applyRowFilters();
  initPayloadTabs();
  </script>
</body>
</html>
""")
    return "\n".join(line.strip() for line in html.strip().splitlines())


def render_csv(report: Dict[str, object]) -> str:
    rows = ["severity,route,source,sink,gadget,description,validation,payload,payload_variants"]
    for chain in report.get("flowChains", []):
        route = chain.get("route") or {}
        source = chain.get("source") or {}
        sink = chain.get("sink") or {}
        gadget = (chain.get("gadget") or {}).get("kind", "")
        variants = chain.get("payloadVariants") or []
        variant_summary = "; ".join(
            f"{variant.get('label', 'payload')}: {variant.get('payload', '')}" for variant in variants
        )
        row = [
            chain.get("severity", ""),
            f"{route.get('method', '')} {route.get('path', '')}".strip(),
            f"{source.get('path', '')}:{source.get('line', '')}",
            f"{sink.get('path', '')}:{sink.get('line', '')}",
            gadget,
            chain.get("description", ""),
            chain.get("validation", ""),
            chain.get("exploitExample", ""),
            variant_summary,
        ]
        rows.append(",".join(value.replace(",", ";") for value in row))
    return "\n".join(rows)
