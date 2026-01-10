"""Shared payload and fingerprint metadata derived from fuzzing research."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional


_DATA_FILE = Path(__file__).resolve().parent / "data" / "payload_library.json"


@lru_cache(maxsize=1)
def _load_library() -> Dict[str, object]:
    try:
        return json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:  # pragma: no cover - defensive
        return {"payloads": {}, "fingerprints": []}


def payload_library() -> Dict[str, object]:
    """Return the full payload/fingerprint structure."""

    data = _load_library()
    # Return a shallow copy to avoid accidental mutation of cached data.
    return {
        "payloads": dict(data.get("payloads", {})),
        "fingerprints": list(data.get("fingerprints", [])),
    }


@lru_cache(maxsize=1)
def _fingerprint_alias_map() -> Dict[str, Dict[str, object]]:
    mapping: Dict[str, Dict[str, object]] = {}
    data = _load_library()
    for entry in data.get("fingerprints", []):
        aliases = entry.get("aliases", [])
        if not isinstance(aliases, list):
            continue
        for alias in aliases:
            if isinstance(alias, str):
                mapping[alias] = entry
    return mapping


def fingerprint_for_alias(alias: str) -> Optional[Dict[str, object]]:
    """Return fingerprint metadata for a gadget kind."""

    return _fingerprint_alias_map().get(alias)
