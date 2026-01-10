"""Helpers to load client gadget fingerprint rules derived from research repos."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, List


_DATA_FILE = Path(__file__).resolve().parent / "data" / "client_gadget_fingerprints.json"


@lru_cache(maxsize=1)
def _load_fingerprints() -> Dict[str, object]:
    try:
        data = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:  # pragma: no cover - defensive default
        return {"gadgets": []}
    entries = data.get("gadgets", [])
    normalized: List[Dict[str, object]] = []
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            kind = entry.get("kind")
            if not isinstance(kind, str) or not kind:
                continue
            normalized.append(entry)
    return {"gadgets": normalized}


def client_gadget_rules() -> List[Dict[str, object]]:
    """Return normalized gadget fingerprints."""

    return list(_load_fingerprints().get("gadgets", []))
