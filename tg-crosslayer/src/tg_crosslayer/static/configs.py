"""Family-conditioned exact L0-L5 engineering signatures."""
from __future__ import annotations
import hashlib
import json
from collections import Counter, defaultdict
from itertools import combinations
from typing import Iterable

LAYERS = (
    ("family",),
    ("family", "capabilities"),
    ("family", "capabilities", "native_libraries", "sdk_indicators", "system_features", "config_features"),
    ("family", "capabilities", "native_libraries", "sdk_indicators", "system_features", "config_features", "permissions", "resources"),
    ("family", "capabilities", "native_libraries", "sdk_indicators", "system_features", "config_features", "permissions", "resources", "static_network", "original_lib_names"),
    ("family", "capabilities", "native_libraries", "sdk_indicators", "system_features", "config_features", "permissions", "resources", "static_network", "original_lib_names", "package", "certificate", "app_label"),
)
SET_FIELDS = frozenset({"capabilities", "native_libraries", "sdk_indicators", "system_features", "config_features", "permissions", "resources", "static_network", "original_lib_names"})


def _canonical(value, key):
    if key in SET_FIELDS:
        if value is None:
            return None
        if isinstance(value, str):
            value = [x for x in value.split("|") if x]
        return sorted(set(value))
    return value if value not in ("", "nan") else None


def signature(record: dict, layer: int) -> str:
    if not 0 <= layer < len(LAYERS):
        raise ValueError("layer must be 0..5")
    return json.dumps({k: _canonical(record.get(k), k) for k in LAYERS[layer]},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def group_records(records: Iterable[dict]) -> dict:
    records = list(records)
    seen = set()
    for r in records:
        if not r.get("sample") or r["sample"] in seen:
            raise ValueError("sample identifiers must be nonempty and unique")
        seen.add(r["sample"])
    assignments = []
    groups = [defaultdict(list) for _ in LAYERS]
    for r in records:
        row = {"sample": r["sample"]}
        for level in range(6):
            # Samples without an attributable family remain outside config statistics.
            if r.get("family") is None:
                row[f"L{level}"] = None
                continue
            token = signature(r, level)
            gid = f"L{level}_" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
            row[f"L{level}"] = gid
            groups[level][gid].append(r["sample"])
        assignments.append(row)
    metrics = {}
    for i, memberships in enumerate(groups):
        n = sum(len(x) for x in memberships.values())
        recurring = [v for v in memberships.values() if len(v) > 1]
        metrics[f"L{i}"] = {"eligible_samples": n, "groups": len(memberships),
                             "recurring_groups": len(recurring),
                             "recurring_samples": sum(map(len, recurring)),
                             "recurring_coverage": sum(map(len, recurring)) / n if n else None}
    return {"assignments": assignments, "metrics": metrics}


def categorical_pair_variation(values: Iterable) -> float | None:
    vals = [v for v in values if v is not None and v != ""]
    n = len(vals)
    if n < 2:
        return None
    frequencies = Counter(vals)
    pairs = n * (n - 1) // 2
    return 1 - sum(c * (c - 1) // 2 for c in frequencies.values()) / pairs


def jaccard_distance(a: Iterable, b: Iterable) -> float:
    x, y = set(a), set(b)
    return 1 - len(x & y) / len(x | y) if x or y else 0.0


def set_pair_variation(values: Iterable) -> float | None:
    vals = [set(v.split("|") if isinstance(v, str) else v) for v in values if v is not None]
    if len(vals) < 2:
        return None
    count = 0
    distance = 0.0
    for a, b in combinations(vals, 2):
        distance += jaccard_distance(a, b)
        count += 1
    return distance / count if count else None


def within_config_variation(records: list[dict], field: str, *, set_valued: bool = False) -> dict:
    """Aggregate only observable same-L2-config pairs; no replacement of missing values."""
    lookup = defaultdict(list)
    for r in records:
        if r.get("family") is not None:
            lookup[signature(r, 2)].append(r)
    weighted_sum = 0.0
    eligible_pairs = 0
    for group in lookup.values():
        values = [r.get(field) for r in group]
        observed = [x for x in values if x is not None and x != ""]
        n = len(observed)
        if n < 2:
            continue
        val = set_pair_variation(observed) if set_valued else categorical_pair_variation(observed)
        pairs = n * (n - 1) // 2
        eligible_pairs += pairs
        weighted_sum += val * pairs
    return {"field": field, "observable_pairs": eligible_pairs,
            "mean_pairwise_distance": weighted_sum / eligible_pairs if eligible_pairs else None}
