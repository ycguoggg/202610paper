"""Qualified complete-group and exact-channel snapshot transitions."""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime
from .endpoints import parse_ip, parse_ports


def normalize_snapshot(row: dict) -> dict:
    """Each snapshot denotes an entire IP set for its stated observation scope."""
    group = str(row.get("group") or "").strip()
    if not group:
        raise ValueError("group must be nonempty")
    timestamp = datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("timezone is required")
    ips = row.get("ips") or []
    if isinstance(ips, str):
        ips = [part.strip() for part in ips.split("|") if part.strip()]
    ipset = set()
    for value in ips:
        ip = parse_ip(value, public_only=False)
        if ip is None:
            raise ValueError("invalid snapshot IP")
        ipset.add(ip)
    ports_by_ip = {}
    for ip, ports in row.get("ports_by_ip", {}).items():
        normalized = parse_ip(ip, public_only=False)
        if not normalized:
            raise ValueError("invalid port-map IP")
        ports_by_ip[normalized] = sorted(parse_ports(ports))
    return {"group": group, "channel": str(row.get("channel") or ""),
            "timestamp": timestamp, "ips": ipset, "ports_by_ip": ports_by_ip,
            "complete": row.get("complete") is True or str(row.get("complete")).lower() == "true",
            "decoder_profile": str(row.get("decoder_profile") or "")}


def analyze_churn(snapshots: list[dict], *, scope: str = "group", max_gap_hours: float = 24) -> dict:
    """Never mix exact-channel events with complete config-group transitions."""
    if scope not in {"group", "channel"}:
        raise ValueError("scope must be group or channel")
    buckets = defaultdict(list)
    for snapshot in snapshots:
        row = normalize_snapshot(snapshot)
        if scope == "group" and not row["complete"]:
            continue
        key = (row["group"], row["channel"] if scope == "channel" else "")
        buckets[key].append(row)
    transitions = 0
    changed = 0
    replaced = 0
    port_only = 0
    changed_similarities = []
    recurrence_events = 0
    groups_with_recurrence = set()
    for key, series in buckets.items():
        series.sort(key=lambda r: r["timestamp"])
        # Co-timestamp duplicates are not consecutive measurements.
        unique = {}
        for row in series:
            instant = row["timestamp"]
            if instant in unique:
                previous = unique[instant]
                if any(row[field] != previous[field] for field in ("ips", "ports_by_ip", "decoder_profile")):
                    raise ValueError("conflicting snapshots at the same timestamp and scope")
            unique[instant] = row
        rows = [unique[t] for t in sorted(unique)]
        history = set()
        for index, current in enumerate(rows):
            frozen = frozenset(current["ips"])
            if index:
                previous = rows[index - 1]
                gap = (current["timestamp"] - previous["timestamp"]).total_seconds() / 3600
                if gap < 0 or gap > max_gap_hours or current["decoder_profile"] != previous["decoder_profile"]:
                    history.add(frozen)
                    continue
                transitions += 1
                old, new = previous["ips"], current["ips"]
                if old != new:
                    changed += 1
                    jaccard = len(old & new) / len(old | new) if old or new else 1.0
                    changed_similarities.append(jaccard)
                    if not old & new:
                        replaced += 1
                    if frozen in history:
                        recurrence_events += 1
                        groups_with_recurrence.add(key[0])
                elif current["ports_by_ip"] != previous["ports_by_ip"] and current["ports_by_ip"] and previous["ports_by_ip"]:
                    port_only += 1
            history.add(frozen)
    ordered = sorted(changed_similarities)
    n = len(ordered)
    median = (ordered[(n - 1) // 2] + ordered[n // 2]) / 2 if n else None
    return {"scope": scope, "qualified_groups": len(buckets), "transitions": transitions,
            "ip_set_changes": changed, "change_rate": changed / transitions if transitions else None,
            "complete_replacements": replaced,
            "replacement_fraction_of_changes": replaced / changed if changed else None,
            "median_jaccard_among_changed": median,
            "port_only_transitions": port_only, "set_recurrence_events": recurrence_events,
            "groups_with_recurrence": len(groups_with_recurrence)}
