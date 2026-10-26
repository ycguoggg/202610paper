"""Parse candidate endpoints without assuming app-session success."""
from __future__ import annotations
import ipaddress
from urllib.parse import urlsplit


def parse_ip(value: str, *, public_only: bool = True) -> str | None:
    try:
        ip = ipaddress.ip_address(str(value).strip())
        return str(ip) if (not public_only or ip.is_global) else None
    except ValueError:
        return None


def normalize_host(value: str) -> str:
    value = (value or "").strip()
    if "://" in value:
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return ""
    return value.rstrip(".").lower()


def parse_ports(value) -> set[int]:
    if value is None or value == "":
        return set()
    values = value if isinstance(value, list) else str(value).replace("|", ",").split(",")
    out = set()
    for raw in values:
        p = int(raw)
        if not 1 <= p <= 65535:
            raise ValueError("port outside valid range")
        out.add(p)
    return out


def normalize_event(record: dict, *, public_only: bool = True) -> dict:
    """Required: sample, timestamp, ip, port, observation_kind.

    Observation kind is one of returned / attempted / responded.
    An observed attempt does not establish a successful service session.
    """
    from datetime import datetime
    sample = str(record.get("sample", "")).strip()
    if not sample:
        raise ValueError("missing sample")
    kind = str(record.get("observation_kind", "")).lower()
    if kind not in {"returned", "attempted", "responded"}:
        raise ValueError("observation_kind must be returned, attempted or responded")
    ip = parse_ip(str(record.get("ip", "")), public_only=public_only)
    if not ip:
        raise ValueError("invalid or non-public IP")
    port = int(record["port"])
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    stamp = str(record["timestamp"]).replace("Z", "+00:00")
    timestamp = datetime.fromisoformat(stamp)
    if timestamp.tzinfo is None:
        raise ValueError("timestamp requires timezone")
    return {"sample": sample, "config": str(record.get("config") or ""),
            "timestamp": timestamp.isoformat(), "ip": ip, "port": port,
            "observation_kind": kind,
            "entry_domain": normalize_host(str(record.get("entry_domain") or "")),
            "channel": str(record.get("channel") or ""),
            "snapshot_id": str(record.get("snapshot_id") or "")}
