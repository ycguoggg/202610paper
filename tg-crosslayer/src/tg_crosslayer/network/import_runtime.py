"""Convert local, app-attributed probe output into candidate endpoint events."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from ..io import read_json
from .endpoints import normalize_event


def import_probe_results(root: str | Path, sample_configs: dict[str, str] | None = None) -> list[dict]:
    configs = sample_configs or {}
    events = []
    for path in sorted(Path(root).glob("*/result.json")):
        report = read_json(path)
        if not report.get("cleanup_ok"):
            continue
        sample = report.get("sample", "")
        for attempt in report.get("attempts", []):
            record = {"sample": sample, "config": configs.get(sample, ""),
                      "timestamp": attempt.get("utc"), "ip": attempt.get("ip"),
                      "port": attempt.get("port"), "observation_kind": "attempted"}
            try:
                events.append(normalize_event(record))
            except (KeyError, ValueError, TypeError):
                continue
        for flow in report.get("flows", []):
            if not flow.get("real_reply"):
                continue
            epoch = flow.get("first_epoch")
            stamp = datetime.fromtimestamp(epoch, timezone.utc).isoformat() if epoch is not None else report.get("started_utc")
            record = {"sample": sample, "config": configs.get(sample, ""),
                      "timestamp": stamp, "ip": flow.get("ip"), "port": flow.get("port"),
                      "observation_kind": "responded"}
            try:
                events.append(normalize_event(record))
            except (KeyError, ValueError, TypeError, OverflowError):
                continue
    return events
