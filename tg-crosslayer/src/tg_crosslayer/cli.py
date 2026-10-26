"""Command-line interfaces; all inputs and outputs are caller-provided."""
from __future__ import annotations
import argparse
import json
import pathlib
from .io import read_json, read_jsonl, read_csv, write_json, write_jsonl
from .static.scan import scan_project
from .static.upstream import build_baseline, attribute_family
from .static.configs import group_records, within_config_variation, SET_FIELDS
from .network.endpoints import normalize_event
from .network.pools import summarize_pools, config_pool_links
from .network.churn import analyze_churn
from .network.import_runtime import import_probe_results


def _records(path: str) -> list[dict]:
    records = read_jsonl(path) if str(path).endswith(".jsonl") else read_json(path)
    if not isinstance(records, list):
        raise ValueError("input must be a JSON array or JSONL records")
    return records


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tg-crosslayer")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="inspect a JADX/decompiled project")
    scan.add_argument("--project", required=True)
    scan.add_argument("--sample", required=True)
    scan.add_argument("--full-java", action="store_true")
    scan.add_argument("--output", required=True)
    baseline = commands.add_parser("baseline", help="index one official client baseline")
    baseline.add_argument("--project", required=True)
    baseline.add_argument("--family", required=True)
    baseline.add_argument("--output", required=True)
    assign = commands.add_parser("attribute", help="match sample to official baselines")
    assign.add_argument("--record", required=True)
    assign.add_argument("--baselines", required=True, help="JSON array of baseline objects")
    assign.add_argument("--output", required=True)
    group = commands.add_parser("group", help="exact signatures and group coverage at L0-L5")
    group.add_argument("--records", required=True)
    group.add_argument("--output", required=True)
    group.add_argument("--variation-field", action="append", default=[])
    endpoint = commands.add_parser("pools", help="per-app and per-config candidate IP sharing")
    endpoint.add_argument("--events", required=True)
    endpoint.add_argument("--include-nonpublic", action="store_true", help="permit test/lab IP ranges")
    endpoint.add_argument("--config-map", help="JSON mapping sample->config")
    endpoint.add_argument("--output", required=True)
    churn = commands.add_parser("churn", help="qualified snapshot set changes")
    churn.add_argument("--snapshots", required=True)
    churn.add_argument("--scope", choices=["group", "channel"], default="group")
    churn.add_argument("--max-gap-hours", type=float, default=24.0)
    churn.add_argument("--output", required=True)
    imp = commands.add_parser("import-probe", help="import raw local app UID observations")
    imp.add_argument("--runs", required=True)
    imp.add_argument("--config-map")
    imp.add_argument("--output", required=True)
    probe = commands.add_parser("probe", help="run rooted Android UID-scoped endpoint observation")
    probe.add_argument("--cases", required=True, help="JSON array: sample (APK MD5), apk, package")
    probe.add_argument("--output", required=True)
    probe.add_argument("--adb", default="adb")
    probe.add_argument("--serial", default=None)
    probe.add_argument("--abi", choices=["auto", "arm64-v8a", "armeabi-v7a"], default="auto")
    probe.add_argument("--strategy", choices=["cumulative", "adaptive"], default="cumulative")
    probe.add_argument("--block-scope", choices=["ip", "endpoint", "none"], default="ip")
    probe.add_argument("--seconds", type=int, default=60)
    probe.add_argument("--poll", type=float, default=2)
    probe.add_argument("--warmup", type=float, default=6)
    probe.add_argument("--grace", type=float, default=3)
    probe.add_argument("--probe-timeout", type=float, default=10)
    probe.add_argument("--reset-interval", type=float, default=30)
    probe.add_argument("--recovery", type=float, default=8)
    probe.add_argument("--restart-interval", type=float, default=0)
    probe.add_argument("--block-mode", choices=["reject", "drop"], default="reject")
    probe.add_argument("--restart-on-stall", action=argparse.BooleanOptionalAction, default=True)
    probe.add_argument("--prefer-nonweb", action="store_true")
    probe.add_argument("--reuse-installed", action="store_true")
    probe.add_argument("--ui-navigation", action="store_true")
    probe.add_argument("--sample", action="append")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        write_json(args.output, scan_project(args.project, args.sample, full_java=args.full_java))
    elif args.command == "baseline":
        write_json(args.output, build_baseline(args.project, args.family))
    elif args.command == "attribute":
        write_json(args.output, attribute_family(read_json(args.record), read_json(args.baselines)))
    elif args.command == "group":
        records = _records(args.records)
        result = group_records(records)
        if args.variation_field:
            result["variations"] = [within_config_variation(records, field, set_valued=field in SET_FIELDS)
                                    for field in args.variation_field]
        write_json(args.output, result)
    elif args.command == "pools":
        events = [normalize_event(r, public_only=not args.include_nonpublic) for r in _records(args.events)]
        mapping = read_json(args.config_map) if args.config_map else None
        result = summarize_pools(events, mapping)
        result["config_ip_links"] = config_pool_links(events, mapping)
        write_json(args.output, result)
    elif args.command == "churn":
        if args.max_gap_hours <= 0:
            parser.error("max-gap-hours must be positive")
        write_json(args.output, analyze_churn(_records(args.snapshots), scope=args.scope,
                                               max_gap_hours=args.max_gap_hours))
    elif args.command == "import-probe":
        mapping = read_json(args.config_map) if args.config_map else None
        write_jsonl(args.output, import_probe_results(args.runs, mapping))
    elif args.command == "probe":
        if not 20 <= args.seconds <= 1800:
            parser.error("seconds must be 20..1800")
        if args.recovery < 0 or args.recovery >= args.seconds:
            parser.error("recovery must be in [0, seconds)")
        if min(args.poll, args.grace, args.warmup, args.probe_timeout) <= 0:
            parser.error("poll, grace, warmup and probe-timeout must be positive")
        from .runtime.probe import ProgressiveProbe
        ProgressiveProbe(args).run_blackbox()


if __name__ == "__main__":
    main()
