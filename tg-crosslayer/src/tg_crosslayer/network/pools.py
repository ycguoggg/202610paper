"""App- and configuration-attributed infrastructure sharing metrics."""
from __future__ import annotations
from collections import Counter, defaultdict
from itertools import combinations


def summarize_pools(events: list[dict], sample_configs: dict[str, str] | None = None) -> dict:
    """Aggregate the distinct timestamped candidate union, not live availability."""
    mapping = sample_configs or {}
    app_ips = defaultdict(set)
    cfg_ips = defaultdict(set)
    ip_apps = defaultdict(set)
    ip_configs = defaultdict(set)
    all_pairs = set()
    by_status = defaultdict(set)
    domains = set()
    for event in events:
        sample = event["sample"]
        config = mapping.get(sample) or event.get("config", "")
        ip = event["ip"]
        app_ips[sample].add(ip)
        ip_apps[ip].add(sample)
        if config:
            cfg_ips[config].add(ip)
            ip_configs[ip].add(config)
        all_pairs.add((ip, int(event["port"])))
        by_status[event["observation_kind"]].add(ip)
        if event.get("entry_domain"):
            domains.add(event["entry_domain"])
    shared_app = {ip for ip, apps in ip_apps.items() if len(apps) > 1}
    shared_config = {ip for ip, cfgs in ip_configs.items() if len(cfgs) > 1}
    edges = set()
    for ip, cfgs in ip_configs.items():
        edges.update(combinations(sorted(cfgs), 2))
    return {
        "observed_apps": len(app_ips), "observed_configs": len(cfg_ips),
        "candidate_ips": len(ip_apps), "candidate_ip_ports": len(all_pairs),
        "entry_domains": len(domains),
        "ips_shared_by_apps": len(shared_app),
        "ips_shared_by_configs": len(shared_config),
        "apps_with_shared_ip": sum(bool(ips & shared_app) for ips in app_ips.values()),
        "config_pair_sharing_edges": len(edges),
        "evidence_ip_counts": {k: len(v) for k, v in sorted(by_status.items())},
        "per_app_ip_count": {k: len(v) for k, v in sorted(app_ips.items())},
        "per_config_ip_count": {k: len(v) for k, v in sorted(cfg_ips.items())},
    }


def config_pool_links(events: list[dict], sample_configs: dict[str, str] | None = None) -> list[dict]:
    pairs = defaultdict(set)
    mapping = sample_configs or {}
    for ev in events:
        config = mapping.get(ev["sample"]) or ev.get("config", "")
        if config:
            pairs[(config, ev["ip"])].add(ev["sample"])
    return [{"config": config, "ip": ip, "app_count": len(apps)}
            for (config, ip), apps in sorted(pairs.items())]
