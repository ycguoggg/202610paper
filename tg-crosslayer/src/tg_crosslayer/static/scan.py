"""Bounded text/native scanning of an unpacked or decompiled APK project."""
from __future__ import annotations
import hashlib
import ipaddress
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit
from .markers import (TG_TEXT_MARKERS, TG_PATH_MARKERS, CAPABILITY_MARKERS,
                      TEXT_SUFFIXES, RESOURCE_NAME_HINTS, JAVA_NAME_HINTS,
                      URL_RE, DOMAIN_RE, IP_RE)


def _text_files(root: Path, full_java: bool, max_bytes: int):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root)
        parts = {s.lower() for s in rel.parts}
        if parts & {".git", "__pycache__", "cache", "build"}:
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES or path.stat().st_size > max_bytes:
            continue
        if path.suffix.lower() == ".java" and not full_java and not (any(x in path.stem.lower() for x in JAVA_NAME_HINTS)
            or "org/telegram/" in rel.as_posix().lower()):
            continue
        if path.suffix.lower() != ".java" and not (parts & {"res", "resources", "assets"} or any(x in path.stem.lower() for x in RESOURCE_NAME_HINTS)):
            continue
        yield path


def _native_files(root: Path):
    for p in sorted(root.rglob("*.so")):
        if p.is_file() and not p.is_symlink():
            yield p


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def scan_project(root: str | Path, sample: str, *, full_java: bool = False,
                 max_file_bytes: int = 2_000_000, include_endpoints: bool = True) -> dict:
    """Extract static evidence; generated values are not executed or resolved."""
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(root)
    hits: dict[str, set[str]] = defaultdict(set)
    tg: set[str] = set()
    static_hosts: set[str] = set()
    static_ips: set[str] = set()
    static_urls: set[str] = set()
    permission: set[str] = set()
    components: set[str] = set()
    resources: set[str] = set()
    scanned = 0
    sdk_seen: set[str] = set()
    for path in _text_files(root, full_java, max_file_bytes):
        rel = path.relative_to(root).as_posix()
        body = path.read_text(encoding="utf-8", errors="ignore")
        low = body.lower()
        scanned += 1
        for marker in TG_PATH_MARKERS:
            if marker in rel.lower():
                tg.add(marker)
        for marker in TG_TEXT_MARKERS:
            if marker in low:
                tg.add(marker)
        sdk_seen.update(x for x in ("bugly", "umeng", "xinstall", "clink") if x in low)
        for cap, markers in CAPABILITY_MARKERS.items():
            if any(marker in low for marker in markers):
                hits[cap].add(rel)
        if path.name.lower() == "androidmanifest.xml":
            permission.update(re.findall(r"android\.permission\.[A-Za-z_]+", body))
            components.update(re.findall(r"<\s*(activity|service|receiver|provider)\b", low))
        if "res" in {x.lower() for x in path.relative_to(root).parts}:
            resource_id = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
            resources.add(f"{rel}:{resource_id}")
        if include_endpoints:
            for url in URL_RE.findall(body):
                u = url.rstrip(".,;:)]}")
                static_urls.add(u)
                host = (urlsplit(u).hostname or "").lower()
                if host and DOMAIN_RE.fullmatch(host):
                    static_hosts.add(host)
                elif _public_ip(host):
                    static_ips.add(host)
            for domain in DOMAIN_RE.findall(body):
                static_hosts.add(domain.lower())
            for ip in IP_RE.findall(body):
                if _public_ip(ip):
                    static_ips.add(ip)
    natives = sorted({p.name.lower() for p in _native_files(root)})
    sdk_names = ("bugly", "umeng", "xinstall", "clink")
    sdk = sorted(sdk_seen | {name for name in sdk_names if name in " ".join(natives)})
    # An explicit absence in an inspected project is different from an unobserved field.
    system_features = sorted(x for x in ("environment", "protection") if x in hits)
    config_features = sorted(x for x in ("config", "proxy", "web_h5") if x in hits)
    core_files = [p for p in _native_files(root) if "tmessages" in p.name.lower()]
    core_hashes = []
    core_jni_signatures = set()
    for core in core_files:
        binary = core.read_bytes()
        core_hashes.append(hashlib.sha256(binary).hexdigest())
        # Retained JNI identifiers can remain recognizable under file renaming.
        for symbol in re.findall(rb"Java_org_telegram_[A-Za-z0-9_]{8,160}", binary):
            core_jni_signatures.add(hashlib.sha256(symbol).hexdigest()[:24])
    core_hashes = sorted(set(core_hashes))
    return {
        "sample": sample, "scanned_files": scanned,
        "tg_markers": sorted(tg), "capabilities": sorted(k for k, v in hits.items() if v),
        "capability_evidence": {k: sorted(v) for k, v in sorted(hits.items())},
        "native_libraries": natives, "original_lib_names": natives, "core_hashes": core_hashes,
        "core_jni_signatures": sorted(core_jni_signatures),
        "sdk_indicators": sdk, "system_features": system_features, "config_features": config_features,
        "permissions": sorted(permission), "components": sorted(components),
        "resources": sorted(resources),
        "static_network": sorted(static_hosts | static_ips) if include_endpoints else [],
        "endpoint_evidence": {
            "urls": sorted(static_urls), "domains": sorted(static_hosts), "ips": sorted(static_ips)
        } if include_endpoints else {},
    }
