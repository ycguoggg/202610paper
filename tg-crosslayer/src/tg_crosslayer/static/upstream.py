"""Explicit upstream-reference matching, with auditable evidence tiers."""
from __future__ import annotations
from .scan import scan_project


def build_baseline(project: str, family: str) -> dict:
    record = scan_project(project, sample="official", include_endpoints=False, full_java=True)
    return {"family": family,
            "core_hashes": record["core_hashes"],
            "core_jni_signatures": record["core_jni_signatures"],
            "native_libraries": record["native_libraries"],
            "tg_markers": record["tg_markers"]}


def attribute_family(sample: dict, baselines: list[dict]) -> dict:
    """Use exact core match first; peripheral native overlap is supporting evidence only."""
    if not baselines:
        return {"family": None, "evidence": "unavailable", "candidates": []}
    if not sample.get("tg_markers") and not sample.get("core_hashes") and not sample.get("core_jni_signatures"):
        return {"family": None, "evidence": "no_telegram_evidence", "candidates": []}
    exact = [b["family"] for b in baselines
             if set(sample.get("core_hashes", [])) & set(b.get("core_hashes", []))]
    if len(set(exact)) == 1:
        return {"family": exact[0], "evidence": "exact_native_core", "candidates": exact}
    if exact:
        return {"family": None, "evidence": "ambiguous_core", "candidates": sorted(set(exact))}
    # JNI signatures corroborate modified/renamed cores when enough identifiers survive.
    sample_signatures = set(sample.get("core_jni_signatures", []))
    if len(sample_signatures) >= 8:
        similarities = []
        for baseline in baselines:
            reference = set(baseline.get("core_jni_signatures", []))
            similarity = len(sample_signatures & reference) / len(sample_signatures | reference) if reference else 0.0
            similarities.append((similarity, baseline["family"]))
        similarities.sort(reverse=True)
        highest, candidate = similarities[0]
        runner_up = similarities[1][0] if len(similarities) > 1 else 0.0
        if highest >= 0.85 and highest - runner_up >= 0.10:
            return {"family": candidate, "evidence": "jni_core_alignment", "candidates": [candidate]}
    scored = []
    sample_libs = set(sample.get("native_libraries", []))
    sample_tg = set(sample.get("tg_markers", []))
    for baseline in baselines:
        # Shared native SDKs are insufficient to assert an upstream family.
        overlap = len(sample_libs & set(baseline.get("native_libraries", [])))
        anchor = len(sample_tg & set(baseline.get("tg_markers", [])))
        scored.append((overlap, anchor, baseline["family"]))
    scored.sort(reverse=True)
    possible = [family for overlap, anchor, family in scored if overlap > 0 and anchor > 0]
    return {"family": None, "evidence": "structural_candidates_only" if possible else "unresolved",
            "candidates": possible}
