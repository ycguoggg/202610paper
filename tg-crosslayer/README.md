# Telegram Cross-Layer Analysis

Implementation-oriented toolkit for studying reuse in Telegram-derived Android clients and the network endpoint pools associated with their configurations. No APKs, traffic, addresses collected from studied apps, research measurements, credentials or real sample identifiers are included.

## Requirements

Python 3.10+. Static scanning accepts an already decompiled JADX or unpacked APK directory. Baseline matching expects separately supplied official Telegram build artifacts. Live measurement requires ADB, a rooted Android device, `iptables` (with owner and LOG support), and device-side `tcpdump` at `/vendor/bin/tcpdump`.

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Static analysis

```bash
tg-crosslayer scan --project /path/to/decompiled-app --sample sample-id --output output/sample.json
tg-crosslayer baseline --project /path/to/official-client --family TG31 --output output/official.json
tg-crosslayer attribute --record output/sample.json --baselines /path/to/baselines.json --output output/attribution.json
tg-crosslayer group --records /path/to/features.jsonl --variation-field package --variation-field native_libraries --output output/groups.json
```

`baselines.json` is an array of baseline JSON objects. Add the separately justified `family` assignment to each record before grouping. Unmatched samples remain unassigned. Native binary equality gives direct evidence; other shared libraries only produce attribution candidates. A detected SDK is not execution evidence. The `scan` command extracts candidate static indicators; it is not a ground-truth fraud classifier.

Grouping is exact by normalized, family-conditioned signatures. The levels are L0 (upstream), L1 (capabilities), L2 (engineering configuration), L3 (permissions/resources), L4 (static network/original libraries), and L5 (release identity). Coverage is calculated on samples eligible for that layer. Within-config variation uses observable pairs; missing fields are excluded.

## Runtime and backend analysis

```bash
tg-crosslayer probe --cases /private/cases.json --output output/baseline --block-scope none
tg-crosslayer probe --cases /private/cases.json --output output/perturbed --block-scope ip
tg-crosslayer import-probe --runs output/perturbed --output output/events.jsonl
tg-crosslayer pools --events output/events.jsonl --output output/pools.json
tg-crosslayer churn --snapshots /private/snapshots.jsonl --scope group --output output/churn.json
```

`cases.json` is a local JSON array of objects with `sample` (the APK MD5), `apk` (local absolute path) and `package` (Android package name). It is not part of the repository. The probe follows UID-scoped outbound flow attempts, records replies separately, progressively blocks previously attempted non-DNS targets, clears test rules and records local capture files. Baseline and perturbation are separate invocations; compare only equivalent observation windows.

The endpoint-event schema is `sample`, `timestamp` (timezone-aware ISO-8601), `ip`, `port`, `observation_kind` (`returned`, `attempted`, `responded`), and optional `config`, `entry_domain`, `channel`, `snapshot_id`. Pool counts are candidate unions, not proof of successful Telegram sessions. To link configs without embedding operational data, supply `--config-map /private/sample-config.json` as a JSON object mapping samples to L2 configuration IDs.

The snapshot schema is `group`, `timestamp`, `ips` (list or `|`-separated), `complete` (boolean), `decoder_profile`, optional `channel` and `ports_by_ip`. Use `--scope group` for complete config-group snapshots and `--scope channel` for individual channels. Comparisons require matching decoder profiles and satisfy `--max-gap-hours`; these denominators are not interchangeable.

## Output policy

Everything under `output/`, `results/`, `captures/`, `samples/` and `apks/` is ignored by Git. Under `data/`, only `README.md` is tracked; all datasets and other contents are ignored. Never commit probe output, real endpoint lists, private manifests or decompiled third-party source without permission. This repository intentionally contains no reported measurement tables or fixed counts: those are computed from separately supplied inputs.
