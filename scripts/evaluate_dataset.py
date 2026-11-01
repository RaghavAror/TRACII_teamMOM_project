"""Measure Tracii's malicious-package detectors on the chainviz-v2 labelled dataset.

Measurement only: no model is trained, no package is installed or executed.

Usage (from repo root):
  .venv/bin/python scripts/evaluate_dataset.py --labels datasets/chainviz-dataset/labels.csv --label benign
  .venv/bin/python scripts/evaluate_dataset.py --labels ... --malicious-root datasets/cache/datadog [--guarddog]
  .venv/bin/python scripts/evaluate_dataset.py --labels ... --split test --final      # once, after tuning on dev

A package counts as flagged when a detector reports a malicious_indicator finding with
severity >= medium (same rule as scripts/evaluate.py). Samples whose code could not be
obtained are listed as unavailable and excluded from rates, never counted as "not flagged".
Writes results/evaluation_dataset[.<split>].local.json (git-ignored until you choose to publish it).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from tracii.detect import guarddog, static_rules  # noqa: E402
from tracii.eval.dataset import Sample, SampleUnavailable, load_labels, load_sample  # noqa: E402

FLAG = {"critical", "high", "medium"}


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    """95% Wilson score interval for k/n (sensible for small n and rates near 0 or 1)."""
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 3), round(min(1.0, c + h), 3)]


def content_key(files: dict[str, str]) -> str:
    """Packages with identical code (ignoring package.json) share a key: near-duplicate samples."""
    h = hashlib.sha256()
    for path in sorted(files):
        if path != "package.json":
            h.update(path.encode() + b"\0" + files[path].encode() + b"\0")
    return h.hexdigest()[:16]


def evaluate(sample: Sample, pkg, use_guarddog: bool) -> dict:
    t = time.perf_counter()
    st = static_rules.analyze_package(pkg)
    row = {"id": sample.id, "package": f"{sample.package}@{sample.version}", "label": sample.label,
           "group": sample.group, "content_key": content_key(pkg.files), "files": len(pkg.files),
           "has_install_script": bool(static_rules.install_scripts(pkg.manifest)),
           # name-squats / placeholders: no install script and (almost) no JS, so nothing for code analysis to see
           "no_code": not static_rules.install_scripts(pkg.manifest) and sum(
               len(t) for p, t in {**pkg.files, **pkg.large}.items() if p.endswith((".js", ".cjs", ".mjs"))) < 200,
           "static_ms": round((time.perf_counter() - t) * 1000, 1),
           "static_flagged": any(f.severity.value in FLAG for f in st),
           "static_rules": sorted({f.rule_or_advisory for f in st if f.severity.value in FLAG}),
           "static_info_rules": sorted({f.rule_or_advisory for f in st if f.severity.value not in FLAG})}
    if use_guarddog:
        # A GuardDog failure on one package is recorded and excluded from GuardDog's rates (None), not a crash.
        try:
            gd = guarddog.to_findings(guarddog.run_guarddog(pkg), pkg)
            row |= {"guarddog_flagged": any(f.severity.value in FLAG for f in gd),
                    "guarddog_rules": sorted({f.rule_or_advisory for f in gd if f.severity.value in FLAG})}
        except Exception as exc:
            row |= {"guarddog_flagged": None, "guarddog_error": f"{type(exc).__name__}: {str(exc)[:160]}"}
        row["combined_flagged"] = None if row["guarddog_flagged"] is None else \
            row["static_flagged"] or row["guarddog_flagged"]
    return row


def osv_known_malware(samples: list[Sample]) -> dict[str, list[str]]:
    """sample id -> OSV MAL- ids for its exact name@version (one batch query per 500)."""
    out: dict[str, list[str]] = {}
    with httpx.Client(timeout=60) as client:
        for i in range(0, len(samples), 500):
            chunk = samples[i:i + 500]
            body = {"queries": [{"package": {"name": s.package, "ecosystem": "npm"}, "version": s.version} for s in chunk]}
            resp = client.post("https://api.osv.dev/v1/querybatch", json=body)
            resp.raise_for_status()
            for s, res in zip(chunk, resp.json().get("results", [])):
                out[s.id] = sorted(v["id"] for v in res.get("vulns") or [] if v["id"].startswith("MAL-"))
    return out


def summarise(rows: list[dict], detectors: list[str]) -> dict:
    """Per detector and group: flagged / scored with a 95% interval; malicious also per unique-code cluster."""
    out: dict = {}
    for det in detectors:
        key = f"{det}_flagged"
        by_group: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            if r.get(key) is None:          # detector did not run on this package
                continue
            by_group[r["group"]].append(r)
            by_group[r["label"] + "/ALL"].append(r)
            if r["label"] == "malicious" and not r.get("no_code"):
                by_group["malicious/ALL_WITH_CODE"].append(r)
        stats = {"_not_run": sum(1 for r in rows if r.get(key) is None)} if any(r.get(key) is None for r in rows) else {}
        for g, rs in sorted(by_group.items()):
            k, n = sum(r[key] for r in rs), len(rs)
            entry = {"flagged": k, "n": n, "rate": round(k / n, 3), "ci95": wilson(k, n),
                     "meaning": "detection rate (recall)" if g.startswith("malicious") else "false-alarm rate"}
            if g.startswith("malicious"):
                clusters: dict[str, bool] = {}
                for r in rs:
                    clusters[r["content_key"]] = clusters.get(r["content_key"], False) or r[key]
                kc, nc = sum(clusters.values()), len(clusters)
                entry["unique_code"] = {"flagged": kc, "n": nc, "rate": round(kc / nc, 3), "ci95": wilson(kc, nc)}
            stats[g] = entry
        out[det] = stats
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--labels", required=True, help="path to labels.csv")
    ap.add_argument("--split", choices=["dev", "test", "fresh", "fresh2"], default="dev")
    ap.add_argument("--final", action="store_true", help="required for --split test (run it once, after tuning)")
    ap.add_argument("--label", choices=["benign", "malicious", "all"], default="all")
    ap.add_argument("--malicious-root", type=Path, help="checkout of DataDog/malicious-software-packages-dataset")
    ap.add_argument("--cache", type=Path, default=ROOT / "datasets" / "cache" / "packages",
                    help="cache of fetched package text (keep out of git)")
    ap.add_argument("--guarddog", action="store_true", help="also run GuardDog (needs guarddog or Docker)")
    ap.add_argument("--osv", action="store_true",
                    help="also look each name@version up in OSV (MAL- = known malware; already-reported samples only)")
    ap.add_argument("--limit", type=int, help="only the first N samples (smoke runs)")
    ap.add_argument("--workers", type=int, default=8, help="parallel registry fetches")
    ap.add_argument("--out", type=Path, help="output file (default: results/evaluation_dataset[.test].local.json)")
    args = ap.parse_args(argv)

    if args.split in ("test", "fresh", "fresh2") and not args.final:
        ap.error(f"the {args.split} split is locked: tune on dev, then run --split {args.split} --final once")
    samples = load_labels(args.labels, split=args.split, label=None if args.label == "all" else args.label)
    samples = samples[: args.limit] if args.limit else samples
    print(f"{len(samples)} samples ({args.split}, {args.label}); fetching package text …", file=sys.stderr)

    loaded, unavailable = [], []
    with httpx.Client(timeout=60, follow_redirects=False) as client:
        def get(s: Sample):
            try:
                return s, load_sample(s, client, args.cache, args.malicious_root), None
            except SampleUnavailable as exc:
                return s, None, str(exc)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for i, (s, pkg, err) in enumerate(pool.map(get, samples), 1):
                (unavailable.append({"id": s.id, "package": f"{s.package}@{s.version}", "group": s.group,
                                     "reason": err}) if err else loaded.append((s, pkg)))
                if i % 25 == 0:
                    print(f"  {i}/{len(samples)}", file=sys.stderr)

    rows = [evaluate(s, pkg, args.guarddog) for s, pkg in loaded]
    detectors = ["static"] + (["guarddog", "combined"] if args.guarddog else [])
    if args.osv:
        mal = osv_known_malware([s for s, _ in loaded])
        for r in rows:
            r["osv_mal_ids"] = mal.get(r["id"], [])
            r["osv_flagged"] = bool(r["osv_mal_ids"])
            r["static+osv_flagged"] = r["static_flagged"] or r["osv_flagged"]
        detectors += ["osv", "static+osv"]
    out = {
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "chainviz-v2 (labels: DataDog malicious-software-packages-dataset, Apache-2.0; benign: npm registry)",
        "split": args.split, "label_filter": args.label,
        "flag_rule": "malicious_indicator finding with severity >= medium",
        "scored": len(rows), "unavailable": len(unavailable),
        "results": summarise(rows, detectors),
        "notes": ["Measurement only; nothing trained or executed.",
                  "Labels are DataDog's and were not independently verified.",
                  "Small samples: read the ci95 ranges, not the decimals."],
        "unavailable_samples": unavailable, "rows": rows,
    }
    dest = args.out or ROOT / "results" / f"evaluation_dataset{'' if args.split == 'dev' else '.' + args.split}.local.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2))

    for det, stats in out["results"].items():
        print(f"\n{det}: flagged / scored  (95% range)")
        for g, e in stats.items():
            if g == "_not_run":
                print(f"  ({e} packages where this detector did not run are excluded; see rows[].guarddog_error)")
                continue
            ci = f"{e['ci95'][0]:.0%}–{e['ci95'][1]:.0%}" if e["ci95"] else "–"
            line = f"  {g:<32} {e['flagged']:>3}/{e['n']:<3} {e['rate']:>6.1%}  ({ci})  {e['meaning']}"
            if "unique_code" in e:
                u = e["unique_code"]
                line += f"  · unique code {u['flagged']}/{u['n']}"
            print(line)
    if unavailable:
        print(f"\n{len(unavailable)} unavailable (excluded from rates):")
        for u in unavailable[:10]:
            print(f"  {u['id']} {u['package']}: {u['reason']}")
    print(f"\nwrote {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
