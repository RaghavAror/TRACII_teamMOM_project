"""Build a fresh, never-inspected test set in the labels.csv format (selection only; no detector runs).

    .venv/bin/python scripts/build_fresh_testset.py \\
        --existing datasets/chainviz-dataset/labels.csv \\
        --dd-paths datasets/cache/dd-npm-paths.txt --dd-manifest datasets/cache/dd-manifest.json \\
        --out datasets/fresh/labels.csv

Malicious: DataDog npm samples (from a file listing, `git ls-tree` of a blobless clone, so no
sample is downloaded here) dated >= --since, excluding every package already in --existing;
one version per package, at most --per-batch per (subtype, publication day) so one campaign
cannot dominate; seeded random choice.
Benign: npm registry search results (metadata only), excluding --existing and every name in
DataDog's manifest: popular latest, popular older (2023-2024) releases, packages with install
scripts, and obscure packages published in the last 12 months.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import httpx

COLS = ["id", "label", "subtype", "package", "version", "discovery_date", "source", "split", "install_hooks",
        "signals", "n_files", "total_bytes", "ref"]
HOOKS = ("preinstall", "install", "postinstall")
POPULAR_Q = ["keywords:cli", "keywords:util", "keywords:react", "keywords:http", "keywords:parser", "keywords:test",
             "keywords:logger", "keywords:date", "keywords:string", "keywords:stream", "keywords:config", "keywords:color"]
HOOK_Q = ["keywords:native", "keywords:binding", "keywords:napi", "node-gyp", "prebuild", "keywords:addon",
          "keywords:binary", "keywords:sqlite", "keywords:image"]
OBSCURE_Q = ["toolkit", "helper", "plugin", "sdk", "wrapper", "starter", "utils", "client", "adapter", "bot"]


def dd_rows(paths: Path) -> list[dict]:
    out = []
    for p in paths.read_text().split():
        m = re.match(r"samples/npm/(malicious_intent|compromised_lib)/([^/]+)/([^/]+)/(\d{4}-\d{2}-\d{2})-.*\.zip$", p)
        if m:
            sub, dirname, ver, day = m.groups()
            # DataDog writes scoped names as "@scope@name"
            name = re.sub(r"^(@[^@]+)@", r"\1/", dirname) if dirname.startswith("@") else dirname
            out.append({"subtype": sub, "package": name, "version": ver, "day": day, "path": p})
    return out


def pick_malicious(rows, exclude: set[str], since: str, n_intent: int, n_comp: int, per_batch: int, rng) -> list[dict]:
    rng.shuffle(rows)
    seen_pkg, batch, chosen = set(), {}, {"malicious_intent": [], "compromised_lib": []}
    want = {"malicious_intent": n_intent, "compromised_lib": n_comp}
    for r in rows:
        key = (r["subtype"], r["day"])
        if (r["day"] < since or r["package"] in exclude or r["package"] in seen_pkg
                or batch.get(key, 0) >= per_batch or len(chosen[r["subtype"]]) >= want[r["subtype"]]):
            continue
        seen_pkg.add(r["package"])
        batch[key] = batch.get(key, 0) + 1
        chosen[r["subtype"]].append(r)
    return chosen["malicious_intent"] + chosen["compromised_lib"]


def _get(client, url: str) -> httpx.Response:
    """GET with polite retries on 429/5xx, honouring Retry-After (the search API rate-limits)."""
    for attempt in range(6):
        r = client.get(url)
        if r.status_code not in (429, 500, 502, 503, 504):
            return r
        time.sleep(min(float(r.headers.get("retry-after") or 0) or 5 * 2 ** attempt, 60))
    r.raise_for_status()
    return r


def search(client, q: str, size: int = 250) -> list[dict]:
    r = _get(client, f"https://registry.npmjs.org/-/v1/search?text={quote(q)}&size={size}")
    r.raise_for_status()
    time.sleep(1)   # stay well under the search rate limit
    return r.json().get("objects", [])


def packument(client, name: str) -> dict | None:
    r = _get(client, f"https://registry.npmjs.org/{quote(name, safe='@')}")
    return r.json() if r.status_code == 200 else None


def pick_benign(client, exclude: set[str], rng, n_pop: int, n_old: int, n_hook: int, n_obscure: int) -> list[dict]:
    chosen, used = [], set(exclude)

    def take(name, version, subtype, published):
        used.add(name)
        chosen.append({"subtype": subtype, "package": name, "version": version, "day": published[:10]})

    # popular (latest) and popular older releases: highest search scores for generic keywords
    pool = {}
    for q in POPULAR_Q:
        for o in search(client, q):
            p = o["package"]
            pool.setdefault(p["name"], o.get("downloads", {}).get("monthly", 0) or o.get("score", {}).get("final", 0))
    ranked = [n for n, _ in sorted(pool.items(), key=lambda kv: -kv[1]) if n not in used][:300]
    rng.shuffle(ranked)
    for name in ranked:
        if len([c for c in chosen if c["subtype"].startswith("popular")]) >= n_pop + n_old:
            break
        doc = packument(client, name)
        if not doc or "dist-tags" not in doc:
            continue
        times = doc.get("time", {})
        if sum(c["subtype"] == "popular_latest" for c in chosen) < n_pop:
            v = doc["dist-tags"].get("latest")
            if v and v in doc.get("versions", {}):
                take(name, v, "popular_latest", times.get(v, ""))
        elif sum(c["subtype"] == "popular_older" for c in chosen) < n_old:
            older = [v for v, t in times.items() if v in doc.get("versions", {}) and "2023-01-01" <= t < "2025-01-01"
                     and not re.search(r"[-+]", v)]
            if older:
                v = rng.choice(older)
                take(name, v, "popular_older", times[v])

    # packages with install hooks
    cands = list(dict.fromkeys(o["package"]["name"] for q in HOOK_Q for o in search(client, q)))
    rng.shuffle(cands)
    for name in cands:
        if sum(c["subtype"] == "install_hook" for c in chosen) >= n_hook:
            break
        if name in used:
            continue
        doc = packument(client, name)
        v = (doc or {}).get("dist-tags", {}).get("latest")
        meta = (doc or {}).get("versions", {}).get(v or "", {})
        if v and set((meta.get("scripts") or {})) & set(HOOKS):
            take(name, v, "install_hook", doc.get("time", {}).get(v, ""))

    # obscure, published in the last 12 months, low popularity
    cutoff = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
    cands = []
    for q in OBSCURE_Q:
        for o in search(client, q):
            p = o["package"]
            if p.get("date", "") >= cutoff and (o.get("downloads", {}).get("monthly", 0) or 0) < 500:
                cands.append((p["name"], p["version"], p["date"]))
    rng.shuffle(cands)
    for name, v, day in cands:
        if sum(c["subtype"] == "obscure_recent" for c in chosen) >= n_obscure:
            break
        if name not in used:
            take(name, v, "obscure_recent", day)
    return chosen


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--existing", required=True, type=Path, nargs="+", help="labels files whose packages are excluded")
    ap.add_argument("--dd-paths", required=True, type=Path)
    ap.add_argument("--dd-manifest", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--since", default="2025-09-16", help="earliest DataDog publication day (default: test-split start)")
    ap.add_argument("--per-batch", type=int, default=3)
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--split-name", default="fresh", help="value written to the split column")
    ap.add_argument("--id-prefix", default="F", help="sample id prefix")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    existing = {r["package"] for f in args.existing for r in csv.DictReader(open(f))}
    dd_names = set(json.loads(args.dd_manifest.read_text()))
    mal = pick_malicious(dd_rows(args.dd_paths), existing, args.since, 40, 20, args.per_batch, rng)
    with httpx.Client(timeout=60, follow_redirects=False) as client:
        ben = pick_benign(client, existing | dd_names | {m["package"] for m in mal}, rng, 40, 20, 20, 20)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        for i, m in enumerate(mal):
            w.writerow({"id": f"{args.id_prefix}-M{i:03d}", "label": "malicious", "subtype": m["subtype"], "package": m["package"],
                        "version": m["version"], "discovery_date": m["day"], "source": "datadog_malicious_dataset",
                        "split": args.split_name, "ref": f"DataDog/malicious-software-packages-dataset:{m['path']}"})
        for i, b in enumerate(ben):
            w.writerow({"id": f"{args.id_prefix}-B{i:03d}", "label": "benign", "subtype": b["subtype"], "package": b["package"],
                        "version": b["version"], "discovery_date": b["day"], "source": "npm_registry_search",
                        "split": args.split_name, "ref": f"https://registry.npmjs.org/{b['package']}"})
    print(f"{len(mal)} malicious + {len(ben)} benign -> {args.out}  (seed {args.seed}, since {args.since})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
