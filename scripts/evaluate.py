"""Measure detector results on labelled fixtures. Prints only what was measured.

Usage (from repo root):  .venv/bin/python scripts/evaluate.py [--guarddog]
Writes results/evaluation.json. A package counts as "flagged" by a detector if it
produces any malicious_indicator finding with severity >= medium.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from tracii.detect import guarddog, static_rules  # noqa: E402
from tracii.intake.npm_registry import load_local_package  # noqa: E402

FLAG = {"critical", "high", "medium"}


def metrics(rows: list[dict], key: str) -> dict:
    tp = sum(r[key] and r["label"] == "malicious" for r in rows)
    fp = sum(r[key] and r["label"] == "benign" for r in rows)
    fn = sum(not r[key] and r["label"] == "malicious" for r in rows)
    tn = sum(not r[key] and r["label"] == "benign" for r in rows)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--guarddog", action="store_true", help="also run GuardDog (needs guarddog or Docker)")
    args = ap.parse_args()
    labels = json.loads((ROOT / "fixtures/packages/labels.json").read_text())
    rows = []
    for name, label in labels.items():
        if name.startswith("_"):
            continue
        pkg = load_local_package(str(ROOT / "fixtures/packages" / name))
        t = time.perf_counter()
        st = static_rules.analyze_package(pkg)
        row = {"package": name, "label": label, "static_ms": round((time.perf_counter() - t) * 1000, 1),
               "static_flagged": any(f.severity.value in FLAG for f in st),
               "static_rules": sorted({f.rule_or_advisory for f in st})}
        if args.guarddog:
            t = time.perf_counter()
            gd = guarddog.to_findings(guarddog.run_guarddog(pkg), pkg)
            row |= {"guarddog_ms": round((time.perf_counter() - t) * 1000, 1),
                    "guarddog_flagged": any(f.severity.value in FLAG for f in gd),
                    "guarddog_rules": sorted({f.rule_or_advisory for f in gd})}
        rows.append(row)
    out = {"measured_at": datetime.now(timezone.utc).isoformat(), "n": len(rows), "note": labels["_note"],
           "tracii_static": metrics(rows, "static_flagged"), "rows": rows}
    if args.guarddog:
        out["guarddog"] = metrics(rows, "guarddog_flagged")
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results/evaluation.json").write_text(json.dumps(out, indent=2))
    print(json.dumps({k: v for k, v in out.items() if k != "rows"}, indent=2))
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
