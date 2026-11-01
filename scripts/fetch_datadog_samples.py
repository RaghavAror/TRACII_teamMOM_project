"""Download ONLY the malicious samples listed in labels.csv from DataDog's dataset.

    .venv/bin/python scripts/fetch_datadog_samples.py --labels datasets/chainviz-dataset/labels.csv

The archives contain real malware, encrypted with DataDog's password ("infected").
This script only saves the encrypted zips (to datasets/cache/datadog/, git-ignored); it never
extracts or runs them. tracii.eval.dataset reads them in memory for static analysis.
Source: https://github.com/DataDog/malicious-software-packages-dataset (Apache-2.0).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import quote

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from tracii.eval.dataset import MAX_ZIP, load_labels  # noqa: E402

RAW = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/{ref}/{path}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--labels", required=True)
    ap.add_argument("--dest", type=Path, default=ROOT / "datasets" / "cache" / "datadog")
    ap.add_argument("--ref", default="main", help="git ref of the DataDog repo (pin a commit for reproducibility)")
    args = ap.parse_args()

    samples = [s for s in load_labels(args.labels, label="malicious") if s.datadog_path]
    ok = skipped = 0
    failed = []
    with httpx.Client(timeout=60, follow_redirects=False) as client:
        for s in samples:
            rel = Path(s.datadog_path)
            if rel.is_absolute() or ".." in rel.parts or rel.suffix != ".zip":
                failed.append((s.id, "unexpected path in labels"))
                continue
            target = args.dest / rel
            if target.is_file():
                skipped += 1
                continue
            try:
                resp = client.get(RAW.format(ref=quote(args.ref), path=quote(rel.as_posix())))
                resp.raise_for_status()
                blob = resp.content
                if len(blob) > MAX_ZIP or not blob.startswith(b"PK\x03\x04"):
                    raise ValueError(f"not a zip or too large ({len(blob)} bytes)")
            except (httpx.HTTPError, ValueError) as exc:
                failed.append((s.id, str(exc)[:120]))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
            ok += 1
    print(f"downloaded {ok}, already present {skipped}, failed {len(failed)} of {len(samples)} -> {args.dest}")
    for sid, why in failed:
        print(f"  {sid}: {why}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
