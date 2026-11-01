"""Command-line entry point for CI.

    python -m tracii scan --dir . --fail-on high --sarif tracii.sarif --sbom sbom.cdx.json
    python -m tracii sbom --dir . -o sbom.cdx.json          # inventory only, no network

Exit codes (scan, enforce mode): 0 pass · 1 blocking findings · 2 incomplete scan or bad input.
Observe mode always exits 0 unless the input itself is invalid.
Inside GitHub Actions the markdown report is appended to $GITHUB_STEP_SUMMARY and
outcome/blocking/findings are written to $GITHUB_OUTPUT.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

from tracii import __version__, gate
from tracii.evidence.schema import Category, ScanResult, ScanSource
from tracii.export.sarif import to_sarif
from tracii.export.sbom import to_cyclonedx
from tracii.intake import github
from tracii.inventory.lockfile import InventoryError, build_inventory
from tracii.pipeline import ScanRecord, run_scan

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "projects"
ALL_CATEGORIES = [c.value for c in Category]


class InputError(Exception):
    pass


def _rel_uri(path: Path) -> str:
    base = Path(os.environ.get("GITHUB_WORKSPACE") or os.getcwd()).resolve()
    try:
        return path.resolve().relative_to(base).as_posix()
    except ValueError:
        return path.name


def load_input(args) -> tuple[ScanSource, bytes, bytes, str]:
    """-> (source, package.json, package-lock.json, lockfile URI for SARIF)."""
    if args.github:
        with httpx.Client(timeout=30) as client:
            try:
                ref, branch, sha, pkg, lock = github.fetch_manifest_files(args.github, args.subdir, client)
            except (github.IntakeError, httpx.HTTPError) as exc:
                raise InputError(f"GitHub fetch failed: {exc}") from exc
        uri = f"{args.subdir.strip('/')}/package-lock.json" if args.subdir.strip("/") else "package-lock.json"
        return (ScanSource(kind="github", label=f"{ref.owner}/{ref.repo}", ref=branch, commit_sha=sha,
                           subdir=args.subdir), pkg, lock, uri)
    if args.fixture:
        d = FIXTURES / args.fixture
        if not (d / "package-lock.json").is_file():
            raise InputError(f"unknown fixture '{args.fixture}'")
        pj, lf = d / "package.json", d / "package-lock.json"
        source = ScanSource(kind="fixture", label=args.fixture)
    else:
        d = Path(args.dir)
        pj = Path(args.package_json) if args.package_json else d / "package.json"
        lf = Path(args.lockfile) if args.lockfile else d / "package-lock.json"
        for p in (pj, lf):
            if not p.is_file():
                raise InputError(f"{p} not found" + (" (run `npm install --package-lock-only` to create it)"
                                                     if p.name == "package-lock.json" else ""))
        source = ScanSource(kind="local", label=str(pj.parent.resolve().name or pj.parent))
        if sha := os.environ.get("GITHUB_SHA"):
            source.commit_sha, source.ref = sha, os.environ.get("GITHUB_REF_NAME")
            source.label = os.environ.get("GITHUB_REPOSITORY", source.label)
    return source, pj.read_bytes(), lf.read_bytes(), args.lockfile_uri or _rel_uri(lf)


def _write(path: str, data: dict | str) -> None:
    text = data if isinstance(data, str) else json.dumps(data, indent=2)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text)
    print(f"wrote {path}", file=sys.stderr)


def _github_output(**values) -> None:
    if out := os.environ.get("GITHUB_OUTPUT"):
        with open(out, "a") as fh:
            fh.writelines(f"{k}={v}\n" for k, v in values.items())


def cmd_scan(args) -> int:
    source, pkg, lock, uri = load_input(args)
    try:
        build_inventory(pkg, lock)
    except InventoryError as exc:
        raise InputError(str(exc)) from exc
    rec = ScanRecord(scan_id=uuid.uuid4().hex[:12])
    try:
        result = run_scan(rec, source, pkg, lock, deep_limit=args.deep_scan_limit)
    except Exception as exc:
        raise InputError(f"scan failed: {str(exc)[:300]}") from exc
    finally:
        for line in rec.progress:
            print(f"· {line}", file=sys.stderr)

    policy = gate.GatePolicy(fail_on=args.fail_on, mode=args.mode, categories=tuple(args.categories),
                             fail_on_unknown=args.fail_on_unknown, allow_incomplete=args.allow_incomplete,
                             include_dev=not args.ignore_dev)
    verdict = gate.evaluate(result, policy)
    summary = gate.markdown_summary(result, verdict)

    if args.sarif:
        _write(args.sarif, to_sarif(result, lock.decode(errors="replace"), uri))
    if args.sbom:
        _write(args.sbom, to_cyclonedx(result, pkg.decode(errors="replace")))
    if args.json:
        _write(args.json, {"result": result.model_dump(mode="json"), "summary": result.summary(),
                           "gate": {"outcome": verdict.outcome, "would_fail": verdict.would_fail,
                                    "blocking": [f.id for f in verdict.blocking],
                                    "failed_checks": verdict.failed_checks}})
    if args.summary:
        _write(args.summary, summary)
    if step := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(step, "a") as fh:
            fh.write(summary)
    _github_output(outcome=verdict.outcome, blocking=len(verdict.blocking), findings=len(result.findings),
                   **({"sarif": args.sarif} if args.sarif else {}), **({"sbom": args.sbom} if args.sbom else {}))

    print(summary)
    if args.mode == "observe" and verdict.would_fail:
        print("observe mode: the gate would have failed; exiting 0", file=sys.stderr)
    return verdict.exit_code


def cmd_sbom(args) -> int:
    source, pkg, lock, _ = load_input(args)
    try:
        inv = build_inventory(pkg, lock)
    except InventoryError as exc:
        raise InputError(str(exc)) from exc
    result = ScanResult(scan_id=uuid.uuid4().hex[:12], source=source, inventory=inv, findings=[], checks=[],
                        created_at=datetime.now(timezone.utc).isoformat())
    _write(args.output, to_cyclonedx(result, pkg.decode(errors="replace"), include_vulnerabilities=False))
    _github_output(sbom=args.output)
    return 0


def _add_input(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("input (default: package.json + package-lock.json in --dir)")
    g.add_argument("--dir", default=".", help="project directory (default: .)")
    g.add_argument("--package-json", help="explicit path to package.json")
    g.add_argument("--lockfile", help="explicit path to package-lock.json")
    g.add_argument("--github", metavar="URL", help="scan a public GitHub repo instead of local files")
    g.add_argument("--subdir", default="", help="sub-directory inside the GitHub repo")
    g.add_argument("--fixture", help="scan a bundled demo project (e.g. vulnerable-demo)")
    g.add_argument("--lockfile-uri", help="repo-relative lockfile path used in SARIF locations")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="tracii", description="npm supply-chain scanner (CI mode)")
    ap.add_argument("--version", action="version", version=f"tracii {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan, gate, and export SARIF / SBOM / JSON")
    _add_input(s)
    s.add_argument("--fail-on", choices=gate.THRESHOLDS, default="high",
                   help="lowest severity that fails the gate (default: high)")
    s.add_argument("--mode", choices=["enforce", "observe"], default="enforce",
                   help="observe: report what would fail but exit 0")
    s.add_argument("--categories", nargs="+", choices=ALL_CATEGORIES, default=list(gate.GatePolicy().categories),
                   help="finding categories the gate considers")
    s.add_argument("--fail-on-unknown", action="store_true", help="gate findings with unknown severity too")
    s.add_argument("--ignore-dev", action="store_true", help="ignore findings reached only via devDependencies")
    s.add_argument("--allow-incomplete", action="store_true",
                   help="do not fail when a required check (inventory, osv) could not run")
    s.add_argument("--deep-scan-limit", type=int, default=None, help="tarballs to analyse for malware signals")
    s.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0")
    s.add_argument("--sbom", metavar="FILE", help="write CycloneDX 1.5 JSON SBOM (with known vulnerabilities)")
    s.add_argument("--json", metavar="FILE", help="write the full scan result + gate decision")
    s.add_argument("--summary", metavar="FILE", help="write the markdown report")
    s.set_defaults(func=cmd_scan)

    b = sub.add_parser("sbom", help="write a CycloneDX SBOM from the lockfile only (offline)")
    _add_input(b)
    b.add_argument("-o", "--output", default="sbom.cdx.json", help="output file (default: sbom.cdx.json)")
    b.set_defaults(func=cmd_sbom)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except InputError as exc:
        print(f"tracii: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
