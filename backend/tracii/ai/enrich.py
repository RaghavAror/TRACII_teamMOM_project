"""Public threat-intel and provenance facts the investigation agents may cite.

Every fact becomes an Evidence item with a stable ID, so agent claims built on
it pass the same evidence-ID validation as scanner evidence. Sources (no keys):
- FIRST EPSS      https://api.first.org/data/v1/epss   exploit-probability score per CVE
- CISA KEV        known_exploited_vulnerabilities.json  CVE seen exploited in the wild
- npm registry    /<name>/<version>                     provenance attestation, repo link, maintainers
- OpenSSF Scorecard api.securityscorecards.dev          source-repo hygiene checks
A source that fails is recorded in `limitations`; nothing is guessed.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

from tracii.evidence.schema import Evidence, Finding

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NPM_URL = "https://registry.npmjs.org"
SCORECARD_URL = "https://api.securityscorecards.dev/projects/github.com"
KEV_TTL = 6 * 3600
GITHUB_REPO_RE = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#].*)?$")

def _err(exc: Exception) -> str:
    return str(exc).splitlines()[0][:140] if str(exc) else type(exc).__name__


_kev_cache: dict = {"at": 0.0, "by_cve": {}, "version": ""}
_kev_lock = threading.Lock()


@dataclass
class Enrichment:
    evidence: list[Evidence] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    facts: dict = field(default_factory=dict)   # machine-readable values for deterministic logic


def cves_of(finding: Finding) -> list[str]:
    ids = [finding.rule_or_advisory, *finding.aliases]
    return sorted({i for i in ids if i.startswith("CVE-")})


def _kev(client: httpx.Client) -> tuple[dict, str]:
    with _kev_lock:
        if time.time() - _kev_cache["at"] > KEV_TTL:
            data = client.get(KEV_URL, timeout=30).raise_for_status().json()
            _kev_cache.update(at=time.time(), version=data.get("catalogVersion", ""),
                              by_cve={v["cveID"]: v for v in data.get("vulnerabilities", [])})
        return _kev_cache["by_cve"], _kev_cache["version"]


def threat_intel(finding: Finding, client: httpx.Client) -> Enrichment:
    out = Enrichment()
    cves = cves_of(finding)
    out.facts.update(cves=cves, in_kev=False, epss={})
    if not cves:
        out.limitations.append("No CVE alias on this advisory: EPSS and CISA KEV are keyed by CVE, so neither applies.")
        return out
    try:
        rows = client.get(EPSS_URL, params={"cve": ",".join(cves)}, timeout=15).raise_for_status().json().get("data", [])
        for r in rows:
            score, pct = float(r["epss"]), float(r["percentile"])
            out.facts["epss"][r["cve"]] = score
            out.evidence.append(Evidence(
                id=f"{finding.id}-x-epss-{r['cve']}", kind="threat_intel",
                summary=f"FIRST EPSS {r['cve']}: {score:.3f} probability of exploitation activity in the next 30 days "
                        f"(percentile {pct:.2f}, scored {r.get('date', '?')})",
                url=f"https://api.first.org/data/v1/epss?cve={r['cve']}"))
        missing = set(cves) - {r["cve"] for r in rows}
        if missing:
            out.limitations.append(f"EPSS has no score for {', '.join(sorted(missing))}.")
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        out.limitations.append(f"EPSS lookup failed: {_err(exc)}")
    try:
        kev, version = _kev(client)
        for cve in cves:
            entry = kev.get(cve)
            if entry:
                out.facts["in_kev"] = True
                out.evidence.append(Evidence(
                    id=f"{finding.id}-x-kev-{cve}", kind="threat_intel",
                    summary=f"CISA KEV lists {cve} as exploited in the wild (added {entry.get('dateAdded')}; "
                            f"ransomware use: {entry.get('knownRansomwareCampaignUse', 'Unknown')})",
                    url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))
        if not out.facts["in_kev"]:
            out.evidence.append(Evidence(
                id=f"{finding.id}-x-kev", kind="threat_intel",
                summary=f"CISA KEV (catalog {version}) does not list {', '.join(cves)}: no confirmed in-the-wild "
                        "exploitation recorded there. Absence is not proof of no exploitation.",
                url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        out.limitations.append(f"CISA KEV lookup failed: {_err(exc)}")
    return out


def provenance(finding: Finding, client: httpx.Client) -> Enrichment:
    """npm provenance (SLSA attestation), declared repo and maintainers, plus Scorecard for that repo."""
    out = Enrichment()
    out.facts.update(provenance=None, repo=None, scorecard=None, maintainers=None)
    try:
        meta = client.get(f"{NPM_URL}/{quote(finding.package, safe='@')}/{quote(finding.version)}",
                          timeout=15).raise_for_status().json()
    except (httpx.HTTPError, ValueError) as exc:
        out.limitations.append(f"npm registry metadata unavailable (version may be unpublished): {_err(exc)}")
        return out
    att = (meta.get("dist") or {}).get("attestations")
    pred = ((att or {}).get("provenance") or {}).get("predicateType")
    out.facts["provenance"] = bool(att)
    out.evidence.append(Evidence(
        id=f"{finding.id}-x-prov", kind="metadata",
        summary=(f"npm lists a provenance attestation for {finding.package}@{finding.version} ({pred})"
                 if att else f"No npm provenance attestation for {finding.package}@{finding.version}: the registry "
                             "cannot link this tarball to a source commit and CI build"),
        url=(att or {}).get("url")))
    maintainers = meta.get("maintainers") or []
    out.facts["maintainers"] = len(maintainers)
    publisher = (meta.get("_npmUser") or {}).get("name")
    out.evidence.append(Evidence(
        id=f"{finding.id}-x-maint", kind="metadata",
        summary=f"{len(maintainers)} npm maintainer(s) on this version" + (f"; published by {publisher}" if publisher else "")))
    repo = meta.get("repository")
    repo_url = repo.get("url") if isinstance(repo, dict) else repo if isinstance(repo, str) else None
    m = GITHUB_REPO_RE.search(repo_url or "")
    if not m:
        out.evidence.append(Evidence(id=f"{finding.id}-x-repo", kind="metadata",
                                     summary=f"Declared source repository: {repo_url or 'none'} (not a GitHub URL, so no Scorecard)"))
        return out
    owner, name = m.group(1), m.group(2)
    out.facts["repo"] = f"{owner}/{name}"
    out.evidence.append(Evidence(id=f"{finding.id}-x-repo", kind="metadata",
                                 summary=f"Declared source repository github.com/{owner}/{name} (self-declared in package.json, not verified)",
                                 url=f"https://github.com/{owner}/{name}"))
    try:
        sc = client.get(f"{SCORECARD_URL}/{owner}/{name}", timeout=15).raise_for_status().json()
        weak = sorted((c for c in sc.get("checks", []) if 0 <= (c.get("score") if c.get("score") is not None else -1) <= 3),
                      key=lambda c: c["score"])
        out.facts["scorecard"] = sc.get("score")
        out.evidence.append(Evidence(
            id=f"{finding.id}-x-sc", kind="metadata",
            summary=f"OpenSSF Scorecard {sc.get('score')}/10 for github.com/{owner}/{name} ({sc.get('date', '')[:10]}); "
                    "weak checks: " + (", ".join(f"{c['name']}={c['score']}" for c in weak[:6]) or "none"),
            url=f"https://scorecard.dev/viewer/?uri=github.com/{owner}/{name}"))
    except (httpx.HTTPError, ValueError) as exc:
        out.limitations.append(f"OpenSSF Scorecard unavailable for {owner}/{name}: {_err(exc)}")
    return out
