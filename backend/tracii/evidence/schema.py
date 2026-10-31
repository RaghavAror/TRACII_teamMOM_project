"""The one finding format every detector, the AI layer and the UI agree on.

Rules encoded here:
- `category` keeps known vulnerabilities, malicious-behaviour indicators and
  repository posture strictly apart. Nothing merges them into one score.
- Every finding carries its own evidence items with stable IDs. AI output may
  only reference these IDs (see tracii.ai.grounding).
- `limitations` says what the check could NOT see. An empty finding list is
  "no issue detected by these checks", never "safe".
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Category(str, Enum):
    VULNERABILITY = "known_vulnerability"   # OSV / advisory data
    MALICIOUS_INDICATOR = "malicious_indicator"  # GuardDog / Tracii static rules
    POSTURE = "repository_posture"          # Scorecard-style hygiene signals (never malware evidence)
    VERSION_DIFF = "version_diff"           # risky change between two releases


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    HIGH = "high"      # exact advisory match on exact installed version
    MEDIUM = "medium"  # correlated behaviour chain / scanner rule with code location
    LOW = "low"        # single capability signal, often benign


class RemediationStatus(str, Enum):
    NONE = "none"
    PROPOSED = "proposed"
    VERIFIED_FIXED = "verified_fixed"   # a real rescan no longer reports it
    STILL_PRESENT = "still_present"     # a real rescan still reports it
    UNVERIFIED = "unverified"           # proposed, but no rescan could run


class Evidence(BaseModel):
    id: str
    kind: Literal["advisory", "code", "metadata", "install_script", "lockfile", "diff", "scanner_output", "threat_intel"]
    summary: str
    file: str | None = None
    line: int | None = None
    snippet: str | None = None   # untrusted package text; displayed and sent to AI as data only
    url: str | None = None


class DependencyPath(BaseModel):
    nodes: list[str]          # ["<app>", "express@4.17.1", "qs@6.7.0"]
    direct_dependency: str    # which declared dependency brings it in
    dev_only: bool = False


class Finding(BaseModel):
    id: str
    category: Category
    source: str                     # "osv-scanner", "osv-api", "guarddog", "tracii-static", ...
    rule_or_advisory: str           # GHSA-..., CVE-..., or a rule id
    title: str
    package: str
    version: str
    severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[Evidence] = Field(default_factory=list)
    paths: list[DependencyPath] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    remediation_status: RemediationStatus = RemediationStatus.NONE

    @property
    def key(self) -> str:
        """Identity used for dedupe and rescan comparison (independent of scan run)."""
        return f"{self.category.value}|{self.package}|{self.rule_or_advisory}"


def make_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


class CheckRun(BaseModel):
    """What was actually checked. Shown in the UI so absence of findings is honest."""
    name: str
    status: Literal["ran", "skipped", "failed", "not_configured"]
    detail: str = ""
    packages_checked: int = 0


class PackageNode(BaseModel):
    name: str
    version: str
    path: str                 # lockfile key, e.g. node_modules/a/node_modules/b
    direct: bool
    dev: bool = False
    optional: bool = False
    has_install_script: bool = False
    resolved: str | None = None
    integrity: str | None = None
    dependencies: dict[str, str] = Field(default_factory=dict)  # name -> lockfile path it resolves to


class Inventory(BaseModel):
    project_name: str
    lockfile_version: int
    packages: list[PackageNode]
    declared: dict[str, str]          # direct deps from package.json name -> spec
    declared_dev: dict[str, str]
    warnings: list[str] = Field(default_factory=list)


class ScanSource(BaseModel):
    kind: Literal["github", "upload", "fixture", "local"]
    label: str
    commit_sha: str | None = None
    ref: str | None = None
    subdir: str = ""


class ScanResult(BaseModel):
    scan_id: str
    source: ScanSource
    inventory: Inventory
    findings: list[Finding]
    checks: list[CheckRun]
    created_at: str
    parent_scan_id: str | None = None   # set when this is a verification rescan

    def summary(self) -> dict:
        counts: dict[str, dict[str, int]] = {}
        for f in self.findings:
            bucket = counts.setdefault(f.category.value, {})
            bucket[f.severity.value] = bucket.get(f.severity.value, 0) + 1
        return {
            "by_category": counts,  # kept separate on purpose: no merged "risk score"
            "packages": len(self.inventory.packages),
            "direct": sum(1 for p in self.inventory.packages if p.direct),
            "with_install_scripts": sum(1 for p in self.inventory.packages if p.has_install_script),
        }
