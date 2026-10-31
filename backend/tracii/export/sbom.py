"""CycloneDX 1.5 JSON SBOM from the lockfile inventory.

- One component per unique name@version (npm may install the same version at
  several paths; all paths are listed as `cdx:npm:package:path` properties).
- bom-ref is the package URL (purl); scoped names are split into group + name.
- Lockfile `integrity` (SRI, e.g. sha512-<base64>) becomes a hex hash.
- devDependencies get scope "excluded" (not shipped) plus the CycloneDX npm
  taxonomy property `cdx:npm:package:development`.
- The `dependencies` graph follows npm's resolved nested paths.
- Only known vulnerabilities (OSV) go into `vulnerabilities`. Malicious-behaviour
  indicators are detector signals, not advisories, so they are not mixed in.
"""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from urllib.parse import quote

from tracii import __version__
from tracii.evidence.schema import Category, Finding, PackageNode, ScanResult

_SRI_ALG = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}
_RATING = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
           "unknown": "unknown"}


def purl(name: str, version: str) -> str:
    if name.startswith("@") and "/" in name:
        scope, short = name.split("/", 1)
        return f"pkg:npm/{quote(scope, safe='')}/{quote(short, safe='')}@{quote(version, safe='')}"
    return f"pkg:npm/{quote(name, safe='')}@{quote(version, safe='')}"


def sri_hashes(integrity: str | None) -> list[dict]:
    out = []
    for token in (integrity or "").split():
        alg, _, b64 = token.partition("-")
        if alg not in _SRI_ALG or not b64:
            continue
        try:
            out.append({"alg": _SRI_ALG[alg], "content": base64.b64decode(b64, validate=True).hex()})
        except (binascii.Error, ValueError):
            continue
    return out


def _component(nodes: list[PackageNode]) -> dict:
    n = nodes[0]
    group, short = (n.name.split("/", 1) if n.name.startswith("@") and "/" in n.name else (None, n.name))
    dev = all(x.dev for x in nodes)
    comp: dict = {"type": "library", "bom-ref": purl(n.name, n.version), "name": short, "version": n.version,
                  "purl": purl(n.name, n.version),
                  "scope": "excluded" if dev else ("optional" if all(x.optional for x in nodes) else "required")}
    if group:
        comp["group"] = group
    if hashes := sri_hashes(next((x.integrity for x in nodes if x.integrity), None)):
        comp["hashes"] = hashes
    if resolved := next((x.resolved for x in nodes if x.resolved), None):
        comp["externalReferences"] = [{"type": "distribution", "url": resolved}]
    props = [{"name": "cdx:npm:package:path", "value": x.path} for x in nodes]
    if dev:
        props.append({"name": "cdx:npm:package:development", "value": "true"})
    if any(x.has_install_script for x in nodes):
        props.append({"name": "tracii:hasInstallScript", "value": "true"})
    if any(x.direct for x in nodes):
        props.append({"name": "tracii:direct", "value": "true"})
    comp["properties"] = props
    return comp


def _vulnerability(f: Finding) -> dict:
    url = next((e.url for e in f.evidence if e.url), None)
    v: dict = {"bom-ref": f"vuln-{f.id}", "id": f.rule_or_advisory,
               "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{quote(f.rule_or_advisory)}"},
               "ratings": [{"severity": _RATING[f.severity.value], "method": "other",
                            "source": {"name": f.source}}],
               "description": f.title, "affects": [{"ref": purl(f.package, f.version)}]}
    if f.aliases:
        v["references"] = [{"id": a, "source": {"name": "alias"}} for a in f.aliases]
    if f.fixed_versions:
        v["recommendation"] = "Upgrade to " + ", ".join(f.fixed_versions[:5])
    if url:
        v["advisories"] = [{"url": url}]
    return v


def to_cyclonedx(result: ScanResult, package_json: str = "", include_vulnerabilities: bool = True) -> dict:
    inv = result.inventory
    try:
        app_version = str(json.loads(package_json).get("version") or "") if package_json else ""
    except (json.JSONDecodeError, AttributeError):
        app_version = ""

    groups: dict[str, list[PackageNode]] = {}
    ref_of_path: dict[str, str] = {}
    for n in inv.packages:
        ref = purl(n.name, n.version)
        groups.setdefault(ref, []).append(n)
        ref_of_path[n.path] = ref

    root_ref = "tracii:app"
    root: dict = {"type": "application", "bom-ref": root_ref, "name": inv.project_name}
    if app_version:
        root["version"] = app_version
    if result.source.commit_sha:
        root["externalReferences"] = [{"type": "vcs", "url": f"https://github.com/{result.source.label}",
                                       "comment": f"commit {result.source.commit_sha}"}]

    depends: dict[str, set[str]] = {ref: set() for ref in groups}
    for n in inv.packages:
        depends[ref_of_path[n.path]].update(ref_of_path[t] for t in n.dependencies.values() if t in ref_of_path)
    direct = sorted({ref_of_path[n.path] for n in inv.packages if n.direct})

    bom: dict = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": result.created_at,
                     "tools": {"components": [{"type": "application", "name": "tracii", "version": __version__}]},
                     "component": root,
                     "properties": [{"name": "tracii:lockfileVersion", "value": str(inv.lockfile_version)},
                                    *({"name": "tracii:warning", "value": w} for w in inv.warnings)]},
        "components": [_component(nodes) for nodes in groups.values()],
        "dependencies": [{"ref": root_ref, "dependsOn": direct},
                         *({"ref": ref, "dependsOn": sorted(deps - {ref})} for ref, deps in depends.items())],
    }
    if include_vulnerabilities:
        vulns = [_vulnerability(f) for f in result.findings if f.category is Category.VULNERABILITY]
        if vulns:
            bom["vulnerabilities"] = vulns
    return bom
