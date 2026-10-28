import tarfile

import pytest

from tests.conftest import FIXTURES, integrity, make_tarball
from tracii.detect import osv
from tracii.detect.static_rules import analyze_package
from tracii.diff.version_diff import diff_packages
from tracii.evidence.schema import Category
from tracii.evidence.slicing import slices_for_finding
from tracii.intake.npm_registry import (
    IntegrityError, UnsafeArchive, extract_in_memory, load_local_package, verify_integrity,
)
from tracii.inventory.lockfile import build_inventory

PKGS = FIXTURES / "packages"


def rules(findings):
    return {f.rule_or_advisory for f in findings}


def test_osv_matches_exact_versions_only(demo_project, mock_http):
    inv = build_inventory(*demo_project)
    findings, check = osv.scan(inv, demo_project[1], client=mock_http())
    assert check.status == "ran"
    got = {(f.package, f.version, f.rule_or_advisory) for f in findings}
    assert got == {("lodash", "4.17.20", "GHSA-35jh-r3h4-6jhm"), ("minimist", "1.2.5", "GHSA-xvch-5gv4-984h")}
    lodash = next(f for f in findings if f.package == "lodash")
    assert lodash.fixed_versions == ["4.17.21"] and lodash.category == Category.VULNERABILITY
    assert lodash.evidence[0].url.startswith("https://")


def test_osv_failure_is_reported_not_hidden(demo_project):
    import httpx
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    findings, check = osv.scan(build_inventory(*demo_project), b"", client=client)
    assert findings == [] and check.status == "failed"


def test_osv_dedupe_by_alias():
    a = osv.vuln_to_finding({"id": "GHSA-1", "aliases": ["CVE-1"]}, "p", "1.0.0", "osv-api")
    b = osv.vuln_to_finding({"id": "CVE-1", "aliases": ["GHSA-1"]}, "p", "1.0.0", "osv-api")
    assert len(osv.dedupe([a, b])) == 1


def test_malicious_fixture_produces_linked_chain():
    findings = analyze_package(load_local_package(PKGS / "fake-exfil"))
    chain = next(f for f in findings if f.rule_or_advisory == "TRACII-CHAIN-EXFIL")
    assert chain.category == Category.MALICIOUS_INDICATOR
    assert chain.severity.value == "high" and "install time" in chain.title
    steps = [e for e in chain.evidence if e.line]
    assert [e.summary for e in steps] == ["source: env_read", "transform: encode", "sink: network"]
    assert all(e.file == "setup.js" for e in steps)
    assert any("collector.example.invalid" in e.summary for e in chain.evidence)
    assert "TRACII-INSTALL-SCRIPT" in rules(findings)


def test_benign_api_client_is_not_a_chain():
    findings = analyze_package(load_local_package(PKGS / "benign-http-client"))
    assert findings == []


def test_install_time_recon_flagged():
    findings = analyze_package(load_local_package(PKGS / "prompt-injection"))
    assert "TRACII-CHAIN-EXFIL" in rules(findings)  # hostname -> dns at preinstall


def test_obfuscated_eval_flagged():
    findings = analyze_package(load_local_package(PKGS / "obfuscated-loader"))
    assert "TRACII-OBFUSCATED-EVAL" in rules(findings)


def test_slice_contains_only_relevant_code():
    pkg = load_local_package(PKGS / "fake-exfil")
    chain = next(f for f in analyze_package(pkg) if f.rule_or_advisory == "TRACII-CHAIN-EXFIL")
    slices = slices_for_finding(chain, pkg.files)
    assert len(slices) == 1 and "process.env" in slices[0].code and "https.request" in slices[0].code
    assert set(slices[0].evidence_ids) <= {e.id for e in chain.evidence}


def test_version_diff_highlights_new_install_script():
    old = load_local_package(PKGS / "benign-http-client")
    new = load_local_package(PKGS / "fake-exfil")
    new.name = old.name
    report = diff_packages(old, new)
    assert "postinstall" in report["install_scripts_added_or_changed"]
    assert "collector.example.invalid" in report["hosts_added"]
    assert {f["rule_or_advisory"] for f in report["findings"]} >= {"DIFF-INSTALL-SCRIPT", "DIFF-NEW-CAPABILITY"}


# ---- untrusted archive handling ----

def test_integrity_mismatch_rejected():
    blob = make_tarball({"package/index.js": b"1"})
    verify_integrity(blob, integrity(blob))
    with pytest.raises(IntegrityError):
        verify_integrity(blob + b"x", integrity(blob))
    with pytest.raises(IntegrityError):
        verify_integrity(blob, None)


@pytest.mark.parametrize("name", ["../evil.js", "/etc/passwd", "package/../../x.js"])
def test_path_traversal_rejected(name):
    with pytest.raises(UnsafeArchive):
        extract_in_memory(make_tarball({name: b"x"}))


def test_symlink_rejected():
    link = tarfile.TarInfo("package/link")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
    with pytest.raises(UnsafeArchive):
        extract_in_memory(make_tarball({"package/index.js": b"1"}, extra=[link]))


def test_not_a_tarball_rejected():
    with pytest.raises(UnsafeArchive):
        extract_in_memory(b"this is not gzip")
