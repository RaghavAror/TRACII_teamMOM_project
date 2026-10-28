import json

import pytest

from tracii.impact.paths import DependencyGraph
from tracii.inventory.lockfile import InventoryError, build_inventory


def test_real_v3_lockfile_direct_transitive_dev(demo_project):
    inv = build_inventory(*demo_project)
    by_path = {p.path: p for p in inv.packages}
    assert inv.lockfile_version == 3
    assert by_path["node_modules/express"].direct and by_path["node_modules/express"].version == "4.17.1"
    assert by_path["node_modules/qs"].direct is False          # transitive via express/body-parser
    assert by_path["node_modules/minimist"].direct            # declared devDependency...
    assert by_path["node_modules/minimist"].dev is False      # ...but prod mkdirp also needs it, so npm ships it


def test_shortest_path_and_dev_only(demo_project):
    inv = build_inventory(*demo_project)
    g = DependencyGraph(inv)
    paths = g.paths_for("minimist", "1.2.5")
    direct = {p.direct_dependency: p for p in paths}
    assert direct["mkdirp"].nodes == ["<app>", "mkdirp@0.5.5", "minimist@1.2.5"]
    assert direct["mkdirp"].dev_only is False
    assert direct["minimist"].dev_only is True
    qs_paths = g.paths_for("qs", "6.7.0")
    assert qs_paths and qs_paths[0].nodes[1] == "express@4.17.1"


def test_nested_node_modules_resolution():
    pkg = {"name": "app", "dependencies": {"a": "1", "b": "1"}}
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"a": "1", "b": "1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "^2"}},
        "node_modules/a/node_modules/c": {"version": "2.0.0"},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"c": "^1"}},
        "node_modules/c": {"version": "1.0.0", "hasInstallScript": True},
    }}
    inv = build_inventory(json.dumps(pkg), json.dumps(lock))
    by_path = {p.path: p for p in inv.packages}
    assert by_path["node_modules/a"].dependencies["c"] == "node_modules/a/node_modules/c"
    assert by_path["node_modules/b"].dependencies["c"] == "node_modules/c"
    assert by_path["node_modules/c"].has_install_script


def test_v1_lockfile_supported_with_warning():
    pkg = {"name": "old", "dependencies": {"x": "1"}}
    lock = {"lockfileVersion": 1, "dependencies": {"x": {"version": "1.0.0", "requires": {"y": "1"},
                                                         "dependencies": {"y": {"version": "1.1.0"}}}}}
    inv = build_inventory(json.dumps(pkg), json.dumps(lock))
    assert {p.path for p in inv.packages} == {"node_modules/x", "node_modules/x/node_modules/y"}
    assert any("hasInstallScript" in w for w in inv.warnings)


@pytest.mark.parametrize("pkg,lock,msg", [
    ("{not json", "{}", "package.json is not valid JSON"),
    ("[]", "{}", "must be a JSON object"),
    ("{}", '{"lockfileVersion": "3"}', "integer lockfileVersion"),
    ("{}", '{"lockfileVersion": 3}', "neither"),
    ("{}", b"\xff\xfe", "not valid JSON"),
])
def test_malformed_inputs_rejected(pkg, lock, msg):
    with pytest.raises(InventoryError, match=msg):
        build_inventory(pkg, lock)


def test_stale_lockfile_warns():
    inv = build_inventory('{"dependencies": {"ghost": "1"}}', '{"lockfileVersion": 3, "packages": {"": {}}}')
    assert any("ghost" in w for w in inv.warnings)
