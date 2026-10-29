"""Attack replays: four real npm incidents, replayed against the user's own dependency graph.

Scenario facts live in scenarios.json, one source URL per step (OSV advisories, npm
registry publish times, the public disclosure issues). The replay never claims the
user was attacked:
- in_project: the scanned project depends on the incident's package. Says whether the
  installed version is one of the malicious ones and which of the user's packages sit
  above it.
- simulated: the project does not use that package. The same pattern is applied to
  the user's most depended-on package, to show the blast radius. Labelled as hypothetical.
"""

from __future__ import annotations

import json
from pathlib import Path

from tracii.evidence.schema import Inventory
from tracii.impact.paths import APP, DependencyGraph

SCENARIOS: list[dict] = json.loads((Path(__file__).parent / "scenarios.json").read_text())
_BY_ID = {s["id"]: s for s in SCENARIOS}


def get(scenario_id: str) -> dict | None:
    return _BY_ID.get(scenario_id)


def _blast(graph: DependencyGraph, path: str) -> dict:
    waves = graph.dependent_waves(path)
    above = {p for w in waves for p in w if p != APP}
    direct = sorted({graph.nodes[p].name for p in above | {path} if graph.nodes[p].direct})
    paths = graph.paths_to(path)
    return {"waves": waves, "affected_packages": len(above), "affected_direct": direct,
            "reaches_app": any(APP in w for w in waves),
            "dev_only": bool(paths) and all(p.dev_only for p in paths),
            "paths": [p.model_dump() for p in paths[:5]]}


def replay(scenario: dict, inventory: Inventory) -> dict:
    graph = DependencyGraph(inventory)
    target = scenario["target"]["package"]
    bad = set(scenario["target"]["bad_versions"])
    hits = sorted(p for p, n in graph.nodes.items() if n.name == target)
    base = {"scenario": scenario, "injected": scenario.get("injected")}
    if hits:
        targets = []
        for p in hits:
            n = graph.nodes[p]
            targets.append({"id": p, "label": graph.label(p), "installed_version": n.version,
                            "installed_is_malicious": n.version in bad, **_blast(graph, p)})
        exposed = [t for t in targets if t["installed_is_malicious"]]
        note = (f"Your lockfile installs a malicious version of {target} ({', '.join(t['label'] for t in exposed)}). "
                f"{scenario['target']['if_installed']} Move to {scenario['target']['safe_advice']}."
                if exposed else
                f"Your project uses {target} but not one of the malicious versions "
                f"({', '.join(sorted(bad))}). The replay shows what would have been exposed.")
        return {**base, "mode": "in_project", "targets": targets, "note": note}

    candidates = [p for p in graph.nodes if not graph.nodes[p].dev]
    if not candidates:
        candidates = list(graph.nodes)
    if not candidates:
        return {**base, "mode": "simulated", "targets": [], "note": "The lockfile has no packages to simulate on."}
    rev_counts = {p: sum(len(w) for w in graph.dependent_waves(p)) for p in candidates}
    pick = max(candidates, key=lambda p: (rev_counts[p], not graph.nodes[p].direct, p))
    t = {"id": pick, "label": graph.label(pick), "installed_version": graph.nodes[pick].version,
         "installed_is_malicious": False, **_blast(graph, pick)}
    return {**base, "mode": "simulated", "targets": [t],
            "note": f"SIMULATION. Your project does not depend on {target}. This replays the same attack pattern on "
                    f"{t['label']}, the package the most other packages in your project depend on, to show the "
                    "blast radius if it were compromised the same way. Nothing here is a finding."}
