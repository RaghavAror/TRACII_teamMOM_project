"""Dependency impact ("blast radius" inside the user's project).

For a flagged package we report:
- the shortest path from the app to it,
- every direct dependency that brings it in, each with its own shortest path,
- whether it is reachable only through devDependencies (does not ship to prod).

This is dependency-path reachability only. Whether the app's own code calls the
vulnerable function is NOT analysed; findings say so in `limitations`.
"""

from __future__ import annotations

from collections import deque

from tracii.evidence.schema import DependencyPath, Inventory, PackageNode

APP = "<app>"


class DependencyGraph:
    def __init__(self, inventory: Inventory):
        self.nodes: dict[str, PackageNode] = {n.path: n for n in inventory.packages}
        self.direct = [n.path for n in inventory.packages if n.direct]
        self.declared_dev = set(inventory.declared_dev)

    def label(self, path: str) -> str:
        n = self.nodes[path]
        return f"{n.name}@{n.version}"

    def _bfs_from(self, start: str) -> dict[str, str | None]:
        parents: dict[str, str | None] = {start: None}
        queue = deque([start])
        while queue:
            cur = queue.popleft()
            for child in sorted(self.nodes[cur].dependencies.values()):
                if child not in parents and child in self.nodes:
                    parents[child] = cur
                    queue.append(child)
        return parents

    def paths_to(self, target_path: str) -> list[DependencyPath]:
        """One shortest path per direct dependency that reaches `target_path`."""
        results: list[DependencyPath] = []
        for d in self.direct:
            parents = self._bfs_from(d)
            if target_path not in parents:
                continue
            chain, cur = [], target_path
            while cur is not None:
                chain.append(self.label(cur))
                cur = parents[cur]
            direct_name = self.nodes[d].name
            results.append(
                DependencyPath(
                    nodes=[APP, *reversed(chain)],
                    direct_dependency=direct_name,
                    dev_only=direct_name in self.declared_dev,
                )
            )
        results.sort(key=lambda p: (p.dev_only, len(p.nodes), p.direct_dependency))
        return results

    def paths_for(self, name: str, version: str) -> list[DependencyPath]:
        out: list[DependencyPath] = []
        for path, node in self.nodes.items():
            if node.name == name and node.version == version:
                out.extend(self.paths_to(path))
        return out

    def _reverse(self) -> dict[str, set[str]]:
        rev: dict[str, set[str]] = {p: set() for p in self.nodes}
        for p, n in self.nodes.items():
            for c in n.dependencies.values():
                if c in rev:
                    rev[c].add(p)
        for d in self.direct:
            rev[d].add(APP)
        return rev

    def dependent_waves(self, target_path: str) -> list[list[str]]:
        """Everything that (transitively) depends on target, grouped by distance; ends at APP if reachable."""
        rev, seen, waves = self._reverse(), {target_path}, []
        frontier = [target_path]
        while frontier:
            nxt = sorted({p for cur in frontier for p in rev.get(cur, ()) if p not in seen})
            if not nxt:
                break
            seen.update(nxt)
            waves.append(nxt)
            frontier = [p for p in nxt if p != APP]
        return waves

    def graph_json(self, findings: list | None = None) -> dict:
        """Node/edge list for the 3D view. Findings are summarised per node, categories kept apart."""
        rev = self._reverse()
        flagged: dict[tuple[str, str], dict[str, list]] = {}
        for f in findings or []:
            flagged.setdefault((f.package, f.version), {}).setdefault(f.category.value, []).append(
                {"id": f.id, "severity": f.severity.value, "rule": f.rule_or_advisory})
        reach: dict[str, bool] = {}   # is the node reachable from a production (non-dev) direct dependency?
        for d in self.direct:
            if self.nodes[d].name not in self.declared_dev:
                reach.update(dict.fromkeys(self._bfs_from(d), True))
        nodes = [{"id": APP, "label": APP, "app": True}]
        for p, n in self.nodes.items():
            nodes.append({"id": p, "label": self.label(p), "name": n.name, "version": n.version,
                          "direct": n.direct, "dev_only": not reach.get(p, False),
                          "install_script": n.has_install_script, "dependents": len(rev[p] - {APP}),
                          "findings": flagged.get((n.name, n.version), {})})
        edges = [{"source": APP, "target": d} for d in self.direct]
        edges += [{"source": p, "target": c} for p, n in self.nodes.items() for c in n.dependencies.values()
                  if c in self.nodes]
        return {"nodes": nodes, "edges": edges, "roots": self.direct, "app": APP}
