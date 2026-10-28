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

    def graph_json(self) -> dict:
        """Compact node/edge list for the UI path explorer."""
        return {
            "nodes": [
                {"id": p, "label": self.label(p), "direct": n.direct, "dev": n.dev,
                 "install_script": n.has_install_script}
                for p, n in self.nodes.items()
            ],
            "edges": [
                {"from": p, "to": c} for p, n in self.nodes.items() for c in n.dependencies.values()
            ],
            "roots": self.direct,
        }
