"""Build an exact dependency inventory from package.json + package-lock.json.

Pure parsing: nothing is installed and no package code is touched. Supports
lockfileVersion 2/3 (`packages` map) and the legacy v1 nested `dependencies`.
"""

from __future__ import annotations

import json
from typing import Any

from tracii.evidence.schema import Inventory, PackageNode

MAX_JSON_BYTES = 20 * 1024 * 1024


class InventoryError(ValueError):
    """Raised for input we refuse to analyse (malformed, wrong shape, too large)."""


def load_json(raw: bytes | str, label: str) -> dict[str, Any]:
    if isinstance(raw, str):
        raw = raw.encode()
    if len(raw) > MAX_JSON_BYTES:
        raise InventoryError(f"{label} is larger than {MAX_JSON_BYTES // (1024 * 1024)} MB")
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InventoryError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InventoryError(f"{label} must be a JSON object")
    return data


def _resolve(from_path: str, dep: str, known: set[str]) -> str | None:
    """npm resolution: nearest node_modules/<dep> walking up from `from_path`."""
    base = from_path
    while True:
        candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if candidate in known:
            return candidate
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx != -1 else ""


def _name_from_path(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]


def _flatten_v1(deps: dict[str, Any], prefix: str, out: dict[str, dict]) -> None:
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        path = f"{prefix}/node_modules/{name}" if prefix else f"node_modules/{name}"
        out[path] = {
            "version": meta.get("version", ""),
            "resolved": meta.get("resolved"),
            "integrity": meta.get("integrity"),
            "dev": bool(meta.get("dev")),
            "optional": bool(meta.get("optional")),
            "dependencies": dict(meta.get("requires") or {}),
        }
        _flatten_v1(meta.get("dependencies") or {}, path, out)


def build_inventory(package_json: bytes | str, lockfile: bytes | str) -> Inventory:
    manifest = load_json(package_json, "package.json")
    lock = load_json(lockfile, "package-lock.json")

    lock_version = lock.get("lockfileVersion")
    if not isinstance(lock_version, int):
        raise InventoryError("package-lock.json has no integer lockfileVersion")

    warnings: list[str] = []
    declared = {k: str(v) for k, v in (manifest.get("dependencies") or {}).items()}
    declared.update({k: str(v) for k, v in (manifest.get("optionalDependencies") or {}).items()})
    declared_dev = {k: str(v) for k, v in (manifest.get("devDependencies") or {}).items()}

    entries: dict[str, dict]
    if lock_version >= 2 and isinstance(lock.get("packages"), dict):
        entries = {}
        for path, meta in lock["packages"].items():
            if path == "" or not isinstance(meta, dict):
                continue
            if not path.startswith("node_modules/") and "/node_modules/" not in path:
                warnings.append(f"workspace entry '{path}' not analysed (workspaces are out of MVP scope)")
                continue
            if meta.get("link"):
                warnings.append(f"linked package '{path}' not analysed")
                continue
            deps = {}
            for section in ("dependencies", "optionalDependencies", "peerDependencies"):
                deps.update(meta.get(section) or {})
            entries[path] = {
                "version": meta.get("version", ""),
                "resolved": meta.get("resolved"),
                "integrity": meta.get("integrity"),
                "dev": bool(meta.get("dev") or meta.get("devOptional")),
                "optional": bool(meta.get("optional")),
                "has_install_script": bool(meta.get("hasInstallScript")),
                "dependencies": deps,
            }
    elif isinstance(lock.get("dependencies"), dict):
        entries = {}
        _flatten_v1(lock["dependencies"], "", entries)
        warnings.append("lockfileVersion 1 does not record install scripts; hasInstallScript is unknown")
    else:
        raise InventoryError("package-lock.json has neither a 'packages' nor a 'dependencies' map")

    known = set(entries)
    direct_names = set(declared) | set(declared_dev)
    nodes: list[PackageNode] = []
    for path, meta in entries.items():
        # Unresolved deps are normally uninstalled optional/peer deps; skip them.
        resolved_deps = {
            dep: target for dep in meta["dependencies"] if (target := _resolve(path, dep, known))
        }
        name = _name_from_path(path)
        nodes.append(
            PackageNode(
                name=name,
                version=str(meta["version"]),
                path=path,
                direct=path == f"node_modules/{name}" and name in direct_names,
                dev=meta["dev"],
                optional=meta["optional"],
                has_install_script=meta.get("has_install_script", False),
                resolved=meta.get("resolved"),
                integrity=meta.get("integrity"),
                dependencies=resolved_deps,
            )
        )

    for name in direct_names:
        if f"node_modules/{name}" not in known:
            warnings.append(f"declared dependency '{name}' is missing from the lockfile (lockfile may be stale)")

    return Inventory(
        project_name=str(manifest.get("name") or "unnamed-project"),
        lockfile_version=lock_version,
        packages=sorted(nodes, key=lambda n: n.path),
        declared=declared,
        declared_dev=declared_dev,
        warnings=warnings,
    )
