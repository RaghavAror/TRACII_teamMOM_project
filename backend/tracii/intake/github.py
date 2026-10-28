"""GitHub intake: resolve a repo URL to an exact commit SHA, then fetch only
package.json and package-lock.json at that SHA. No clone, no install.
The SHA is recorded so the scan never silently drifts to another commit."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import httpx

URL_RE = re.compile(r"^https://github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?"
                    r"(?:/tree/([A-Za-z0-9._/-]{1,200}))?/?$")
MAX_FILE = 20 * 1024 * 1024


class IntakeError(ValueError):
    pass


@dataclass
class RepoRef:
    owner: str
    repo: str
    ref: str | None


def parse_url(url: str) -> RepoRef:
    m = URL_RE.match(url.strip())
    if not m:
        raise IntakeError("expected https://github.com/<owner>/<repo>[/tree/<ref>]")
    return RepoRef(m[1], m[2], m[3])


def _safe_subdir(subdir: str) -> str:
    sub = subdir.strip().strip("/")
    if sub and (".." in sub.split("/") or not re.fullmatch(r"[A-Za-z0-9._/-]+", sub)):
        raise IntakeError("invalid subdirectory")
    return sub


def _headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN")
    return {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})}


def resolve_commit(ref: RepoRef, client: httpx.Client) -> tuple[str, str]:
    api = f"https://api.github.com/repos/{ref.owner}/{ref.repo}"
    branch = ref.ref
    if not branch:
        r = client.get(api, headers=_headers())
        if r.status_code == 404:
            raise IntakeError("repository not found or private")
        r.raise_for_status()
        branch = r.json()["default_branch"]
    r = client.get(f"{api}/commits/{branch}", headers=_headers())
    if r.status_code in (404, 422):
        raise IntakeError(f"ref '{branch}' not found")
    r.raise_for_status()
    return branch, r.json()["sha"]


def fetch_manifest_files(url: str, subdir: str, client: httpx.Client) -> tuple[RepoRef, str, str, bytes, bytes]:
    ref = parse_url(url)
    sub = _safe_subdir(subdir)
    branch, sha = resolve_commit(ref, client)
    out = []
    for name in ("package.json", "package-lock.json"):
        path = f"{sub}/{name}" if sub else name
        r = client.get(f"https://raw.githubusercontent.com/{ref.owner}/{ref.repo}/{sha}/{path}")
        if r.status_code == 404:
            raise IntakeError(f"{path} not found at {sha[:10]} (MVP requires package.json + package-lock.json)")
        r.raise_for_status()
        if len(r.content) > MAX_FILE:
            raise IntakeError(f"{path} too large")
        out.append(r.content)
    return ref, branch, sha, out[0], out[1]
