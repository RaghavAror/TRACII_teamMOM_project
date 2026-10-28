# Audit of the base repository: drPod/chainviz

Audited at commit `6250706` ("Merge ovh-migration") on 27 Oct 2026. MIT licence, © 2026 Darsh Poddar.

## What chainviz is
A JacHacks 2026 project: a 3D force-graph of 1,087 popular npm packages coloured by an ecosystem-wide
"blast radius" (dependents × downloads), plus Claude-Haiku "investigation agents" written in Jac.
It answers *"which npm packages would hurt the ecosystem most if compromised?"*, not
*"is **my** project affected and how do I fix it?"*.

| Part | Files | What works | Gap vs. Tracii's goal |
|---|---|---|---|
| Data pipeline | `scripts/fetch_*.py`, `compute_risk.py`, `export_json.py` | Pre-built `data/risk_data.json` (1,087 pkgs, OSV records, 4 attack scenarios) | Static snapshot; not the user's project |
| Backend | `main.jac`, `services/*.sv.jac`, `graph_store.py` | Jac walkers; Python store as a persistence workaround | Niche runtime; no tests; no version awareness |
| Package scanner | `frontend/index.html` `runScan()` | Paste package.json; highlight nodes | **Matches CVEs by package name only**, ignoring versions; no lockfile; transitive deps invisible |
| AI agents | `investigators.sv.jac` | 5 tool-calling agents + synthesis | Free-text output; no evidence IDs; can't separate facts from model prose; "be dramatic" prompt |
| Malware detection | – | none | Missing |
| Fix / rescan | – | none | Missing |
| Frontend | single 2,436-line HTML, Three.js | Impressive 3D view, attack replays | The guide warns against a graph that "looks impressive but does not help" |

## What Tracii keeps
- **Ideas:** the blast-radius concept (re-scoped to the user's own dependency paths), the curated real-incident
  narratives (event-stream, ua-parser-js, colors, node-ipc) reused as threat-pattern context in
  `backend/tracii/ai/threat_corpus.json`, the "frontend still works when the backend AI is unavailable" principle,
  and the static Vercel deploy shape.
- **No code was copied.** If you later vendor chainviz's 3D view as an optional "ecosystem" tab, keep its MIT
  copyright notice with the copied files.

## Why not extend chainviz in place
1. The Jac runtime adds a language the team must learn mid-hackathon, and the repo already needed a Python
   workaround for state persistence.
2. Every core Tracii stage (lockfile inventory, version-exact matching, malware channel, evidence schema,
   fix and rescan) is absent, so the reusable surface is small.
3. A typed Python service is easier for Claude, Muse Code and teammates to test and review.
