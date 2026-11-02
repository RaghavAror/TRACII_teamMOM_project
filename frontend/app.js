// Tracii frontend: no build step. All package-derived text is untrusted and is
// rendered with textContent only (never innerHTML).
import { $, h, api, post } from "./ui.js";
import { initGraph, focusPackage, preloadGraphLib, setGraphActive } from "./graph3d.js";
import { runAgents } from "./agents-view.js";
import { renderImpactMap, highlightInMap } from "./impact-map.js";

const SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];
const CAT_LABEL = {
  known_vulnerability: "Known vulnerabilities",
  malicious_indicator: "Malicious-behaviour indicators",
  repository_posture: "Repository posture",
  version_diff: "Version diff",
};
// Malicious-indicator findings come from two very different sources; never present a heuristic as confirmed malware.
const isKnownMalware = (f) => f.category === "malicious_indicator" && /^MAL-/.test(f.rule_or_advisory);
const TYPE_LABEL = (f) => f.category === "known_vulnerability" ? "Known vulnerability (advisory)"
  : isKnownMalware(f) ? "Known malicious package (OSV MAL- record)"
  : f.category === "malicious_indicator" ? "Suspicious behaviour (heuristic indicator, not confirmed malware)"
  : CAT_LABEL[f.category];
const SOURCE_LABEL = { "osv-api": "OSV.dev API", "osv-scanner": "OSV-Scanner", guarddog: "GuardDog (DataDog)", "tracii-static": "TRACII behaviour rules" };
const srcLabel = (s) => SOURCE_LABEL[s] || s;
const isDevOnly = (f) => f.paths.length > 0 && f.paths.every((p) => p.dev_only);
const isDirect = (f) => f.paths.some((p) => p.nodes.length === 2);

// Deterministic triage order from scanner facts only (no invented exploitability):
// known malware > severity > ships to production > direct dependency > a fixed version exists.
function priority(f) {
  return [isKnownMalware(f) ? 0 : 1, SEV_ORDER.indexOf(f.severity), isDevOnly(f) ? 1 : 0, isDirect(f) ? 0 : 1,
    f.fixed_versions.length ? 0 : 1];
}
const byPriority = (a, b) => { const x = priority(a), y = priority(b); for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] - y[i]; return 0; };
function whyFirst(f) {
  return [isKnownMalware(f) ? "known malware" : f.severity, isDevOnly(f) ? "dev only" : "ships to production",
    isDirect(f) ? "direct" : "transitive", f.category === "known_vulnerability" ? (f.fixed_versions.length ? `fix: ${f.fixed_versions[0]}` : "no fix published") : null].filter(Boolean);
}

function recommendedAction(f) {
  const via = [...new Set(f.paths.map((p) => p.direct_dependency))].join(", ");
  if (isKnownMalware(f)) return "Remove this version from the dependency tree" + (via ? ` (it arrives via ${via})` : "") +
    ". Only replace it with a version outside the affected range in the OSV record, and treat secrets on machines that installed it as exposed.";
  if (f.category === "known_vulnerability") {
    if (!f.fixed_versions.length) return "No fixed version is published. Check whether your app uses the affected functionality, consider replacing the package, and watch the advisory.";
    return isDirect(f) ? `Upgrade ${f.package} to ${f.fixed_versions.join(" or ")} in package.json. "Propose fix" below builds the change and verifies it by rescanning.`
      : `Upgrade the parent (${via || "unknown"}) to a release that depends on ${f.package} ≥ ${f.fixed_versions[0]}, or add an npm override. "Propose fix" builds the override and verifies it by rescanning.`;
  }
  if (f.category === "malicious_indicator") return f.severity === "info" ? "Context only (e.g. an install script or a capability). No action unless other findings point at this package."
    : "Review the cited code before trusting this version. Compare it with the previous release in Tools → Version diff; pin to a version without the behaviour if it is unexplained.";
  return "Review the cited evidence.";
}

let scan = null;
let activeCat = "known_vulnerability";

// ---------- views (left sidebar) ----------
const VIEW_TITLE = { scan: "New scan", overview: "Overview", findings: "Findings", graph: "Impact map",
  reports: "CI gate & reports", details: "Scan details", ask: "Ask AI", diff: "Version diff" };
const NEEDS_SCAN = new Set(["overview", "findings", "graph", "reports", "details", "ask"]);
function showView(name, { push = true } = {}) {
  if (!VIEW_TITLE[name] || (NEEDS_SCAN.has(name) && !scan)) name = "scan";
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("hidden", v.dataset.view !== name));
  document.querySelectorAll(".side-nav a, .brand").forEach((a) => a.classList.toggle("active", a.dataset.view === name));
  $("#view-title").textContent = VIEW_TITLE[name];
  $("#source-line").classList.toggle("hidden", !scan || name === "scan" || name === "diff");
  if (push && location.hash !== `#/${name}`) history.pushState(null, "", `#/${name}`);
  setGraphActive(name === "graph" && graphMode === "3d");   // pause the 3D render loop when it is not on screen
  $(".content").scrollTo?.(0, 0);
  window.scrollTo(0, 0);
}
window.addEventListener("popstate", () => showView(location.hash.replace("#/", "") || "scan", { push: false }));
document.querySelectorAll("[data-view]").forEach((a) => a.tagName === "A" && a.addEventListener("click", (e) => {
  e.preventDefault();
  if (a.classList.contains("disabled")) return;
  showView(a.dataset.view);
}));
document.addEventListener("tracii:view", (e) => { if (e.detail === "graph") setGraphMode("3d"); showView(e.detail); });   // from the 3D graph

// Impact map is the default; the 3D graph is an optional "Explore in 3D" mode.
let graphMode = "map";
function setGraphMode(mode) {
  graphMode = mode;
  setGraphActive(mode === "3d" && location.hash === "#/graph");
  document.querySelectorAll("#graph-mode button").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  $("#impact-map").classList.toggle("hidden", mode !== "map");
  $("#graph-3d-panel").classList.toggle("hidden", mode !== "3d");
}
document.querySelectorAll("#graph-mode button").forEach((b) => b.addEventListener("click", () => setGraphMode(b.dataset.mode)));
function showInMap(f) {
  setGraphMode("map");
  showView("graph");
  highlightInMap(`${f.package}@${f.version}`);
}
document.addEventListener("click", (e) => {   // close the Export menu when clicking elsewhere
  const m = $("#export-menu");
  if (m.open && !m.contains(e.target)) m.open = false;
});
function enableScanViews() {
  document.querySelectorAll(".needs-scan").forEach((a) => { a.classList.remove("disabled"); a.removeAttribute("title"); a.removeAttribute("aria-disabled"); });
}
document.querySelectorAll(".needs-scan").forEach((a) => { a.classList.add("disabled"); a.title = "Run a scan first"; a.setAttribute("aria-disabled", "true"); });
showView(location.hash.replace("#/", "") || "scan", { push: false });
preloadGraphLib();

// ---------- intake ----------
document.querySelectorAll("#intake .tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("#intake .tabs button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll("#intake .tab-panel").forEach((p) => p.classList.toggle("hidden", p.id !== `form-${b.dataset.tab}`));
}));

document.querySelectorAll("[data-example]").forEach((b) => b.addEventListener("click", () => {
  $("#form-github [name=url]").value = b.dataset.example;
}));

api("/api/fixtures").then((names) => names.forEach((n) => $("#fixture-select").append(
  h("option", { value: n, selected: n === "vulnerable-demo" }, n)))).catch(() => {});

$("#form-github").addEventListener("submit", (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  start(() => post("/api/scan/github", { url: f.get("url"), subdir: f.get("subdir") || "" }));
});
$("#form-upload").addEventListener("submit", (e) => {
  e.preventDefault();
  start(() => api("/api/scan/upload", { method: "POST", body: new FormData(e.target) }));
});
$("#form-fixture").addEventListener("submit", (e) => {
  e.preventDefault();
  start(() => post("/api/scan/fixture", { name: new FormData(e.target).get("name") }));
});

async function start(kickoff) {
  const prog = $("#progress");
  const buttons = document.querySelectorAll("#intake button.primary");
  prog.classList.remove("hidden");
  prog.replaceChildren(h("div", { class: "step running" }, "Starting scan…"));
  buttons.forEach((b) => { b.disabled = true; });
  try {
    const { scan_id } = await kickoff();
    await poll(scan_id);
  } catch (err) {
    prog.append(h("div", { class: "error" }, `Scan failed: ${err.message}`));
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
  }
}

async function poll(id) {
  const prog = $("#progress");
  const t0 = Date.now();
  for (;;) {
    const s = await api(`/api/scans/${id}`);
    const done = s.status !== "running";
    prog.replaceChildren(...s.progress.map((p, i) =>
      h("div", { class: `step ${!done && i === s.progress.length - 1 ? "running" : "ok"}` }, p)),
      done ? null : h("div", { class: "muted" }, `${Math.round((Date.now() - t0) / 1000)} s · large lockfiles take up to a minute`));
    if (s.status === "done") {
      scan = s;
      activeCat = s.result.findings.some(isKnownMalware) ? "malicious_indicator" : "known_vulnerability";
      $("#results").classList.remove("hidden");
      enableScanViews();
      render();
      renderVerdict();
      showView("overview");
      setGraphMode("map");
      renderImpactMap(scan, { onOpen: openFinding });
      initGraph(scan, { onOpenFinding: openFinding });
      return;
    }
    if (s.status === "failed") throw new Error(s.error || "unknown error");
    await new Promise((r) => setTimeout(r, 1000));
  }
}

// ---------- results ----------
function render() {
  const r = scan.result;
  $("#results").classList.remove("hidden");
  const src = r.source;
  $("#source-line").textContent = `${src.kind}: ${src.label}` + (src.commit_sha ? ` @ ${src.ref} (${src.commit_sha})` : "") +
    ` · ${r.inventory.packages.length} packages · lockfile v${r.inventory.lockfile_version} · scanned ${new Date(r.created_at).toLocaleString()} · scan ${r.scan_id}`;
  renderExports(r);
  const shown = r.findings.filter((f) => f.severity !== "info").length;
  $("#nav-findings").textContent = shown || "";
  $("#side-scan").textContent = `${src.kind === "fixture" ? "Demo" : src.kind}: ${src.label}`;
  $("#checks").replaceChildren(...r.checks.map((c) =>
    h("li", { class: `check ${c.status}` }, h("b", {}, c.name), ` ${c.status}`, c.packages_checked ? ` · ${c.packages_checked} pkgs` : "", h("div", { class: "muted" }, c.detail))));
  $("#warnings").replaceChildren(...r.inventory.warnings.map((w) => h("div", { class: "warn" }, "⚠ " + w)));
  renderLicenses(r.inventory);

  const groups = [
    ["Known malicious packages", "OSV MAL- records: reported malware. Remove.", "malicious_indicator", (f) => isKnownMalware(f), "mal"],
    ["Known vulnerabilities", "OSV / GitHub advisories matching the installed version.", "known_vulnerability", (f) => f.category === "known_vulnerability", "vuln"],
    ["Suspicious behaviour", "Heuristic indicators from code rules / GuardDog. Needs review; not confirmed malware.", "malicious_indicator", (f) => f.category === "malicious_indicator" && !isKnownMalware(f), "sus"],
    ["Repository posture", "Hygiene signals. Never malware evidence.", "repository_posture", (f) => f.category === "repository_posture", "post"],
  ];
  $("#summary").replaceChildren(...groups.map(([label, help, cat, pred, cls]) => {
    const list = r.findings.filter(pred);
    const c = {};
    list.forEach((f) => { c[f.severity] = (c[f.severity] || 0) + 1; });
    return h("button", { class: `sum-card ${cls} ${list.length ? "has" : ""}`, type: "button", title: help,
      onclick: () => { activeCat = cat; render(); showView("findings"); } },
      h("div", { class: "sum-n" }, list.length), h("div", { class: "sum-l" }, label),
      h("div", { class: "sevs" }, SEV_ORDER.filter((s) => c[s]).map((s) => h("span", { class: `sev ${s}` }, `${c[s]} ${s}`))),
      h("div", { class: "muted" }, list.length ? help : "No issue detected by these checks."));
  }));

  $("#cat-tabs").replaceChildren(...Object.keys(CAT_LABEL).map((cat) =>
    h("button", { class: cat === activeCat ? "active" : "", onclick: () => { activeCat = cat; render(); } }, CAT_LABEL[cat])));
  renderTable();
}

// One Export menu (top bar) and the same items as cards in "CI gate & reports".
function renderExports(r) {
  const base = `${window.TRACII_API}/api/scans/${encodeURIComponent(r.scan_id)}`;
  const items = [
    ["PDF security report", "Assessment of this scan at the gate threshold set in CI gate & reports", (cls) =>
      h("button", { class: cls, type: "button", onclick: (e) => downloadPdf(e.currentTarget) }, "Download PDF")],
    ["SBOM · CycloneDX", "Every package and version with purl, hash, scope and advisories", (cls) =>
      h("a", { class: cls, href: `${base}/sbom`, download: `tracii-${r.scan_id}.cdx.json` }, "Download SBOM")],
    ["SARIF", "For GitHub code scanning; each result points at package-lock.json", (cls) =>
      h("a", { class: cls, href: `${base}/sarif`, download: `tracii-${r.scan_id}.sarif` }, "Download SARIF")],
    ["CI gate report", "Markdown summary of the gate decision", (cls) =>
      h("button", { class: cls, type: "button", onclick: downloadGateReport }, "Download report")],
  ];
  const menu = $("#export-menu");
  menu.classList.remove("hidden");
  $("#exports").replaceChildren(...items.map(([label, help, el]) => {
    const node = el("menu-item");
    node.textContent = label;
    node.title = help;
    node.addEventListener("click", () => setTimeout(() => { menu.open = false; }, 0));
    return node;
  }));
  $("#report-links").replaceChildren(...items.map(([label, help, el]) =>
    h("div", { class: "report-card" }, h("b", {}, label), h("p", { class: "muted" }, help), el("btn"))));
}

function renderTable() {
  const q = $("#filter").value.trim().toLowerCase();
  const rows = scan.result.findings
    .filter((f) => f.category === activeCat && (!q || f.package.includes(q)))
    .sort(byPriority);
  $("#findings tbody").replaceChildren(...(rows.length ? rows.map((f) => h("tr", { onclick: () => showDetail(f) },
    h("td", {}, h("span", { class: `sev ${f.severity}` }, f.severity)),
    h("td", { class: "mono" }, `${f.package}@${f.version}`, isKnownMalware(f) ? h("span", { class: "tag malware" }, "known malware") : null),
    h("td", { class: "mono", title: srcLabel(f.source) }, f.rule_or_advisory),
    h("td", { class: "muted" }, f.paths[0] ? (f.paths[0].dev_only ? "dev · " : "") + f.paths[0].direct_dependency : "—"),
  )) : [h("tr", {}, h("td", { colspan: 4, class: "muted" }, "No findings in this category from the checks that ran."))]));
}
$("#filter").addEventListener("input", () => scan && renderTable());
$("#graph-focus").addEventListener("click", (e) => {
  const f = scan?.result.findings.filter((x) => x.severity !== "info").sort(byPriority)[0];
  if (!f) { e.target.textContent = "No findings to focus"; return; }
  if (!focusPackage(`${f.package}@${f.version}`)) e.target.textContent = "Not drawn in the 3D view";
  else { activeCat = f.category; render(); showDetail(f); }   // stay on the graph; detail panel updates below
});

function evidenceList(f) {
  return h("ol", { class: "evidence" }, f.evidence.map((e) => h("li", { id: `ev-${e.id}` },
    h("span", { class: "tag" }, e.kind), " ", e.summary,
    e.file ? h("span", { class: "mono" }, ` ${e.file}${e.line ? ":" + e.line : ""}`) : null,
    e.url ? h("a", { href: e.url, target: "_blank", rel: "noopener noreferrer" }, " source ↗") : null,
    e.snippet ? h("pre", { class: "snippet" }, e.snippet) : null,
    h("div", { class: "muted mono" }, e.id))));
}

function pathView(f) {
  if (!f.paths.length) return h("p", { class: "muted" }, "No dependency path recorded.");
  return h("div", {}, f.paths.map((p) => h("div", { class: "path" },
    p.nodes.map((n, i) => [i ? h("span", { class: "arrow" }, "→") : null,
      h("button", { class: `node ${i === p.nodes.length - 1 ? "flagged" : ""}`, onclick: () => { $("#filter").value = n.replace(/@[^@]*$/, "").replace("<app>", ""); renderTable(); } }, n)]),
    p.dev_only ? h("span", { class: "tag" }, "dev only") : null)));
}

function openFinding(id) {
  const f = scan.result.findings.find((x) => x.id === id);
  if (!f) return;
  activeCat = f.category;
  render();
  showDetail(f);
  showView("findings");
}

function showDetail(f) {
  const d = $("#detail");
  const aiBox = h("div", { class: "ai" });
  const fixBox = h("div", { class: "fix" });
  const agentBox = h("div", { class: "ai" });
  const mission = h("select", { title: "SSVC Mission & Well-being impact: how much harm a compromise of this app would do. Your call; Tracii cannot know it." },
    ["low", "medium", "high"].map((v) => h("option", { value: v, selected: v === "medium" }, `mission impact: ${v}`)));
  const direct = f.paths.some((p) => p.nodes.length === 2);
  d.replaceChildren(
    h("div", { class: `type-banner ${isKnownMalware(f) ? "mal" : f.category === "malicious_indicator" ? "sus" : "vuln"}` }, TYPE_LABEL(f)),
    h("h3", {}, f.title),
    h("div", { class: "row" }, h("span", { class: `sev ${f.severity}` }, f.severity),
      h("span", { class: "tag", title: "high = exact advisory match on the exact installed version; medium = correlated behaviour with a code location; low = a single, often benign signal" }, `confidence: ${f.confidence}`),
      h("span", { class: "tag" }, `source: ${srcLabel(f.source)}`),
      f.paths.length ? h("span", { class: "tag" }, direct ? "direct dependency" : "transitive dependency") : null,
      f.paths.length && f.paths.every((p) => p.dev_only) ? h("span", { class: "tag" }, "dev only") : null),
    h("p", { class: "mono" }, `${f.package}@${f.version} · ${f.rule_or_advisory}`, f.aliases.length ? ` (${f.aliases.join(", ")})` : ""),
    h("dl", { class: "facts" },
      h("dt", {}, "Installed"), h("dd", { class: "mono" }, `${f.package}@${f.version}`),
      h("dt", {}, "Reaches your app"), h("dd", {}, f.paths.length ? `${isDirect(f) ? "directly" : "transitively"} via ${[...new Set(f.paths.map((p) => p.direct_dependency))].join(", ")}${isDevOnly(f) ? " (dev only: not shipped)" : ""}` : "path not recorded"),
      f.category === "known_vulnerability" ? [h("dt", {}, "Fixed in"), h("dd", {}, f.fixed_versions.length ? f.fixed_versions.join(", ") : h("span", { class: "warn" }, "no fixed version published"))] : null),
    h("div", { class: `action ${isKnownMalware(f) ? "mal" : ""}` }, h("b", {}, "Recommended action: "), recommendedAction(f)),
    h("div", { class: "row actions" },
      h("button", { onclick: () => proposeFix(f, fixBox) }, "Propose fix"),
      h("button", { class: "ghost", onclick: () => explain(f, aiBox, false, false) }, "Explain with AI"),
      h("button", { class: "ghost", onclick: () => showInMap(f) }, "Show on map")),
    fixBox,
    aiBox,
    h("details", { class: "fold", open: true }, h("summary", {}, "How it reaches your app"), pathView(f)),
    h("details", { class: "fold" }, h("summary", {}, `Evidence (${f.evidence.length})`), evidenceList(f)),
    h("details", { class: "fold" }, h("summary", {}, `Limitations (${f.limitations.length})`),
      h("ul", {}, f.limitations.map((l) => h("li", { class: "muted" }, l)))),
    h("details", { class: "fold" }, h("summary", {}, "More AI options"),
      h("p", { class: "muted" }, "AI output is an assessment, not a finding: every claim must cite the evidence above, uncited claims are discarded, and the scanner verdict never changes."),
      h("div", { class: "row" },
        h("button", { class: "ghost", onclick: () => explain(f, aiBox, true, false), title: "Muse Wonder, multi-step reasoning" }, "Deep explanation"),
        h("button", { class: "ghost", onclick: () => explain(f, aiBox, false, true), title: "Adds open-weight second opinions (Glimmer, Spark Open)" }, "Explain + second opinion")),
      h("p", { class: "muted" }, "Investigation agents (~1 min): four specialists in parallel (exploit likelihood and priority, attacker techniques, build integrity, threat model), then a judge reconciles them."),
      h("div", { class: "row" }, h("button", { class: "ghost", onclick: () => runAgents(scan.scan_id, f, agentBox, mission.value) }, "Run investigation agents"), mission),
      agentBox),
  );
}

async function explain(f, box, deep, independent) {
  box.replaceChildren(h("p", { class: "muted" }, deep ? "Running deep investigation…" : "Investigating…"));
  try {
    const r = await post(`/api/scans/${scan.scan_id}/findings/${f.id}/explain`, { deep, independent });
    box.replaceChildren(
      h("div", { class: "row" }, h("span", { class: `tag ${r.ai_status}` }, r.ai_status === "ok" ? `AI · ${r.model}` : "AI unavailable: deterministic summary"),
        h("span", { class: "tag" }, `AI assessment: ${r.assessment}`), h("span", { class: "tag" }, `AI confidence: ${r.confidence}`)),
      h("p", { class: "muted" }, `Scanner verdict unchanged: ${r.scanner_category} / ${r.scanner_severity}`),
      h("p", {}, h("b", {}, "Observed: "), r.observed), h("p", {}, h("b", {}, "Why it matters: "), r.why_it_matters),
      h("ul", {}, r.claims.map((c) => h("li", {}, c.text, " ", c.evidence_ids.map((id) =>
        h("a", { href: `#ev-${id}`, class: "cite" }, `[${id.split("-").pop()}]`))))),
      r.discarded_claims.length ? h("details", {}, h("summary", {}, `${r.discarded_claims.length} ungrounded claim(s) discarded`),
        h("ul", {}, r.discarded_claims.map((c) => h("li", { class: "muted" }, c.text)))) : null,
      r.benign_explanations.length ? h("p", {}, h("b", {}, "Possible benign explanations: "), r.benign_explanations.join("; ")) : null,
      r.unknowns.length ? h("p", {}, h("b", {}, "Unknowns: "), r.unknowns.join("; ")) : null,
      h("p", {}, h("b", {}, "Next action: "), r.next_action),
      r.slices?.length ? h("details", {}, h("summary", {}, `Code slices sent to the model (${r.slices.length})`),
        r.slices.map((s) => h("pre", { class: "snippet" }, `${s.file}:${s.start}-${s.end}\n${s.code}`))) : null,
      (r.independent_assessments || []).length ? h("div", {}, h("h4", {}, "Independent assessments"),
        r.independent_assessments.map((a) => h("div", { class: "row" }, h("span", { class: "tag" }, `${a.assessor} · ${a.model}`),
          a.status === "ok" ? [h("span", { class: "tag" }, a.assessment), h("span", { class: `tag ${a.agrees_with_primary ? "ok" : "unavailable"}` }, a.agrees_with_primary ? "agrees with primary" : "disagrees with primary")]
          : h("span", { class: "tag unavailable", title: a.error || "" }, a.status === "timeout" ? "timed out" : "unavailable"),
          a.status !== "ok" && a.error ? h("span", { class: "muted" }, a.error) : null)))
        : independent ? h("p", { class: "muted" }, "No open-weight assessor configured (GLIMMER_* / SPARK_OPEN_*).") : null,
    );
  } catch (err) { box.replaceChildren(h("p", { class: "error" }, err.message)); }
}

async function proposeFix(f, box) {
  box.replaceChildren(h("p", { class: "muted" }, "Building proposal…"));
  try {
    const p = await post(`/api/scans/${scan.scan_id}/findings/${f.id}/fix`);
    const out = h("div", {});
    box.replaceChildren(
      h("p", {}, h("b", {}, p.kind.replace("_", " ") + ": "), p.reason),
      p.caveats.length ? h("ul", {}, p.caveats.map((c) => h("li", { class: "warn" }, c))) : null,
      p.diff ? h("pre", { class: "diff" }, p.diff) : null,
      p.diff ? h("p", { class: "muted" }, "Not applied to your repository. Simulate it below; you decide whether to commit it.") : null,
      p.diff ? h("button", { onclick: () => rescan(f, out) }, "Simulate fix and rescan") : null,
      out);
  } catch (err) { box.replaceChildren(h("p", { class: "error" }, err.message)); }
}

async function rescan(f, out) {
  out.replaceChildren(h("p", { class: "muted" }, "Re-resolving lockfile (no install scripts) and rescanning…"));
  try {
    const r = await post(`/api/scans/${scan.scan_id}/findings/${f.id}/rescan`);
    if (!r.comparison) { out.replaceChildren(h("p", { class: "warn" }, `Status: ${r.status}. ${r.detail}`)); return; }
    const list = (k, label) => h("div", {}, h("b", {}, `${label} (${r.comparison[k].length})`),
      h("ul", {}, r.comparison[k].slice(0, 30).map((x) => h("li", { class: "mono" }, `${x.package}@${x.version} ${x.rule}`))));
    const blob = new Blob([r.new_package_lock], { type: "application/json" });
    out.replaceChildren(
      h("p", {}, h("span", { class: `tag ${r.status}` }, r.status.replace("_", " ")), " target finding after rescan"),
      list("fixed", "Disappeared"), list("remaining", "Still present"), list("new", "New"),
      r.comparison.newly_covered.length ? list("newly_covered", "Newly covered by deep scan (not regressions)") : null,
      h("a", { href: URL.createObjectURL(blob), download: "package-lock.proposed.json" }, "Download proposed package-lock.json"));
  } catch (err) { out.replaceChildren(h("p", { class: "error" }, err.message)); }
}

// ---------- ask (text + voice) ----------
function showAnswer(r) {
  const byId = Object.fromEntries(scan.result.findings.map((f) => [f.id, f]));
  $("#answer").replaceChildren(
    r.transcript ? h("p", { class: "muted" }, `You asked: “${r.transcript}”`) : null,
    h("p", {}, r.answer),
    h("div", { class: "row" }, r.cited_finding_ids.map((id) => h("button", { class: "ghost", onclick: () => showDetail(byId[id]) },
      `${byId[id].package}@${byId[id].version} ${byId[id].rule_or_advisory}`))),
    r.unknowns.length ? h("p", { class: "muted" }, "Unknowns: " + r.unknowns.join("; ")) : null);
}
$("#ask-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#answer").textContent = "Thinking…";
  try { showAnswer(await post(`/api/scans/${scan.scan_id}/ask`, { question: new FormData(e.target).get("q") })); }
  catch (err) { $("#answer").textContent = err.message; }
});

// Record mic audio, convert to 16 kHz mono PCM16 WAV (required by /v1/asr/transcribe).
let recorder = null;
let chunks = [];
const vb = $("#voice-btn");
vb.addEventListener("pointerdown", async () => {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    chunks = [];
    recorder = new MediaRecorder(stream);
    recorder.ondataavailable = (e) => chunks.push(e.data);
    recorder.onstop = async () => {
      stream.getTracks().forEach((t) => t.stop());
      const wav = await toWav16k(new Blob(chunks));
      const fd = new FormData();
      fd.append("audio", new Blob([wav], { type: "audio/wav" }), "question.wav");
      $("#answer").textContent = "Transcribing…";
      try { showAnswer(await api(`/api/scans/${scan.scan_id}/ask/voice`, { method: "POST", body: fd })); }
      catch (err) { $("#answer").textContent = err.message; }
    };
    recorder.start();
    vb.textContent = "● Recording… release to send";
  } catch (err) { $("#answer").textContent = "Microphone unavailable: " + err.message; }
});
window.addEventListener("pointerup", () => {
  if (recorder && recorder.state === "recording") { recorder.stop(); vb.textContent = "🎙 Hold to ask"; }
});

async function toWav16k(blob) {
  const ctx = new AudioContext();
  const decoded = await ctx.decodeAudioData(await blob.arrayBuffer());
  const off = new OfflineAudioContext(1, Math.ceil(decoded.duration * 16000), 16000);
  const src = off.createBufferSource();
  src.buffer = decoded; src.connect(off.destination); src.start();
  const pcm = (await off.startRendering()).getChannelData(0);
  const buf = new DataView(new ArrayBuffer(44 + pcm.length * 2));
  const str = (o, s) => [...s].forEach((c, i) => buf.setUint8(o + i, c.charCodeAt(0)));
  str(0, "RIFF"); buf.setUint32(4, 36 + pcm.length * 2, true); str(8, "WAVE"); str(12, "fmt ");
  buf.setUint32(16, 16, true); buf.setUint16(20, 1, true); buf.setUint16(22, 1, true);
  buf.setUint32(24, 16000, true); buf.setUint32(28, 32000, true); buf.setUint16(32, 2, true); buf.setUint16(34, 16, true);
  str(36, "data"); buf.setUint32(40, pcm.length * 2, true);
  pcm.forEach((v, i) => buf.setInt16(44 + i * 2, Math.max(-1, Math.min(1, v)) * 0x7fff, true));
  return buf.buffer;
}

// ---------- version diff ----------
$("#diff-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  const out = $("#diff-out");
  out.textContent = "Fetching both tarballs (integrity-verified, not installed)…";
  try {
    const r = await post("/api/diff", f);
    const kv = (label, v) => h("div", {}, h("b", {}, label + ": "), Array.isArray(v) ? (v.join(", ") || "none") : (Object.keys(v).length ? JSON.stringify(v) : "none"));
    const list = (v, n = 40) => v.length > n ? [...v.slice(0, n), `… +${v.length - n} more`] : v;
    const flagged = Object.entries(r.code_changes || {}).filter(([, c]) => c.new_capabilities.length || c.injected_long_line || c.obfuscator_ids_added);
    out.replaceChildren(
      h("p", { class: r.security_relevant ? "warn" : "muted" }, r.security_relevant
        ? `${r.findings.length} security-relevant change${r.findings.length === 1 ? "" : "s"} between ${r.old_version} and ${r.new_version}.`
        : `No security-relevant changes found between ${r.old_version} and ${r.new_version}`
          + ` (${r.files_modified.length} file${r.files_modified.length === 1 ? "" : "s"} modified, ${r.files_added.length} added, ${r.files_removed.length} removed).`),
      h("p", { class: "muted" }, r.note),
      kv("Install scripts added/changed", r.install_scripts_added_or_changed), kv("Hosts added", r.hosts_added),
      kv("Capabilities added", Object.keys(r.capabilities_added)), kv("Dependencies added", r.dependencies_added),
      kv("Dependencies removed", r.dependencies_removed),
      kv("Files modified", list(r.files_modified || [])),
      kv("Files added", list(r.files_added)), kv("Files removed", list(r.files_removed)),
      flagged.length ? kv("Code added with new behaviour", flagged.map(([p, c]) =>
        `${p} (+${c.lines_added} lines${c.new_capabilities.length ? "; new: " + c.new_capabilities.join(", ") : ""}`
        + `${c.injected_long_line ? `; ${c.injected_long_line.length}-char line at ${c.injected_long_line.line}` : ""}`
        + `${c.obfuscator_ids_added ? `; ${c.obfuscator_ids_added} obfuscator ids` : ""})`)) : null,
      h("ul", {}, r.findings.map((x) => h("li", {}, h("span", { class: `sev ${x.severity}` }, x.severity), " ", x.title,
        h("ul", {}, x.evidence.map((ev) => h("li", { class: "mono muted" }, `${ev.summary}${ev.file ? " " + ev.file + (ev.line ? ":" + ev.line : "") : ""}`)))))));
  } catch (err) { out.textContent = err.message; }
});

// ---------- verdict + gate report ----------
async function renderVerdict() {
  const r = scan.result;
  const box = $("#verdict");
  const mal = r.findings.filter(isKnownMalware);
  const sus = r.findings.filter((f) => f.category === "malicious_indicator" && !isKnownMalware(f) && !["info", "low"].includes(f.severity));
  const vulns = r.findings.filter((f) => f.category === "known_vulnerability");
  const top = r.findings.filter((f) => f.severity !== "info").map((f) => f.severity).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0] || "none";
  const direct = r.inventory.packages.filter((p) => p.direct).length;
  const ran = r.checks.filter((c) => c.status === "ran").map((c) => c.name);
  const notRan = r.checks.filter((c) => c.status !== "ran");
  let g = null;
  try { g = await api(`/api/scans/${encodeURIComponent(r.scan_id)}/gate`); } catch { /* shown as unknown */ }
  const outcome = g?.outcome || "unknown";
  const badge = $("#nav-gate");
  badge.textContent = mal.length ? "malware" : outcome === "unknown" ? "" : outcome;
  badge.className = `badge b-${mal.length ? "fail" : outcome}`;
  const level = mal.length ? "critical" : outcome === "fail" ? "fail" : outcome === "pass" ? "pass" : "warn";
  const headline = mal.length ? `${mal.length} known malicious package${mal.length > 1 ? "s" : ""} in your dependency tree`
    : outcome === "fail" ? `${g.blocking.length} blocking finding${g.blocking.length === 1 ? "" : "s"} at severity high or above`
    : outcome === "pass" ? "No blocking findings from the checks that ran" : outcome === "incomplete" ? "Scan incomplete: a required check did not run" : "Gate decision unavailable";
  const first = r.findings.filter((f) => f.severity !== "info").sort(byPriority).slice(0, 3);
  box.className = `verdict card v-${level}`;
  box.replaceChildren(
    h("div", { class: "v-top" },
      h("div", { class: "v-main" },
        h("div", { class: "v-kicker" }, `CI gate · fail on high · ${outcome.toUpperCase()}${g ? ` (exit ${g.exit_code})` : ""}`),
        h("div", { class: "v-head" }, headline),
        h("div", { class: "muted" }, `${r.source.kind === "fixture" ? "Demo project" : r.source.kind}: ${r.source.label} · highest severity: ${top} · `,
          `checks ran: ${ran.join(", ") || "none"}`, notRan.length ? ` · not run: ${notRan.map((c) => c.name).join(", ")}` : "",
          " · deterministic scanner verdict, no AI involved")),
      h("div", { class: "v-stats" },
        stat(mal.length, "known malware", "mal"), stat(vulns.length, "vulnerabilities", "vuln"), stat(sus.length, "suspicious (medium+)", "sus"),
        stat(g ? g.blocking.length : "–", "blocking", ""), stat(r.inventory.packages.length, `packages · ${direct} direct`, ""))),
    first.length ? h("div", { class: "v-first" }, h("div", { class: "v-kicker" }, "Fix first"),
      h("ol", {}, first.map((f) => h("li", {}, h("button", { class: "linklike", onclick: () => openFinding(f.id) }, `${f.package}@${f.version}`),
        ` ${f.rule_or_advisory} `, whyFirst(f).map((w) => h("span", { class: "tag" }, w))))),
      h("div", { class: "muted" }, "Ordered by scanner facts only: known malware, severity, production path, direct dependency, fix available."),
      h("button", { class: "ghost sm", onclick: () => showView("findings") }, `See all ${r.findings.filter((f) => f.severity !== "info").length} findings →`)) : null);
  renderGate();
}
const stat = (n, label, cls) => h("div", { class: `v-stat ${cls}` }, h("b", {}, n), h("span", {}, label));

// Built at click time from the scan on screen and the gate threshold currently selected, so it can never be stale.
async function downloadPdf(btn) {
  const id = scan.scan_id;
  const form = new FormData($("#gate-form"));
  const q = new URLSearchParams({ fail_on: form.get("fail_on") || "high", ignore_dev: !!form.get("ignore_dev"), fail_on_unknown: !!form.get("fail_on_unknown") });
  const label = btn.textContent;
  btn.disabled = true; btn.textContent = "Building PDF…";
  try {
    const res = await fetch(`${window.TRACII_API}/api/scans/${encodeURIComponent(id)}/report.pdf?${q}`);
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
    const a = h("a", { href: URL.createObjectURL(await res.blob()), download: `tracii-report-${id}.pdf` });
    document.body.append(a); a.click(); a.remove();
  } catch (err) { alert(`PDF report failed: ${err.message}`); }
  finally { btn.disabled = false; btn.textContent = label; }
}

async function downloadGateReport() {
  try {
    const g = await api(`/api/scans/${encodeURIComponent(scan.scan_id)}/gate`);
    const a = h("a", { href: URL.createObjectURL(new Blob([g.markdown], { type: "text/markdown" })), download: `tracii-${scan.scan_id}-gate.md` });
    document.body.append(a); a.click(); a.remove();
  } catch (err) { alert(`Gate report failed: ${err.message}`); }
}

async function renderGate() {
  const out = $("#gate-out");
  const form = new FormData($("#gate-form"));
  const q = new URLSearchParams({ fail_on: form.get("fail_on"), ignore_dev: !!form.get("ignore_dev"), fail_on_unknown: !!form.get("fail_on_unknown") });
  out.replaceChildren(h("p", { class: "muted" }, "Evaluating policy…"));
  let g;
  try { g = await api(`/api/scans/${encodeURIComponent(scan.scan_id)}/gate?${q}`); }
  catch (err) { out.replaceChildren(h("p", { class: "error" }, `Gate unavailable: ${err.message}`)); return; }
  const byId = Object.fromEntries(scan.result.findings.map((f) => [f.id, f]));
  const blocking = g.blocking.map((id) => byId[id]).filter(Boolean).sort(byPriority);
  const p = g.policy;
  const cmd = `python -m tracii scan --dir . --fail-on ${p.fail_on}${p.ignore_dev ? " --ignore-dev" : ""}${p.fail_on_unknown ? " --fail-on-unknown" : ""} --sarif tracii.sarif`;
  out.replaceChildren(
    h("div", { class: "gate-row" },
      h("div", { class: `gate-badge g-${g.outcome}` }, g.outcome.toUpperCase(), h("small", {}, `exit code ${g.exit_code}`)),
      h("div", { class: "v-stats" }, stat(g.blocking.length, "blocking", "vuln"), stat(g.non_blocking, "below threshold", ""),
        stat(g.unknown_severity.length, "unknown severity", ""), g.ignored_dev ? stat(g.ignored_dev, "ignored (dev only)", "") : null)),
    g.failed_checks.length ? h("p", { class: "warn" }, `Incomplete: required check(s) did not run: ${g.failed_checks.join(", ")}. No findings from a check that did not run is not a pass.`) : null,
    h("p", { class: "muted" }, `Gated categories: ${p.categories.join(", ")}. Repository posture never fails the build. Known vulnerabilities and malicious-behaviour findings are gated by severity alike; the findings table keeps them apart.`),
    blocking.length ? h("details", { open: blocking.length <= 8 }, h("summary", {}, `Blocking findings (${blocking.length})`),
      h("ul", {}, blocking.map((f) => h("li", {}, h("span", { class: `sev ${f.severity}` }, f.severity), " ",
        h("button", { class: "linklike mono", onclick: () => openFinding(f.id) }, `${f.package}@${f.version}`), ` ${f.rule_or_advisory}`,
        isKnownMalware(f) ? h("span", { class: "tag malware" }, "known malware") : null)))) : null,
    h("div", { class: "row" }, h("span", { class: "muted" }, "Same decision in CI:"), h("code", { class: "mono cmd" }, cmd)),
  );
}
$("#gate-form").addEventListener("change", () => scan && renderGate());

const COPYLEFT = /\b(A?GPL|LGPL|MPL|EPL|EUPL|SSPL|CDDL|OSL|CC-BY-SA)/i;
function renderLicenses(inv) {
  const prod = inv.packages.filter((p) => !p.dev);
  const counts = {};
  prod.forEach((p) => { const k = p.license || "not recorded"; counts[k] = (counts[k] || 0) + 1; });
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const flagged = prod.filter((p) => !p.license || COPYLEFT.test(p.license));
  $("#licenses").replaceChildren(
    inv.lockfile_version < 2 ? h("p", { class: "warn" }, "Lockfile v1 does not record licenses.") : null,
    h("p", { class: "muted" }, `${prod.length} production package${prod.length === 1 ? "" : "s"} (devDependencies excluded). Licenses are also written to the SBOM.`),
    h("div", { class: "row" }, rows.map(([k, n]) => h("span", { class: `tag ${k === "not recorded" || COPYLEFT.test(k) ? "unavailable" : ""}` }, `${k} · ${n}`))),
    flagged.length ? h("details", {}, h("summary", {}, `${flagged.length} to review (copyleft or no license recorded)`),
      h("ul", {}, flagged.slice(0, 50).map((p) => h("li", { class: "mono" }, `${p.name}@${p.version} · ${p.license || "not recorded"}`))))
      : h("p", { class: "muted" }, "No copyleft or missing licenses among production packages."));
}


// ---------- model intelligence ----------
const STATUS_TEXT = { verified: "connected", failed: "failed", configured: "configured · not yet called", not_configured: "not configured" };
const ROLE_NAME = { investigator: "Muse Spark", deep: "Muse Wonder", image: "Muse Image", voice: "Muse Voice Transcribe", segment: "SAM 3.1",
  independent_glimmer: "Muse Glimmer", independent_spark_open: "Muse Spark Open", dev_agent: "Muse Code" };

const ago = (t) => { const s = Math.max(0, Math.round(Date.now() / 1000 - t)); return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : new Date(t * 1000).toLocaleTimeString(); };
function modelRows(rows, checks = []) {
  const byRole = Object.fromEntries(checks.map((c) => [c.role, c]));
  return h("div", { class: "models" }, rows.map((r) => {
    const c = byRole[r.role];
    const st = r.role === "dev_agent" ? "dev" : r.status;
    return h("div", { class: `model m-${st}` },
      h("div", { class: "row" }, h("b", {}, ROLE_NAME[r.role] || r.role), h("span", { class: "mono muted" }, r.model),
        h("span", { class: `tag ${st}` }, r.role === "dev_agent" ? "development-time only" : STATUS_TEXT[r.status] || r.status),
        r.check_latency_s != null ? h("span", { class: "muted" }, `last check ${r.check_latency_s}s`) : null,
        r.last_ok_at ? h("span", { class: "muted" }, `· last success ${ago(r.last_ok_at)}`) : null),
      h("div", { class: "muted" }, r.feature),
      r.note ? h("div", { class: "muted" }, r.note) : null,
      r.error ? h("div", { class: "error" }, r.error) : null);
  }));
}

async function showModels(checkResult) {
  const body = $("#models-body");
  let rows;
  try { rows = checkResult?.status || await api("/api/models/status"); }
  catch (err) { body.replaceChildren(h("p", { class: "error" }, err.message)); return; }
  updateDot(rows);
  const btn = h("button", { onclick: async () => {
    btn.disabled = true; btn.textContent = "Checking… (one minimal request per model)";
    try { showModels(await post("/api/models/check")); } catch (err) { btn.textContent = err.message; }
  } }, "Run live check");
  body.replaceChildren(
    h("h3", {}, "Model intelligence"),
    h("p", { class: "muted" }, "Scanners decide; models explain. Each model only sees the scanner's evidence and must cite it. Without credentials every AI feature falls back to a deterministic summary."),
    modelRows(rows, checkResult?.results),
    h("div", { class: "row" }, btn,
      checkResult ? h("span", { class: "muted" }, `${checkResult.results.length ? "Checked" : "Nothing to check: no model credentials on this server"}${checkResult.cached ? " (cached, < 60 s old)" : ""}`) : null),
    h("p", { class: "muted" }, "“connected” means a real call succeeded in this server process; “failed” shows the last error. Muse Image is off unless enabled (illustration only, never evidence). Muse Code was used by the team during development, not at runtime."));
}
function updateDot(rows) {
  const meta = rows.filter((r) => ["investigator", "deep"].includes(r.role));
  const cls = meta.some((r) => r.status === "failed") ? "failed" : meta.some((r) => r.status === "verified") ? "verified"
    : meta.some((r) => r.status === "configured") ? "configured" : "not_configured";
  $("#models-dot").className = `dot ${cls}`;
  $("#models-dot").title = `Meta models: ${STATUS_TEXT[cls]}`;
}
api("/api/models/status").then(updateDot).catch(() => {});

$("#models-btn").addEventListener("click", () => { showModels(); $("#models-dialog").showModal(); });

// ---------- guidebook ----------
document.querySelectorAll(".open-guide").forEach((el) => el.addEventListener("click", (e) => {
  e.preventDefault();
  $("#guide-dialog").showModal();
  $("#guide-dialog").scrollTop = 0;
}));
document.querySelectorAll(".guide-toc a").forEach((a) => a.addEventListener("click", (e) => {
  e.preventDefault();
  $(a.getAttribute("href")).scrollIntoView({ behavior: "smooth", block: "start" });
}));
$("#guide-dialog").addEventListener("click", (e) => { if (e.target === e.currentTarget) e.currentTarget.close(); });   // click on backdrop
