// Tracii frontend: no build step. All package-derived text is untrusted and is
// rendered with textContent only (never innerHTML).
import { $, h, api, post } from "./ui.js";
import { initGraph, focusPackage, preloadGraphLib, setGraphActive, prewarmGraph, graphReady } from "./graph3d.js";
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

// Findings tabs: plain names, a tab only appears when it has findings.
const TABS = [
  { key: "malware", label: "Known malware", pred: (f) => isKnownMalware(f) },
  { key: "vuln", label: "Vulnerabilities", pred: (f) => f.category === "known_vulnerability" },
  { key: "suspicious", label: "Suspicious code", pred: (f) => f.category === "malicious_indicator" && !isKnownMalware(f) },
  { key: "posture", label: "Repository posture", pred: (f) => f.category === "repository_posture" },
  { key: "diff", label: "Version changes", pred: (f) => f.category === "version_diff" },
];
const tabOf = (f) => (TABS.find((t) => t.pred(f)) || TABS[1]).key;
const firstTab = (findings) => (TABS.find((t) => findings.some((f) => t.pred(f) && f.severity !== "info"))
  || TABS.find((t) => findings.some(t.pred)) || TABS[1]).key;

// ---------- fix versions (same rule as the backend's Propose fix: highest per-advisory fix, same major preferred) ----------
const sv = (v) => { const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/.exec(v) || []; return [+m[1] || 0, +m[2] || 0, +m[3] || 0, m[4] ? 0 : 1, m[4] || ""]; };
const cmpVer = (a, b) => { const x = sv(a), y = sv(b); for (let i = 0; i < 4; i++) if (x[i] !== y[i]) return x[i] - y[i]; return x[4] < y[4] ? -1 : x[4] > y[4] ? 1 : 0; };
function pickFix(installed, fixed) {
  const newer = fixed.filter((v) => cmpVer(v, installed) > 0);
  if (!newer.length) return null;
  const same = newer.filter((v) => sv(v)[0] === sv(installed)[0]);
  return (same.length ? same : newer).sort(cmpVer)[0];
}
// For the vulnerability findings of one package@version: one target version and what it covers.
function packageFix(vulns) {
  const picks = vulns.map((f) => pickFix(f.version, f.fixed_versions));
  const ok = picks.filter(Boolean).sort(cmpVer);
  const target = ok.length ? ok[ok.length - 1] : null;
  return { target, fixes: ok.length, unfixed: picks.length - ok.length,
    major: !!target && sv(target)[0] !== sv(vulns[0].version)[0] };
}
// Group findings by package@version, worst first.
function groupByPackage(findings) {
  const m = new Map();
  for (const f of findings) {
    const k = `${f.package}@${f.version}`;
    if (!m.has(k)) m.set(k, { key: k, package: f.package, version: f.version, findings: [] });
    m.get(k).findings.push(f);
  }
  const groups = [...m.values()];
  groups.forEach((g) => g.findings.sort(byPriority));
  return groups.sort((a, b) => byPriority(a.findings[0], b.findings[0]) || b.findings.length - a.findings.length);
}
const viaOf = (findings) => [...new Set(findings.flatMap((f) => f.paths.map((p) => p.direct_dependency)))];
// "direct", "via express" or "direct, and via mkdirp" — the package itself is not listed as its own route
function routeText(g) {
  const via = viaOf(g.findings).filter((d) => d !== g.package);
  const direct = g.findings.some(isDirect);
  return [direct ? "direct" : null, via.length ? `${direct ? "and " : ""}via ${via.join(", ")}` : null].filter(Boolean).join(", ") || "—";
}
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;

let scan = null;
let activeCat = "vuln";   // a TABS key
let showContext = false;  // info-level context notes are hidden unless asked for
let readOnly = false;     // a saved scan shown after the server restarted: server-side actions need a fresh scan

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
  if (name === "graph") setGraphMode(graphMode);   // re-applies the panel state and prepares the 3D view if needed
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
  // In map mode the 3D panel stays laid out but invisible until it has been prepared, so opening it later is instant.
  const p3 = $("#graph-3d-panel");
  p3.classList.toggle("hidden", mode !== "3d" && graphReady());
  p3.classList.toggle("prewarm", mode !== "3d" && !graphReady());
  if (mode === "map" && location.hash === "#/graph") prewarmGraph();
}
document.addEventListener("tracii:3d-ready", () => { if (graphMode !== "3d") { $("#graph-3d-panel").classList.add("hidden"); $("#graph-3d-panel").classList.remove("prewarm"); } });
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
  $("#saved-banner")?.remove();
  $("#last-scan")?.remove();
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
      activeCat = firstTab(s.result.findings);
      readOnly = false;
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
  if (readOnly) $("#export-menu").classList.add("hidden");   // exports need the scan on the server
  const shown = r.findings.filter((f) => f.severity !== "info").length;
  $("#nav-findings").textContent = shown || "";
  $("#side-scan").textContent = `${src.kind === "fixture" ? "Demo" : src.kind}: ${src.label}`;
  $("#checks").replaceChildren(...r.checks.map((c) =>
    h("li", { class: `check ${c.status}` }, h("b", {}, c.name), ` ${c.status}`, c.packages_checked ? ` · ${c.packages_checked} pkgs` : "", h("div", { class: "muted" }, c.detail))));
  $("#warnings").replaceChildren(...r.inventory.warnings.map((w) => h("div", { class: "warn" }, "⚠ " + w)));
  renderLicenses(r.inventory);

  // a tab appears only when it has real findings (info-only context notes do not count), or when it is open
  const real = (t) => r.findings.some((f) => t.pred(f) && f.severity !== "info");
  const tabs = TABS.filter((t) => real(t) || (t.key === activeCat && r.findings.some(t.pred) && TABS.some(real)));
  if (!tabs.some((t) => t.key === activeCat)) activeCat = tabs[0]?.key || "vuln";
  $("#cat-tabs").replaceChildren(...tabs.map((t) => {
    const n = groupByPackage(r.findings.filter((f) => t.pred(f) && f.severity !== "info")).length;
    return h("button", { class: t.key === activeCat ? "active" : "", onclick: () => { activeCat = t.key; render(); } },
      t.label, h("span", { class: "tab-n" }, n));
  }));
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
  const tab = TABS.find((t) => t.key === activeCat);
  const anyReal = scan.result.findings.some((f) => f.severity !== "info");   // otherwise: no tabs, only optional notes
  const inTab = scan.result.findings.filter((f) => (!anyReal || tab.pred(f)) && (!q || f.package.toLowerCase().includes(q)));
  const context = inTab.filter((f) => f.severity === "info");
  const groups = groupByPackage(showContext ? inTab : inTab.filter((f) => f.severity !== "info"));
  const rows = groups.map((g) => {
    const worst = g.findings[0];
    const vulns = g.findings.filter((f) => f.category === "known_vulnerability");
    const fx = vulns.length ? packageFix(vulns) : null;
    const what = isKnownMalware(worst) ? worst.title
      : vulns.length ? plural(vulns.length, "vulnerability", "vulnerabilities")
      : plural(g.findings.length, "warning");
    const fixLine = !fx ? null : !fx.target ? h("span", { class: "warn" }, "no fixed version published")
      : h("span", { class: "fixline" }, `upgrade to ${fx.target} ${fx.unfixed ? `fixes ${fx.fixes} of ${vulns.length}` : vulns.length > 1 ? "fixes all" : "fixes it"}`,
        fx.major ? h("span", { class: "tag" }, "major") : null);
    return h("tr", { onclick: () => showPackage(g) },
      h("td", {}, h("span", { class: `sev ${worst.severity}` }, worst.severity)),
      h("td", {}, h("b", {}, g.package), " ", h("span", { class: "muted mono" }, g.version),
        isKnownMalware(worst) ? h("span", { class: "tag malware" }, "known malware") : null),
      h("td", {}, h("div", {}, what, fixLine ? " · " : "", fixLine),
        h("div", { class: "muted small" }, isKnownMalware(worst) ? worst.rule_or_advisory : worst.title)),
      h("td", { class: "muted" }, routeText(g), g.findings.every(isDevOnly) ? " (dev only)" : ""));
  });
  $("#findings tbody").replaceChildren(...(rows.length ? rows : [h("tr", {}, h("td", { colspan: 4, class: "muted" },
    !anyReal ? "No problems found by the checks that ran." : context.length ? "Only context notes here (for example “has an install script”); no warnings." : "Nothing in this category from the checks that ran."))]));
  $("#context-toggle")?.remove();
  if (context.length) $("#findings").after(h("button", { id: "context-toggle", class: "linklike small", onclick: () => { showContext = !showContext; renderTable(); } },
    showContext ? "Hide context notes" : `Show ${plural(context.length, "context note")} (info level: not a problem on its own)`));
}
$("#filter").addEventListener("input", () => scan && renderTable());
$("#graph-focus").addEventListener("click", (e) => {
  const f = scan?.result.findings.filter((x) => x.severity !== "info").sort(byPriority)[0];
  if (!f) { e.target.textContent = "No findings to focus"; return; }
  if (!focusPackage(`${f.package}@${f.version}`)) e.target.textContent = "Not drawn in the 3D view";
  else { activeCat = tabOf(f); render(); showDetail(f); }   // stay on the graph; detail panel updates below
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
  activeCat = tabOf(f);
  if (f.severity === "info") showContext = true;
  render();
  showDetail(f);
  showView("findings");
}

// One package, all its findings: the fix that clears them, then each finding in plain words.
function showPackage(g) {
  if (g.findings.length === 1) return showDetail(g.findings[0]);
  const d = $("#detail");
  const worst = g.findings[0];
  const vulns = g.findings.filter((f) => f.category === "known_vulnerability");
  const fx = vulns.length ? packageFix(vulns) : null;
  const fixBox = h("div", { class: "fix" });
  const via = viaOf(g.findings);
  d.replaceChildren(
    h("div", { class: `type-banner ${isKnownMalware(worst) ? "mal" : worst.category === "malicious_indicator" ? "sus" : "vuln"}` }, TYPE_LABEL(worst)),
    h("h3", {}, g.package, " ", h("span", { class: "muted mono" }, g.version)),
    h("p", {}, plural(g.findings.length, vulns.length === g.findings.length ? "vulnerability" : "finding",
      vulns.length === g.findings.length ? "vulnerabilities" : "findings"),
      via.length ? ` · reaches your app ${g.findings.some(isDirect) ? "directly" : "through " + via.join(", ")}` : "",
      g.findings.every(isDevOnly) ? " (dev only: not shipped)" : ""),
    fx ? h("div", { class: "action" }, h("b", {}, "Fix: "), fx.target
      ? `upgrade ${g.package} to ${fx.target}. ${fx.unfixed ? `That fixes ${fx.fixes} of ${vulns.length}; ${fx.unfixed} ha${fx.unfixed === 1 ? "s" : "ve"} no published fix.` : `That fixes ${vulns.length > 1 ? "all " + vulns.length : "it"}.`}`
        + (fx.major ? " It is a major version change, so test your app." : "")
      : "no fixed version is published; consider replacing the package.") : h("div", { class: `action ${isKnownMalware(worst) ? "mal" : ""}` }, h("b", {}, "What to do: "), recommendedAction(worst)),
    h("div", { class: "row actions" },
      fx?.target ? h("button", { onclick: () => proposeFix(vulns[0], fixBox) }, "Propose fix") : null,
      h("button", { class: "ghost", onclick: () => showInMap(worst) }, "Show on map")),
    fixBox,
    h("h4", {}, "Findings on this package"),
    h("ul", { class: "pkg-findings" }, g.findings.map((f) => h("li", {},
      h("span", { class: `sev ${f.severity}` }, f.severity), " ",
      h("button", { class: "linklike", onclick: () => showDetail(f, g) }, f.title),
      h("div", { class: "muted mono small" }, f.rule_or_advisory, f.aliases.length ? ` · ${f.aliases.join(", ")}` : "",
        f.category === "known_vulnerability" ? ` · fixed in ${f.fixed_versions.join(", ") || "—"}` : "")))),
    h("p", { class: "muted small" }, "Open a finding for its evidence, dependency path and an AI explanation."),
  );
}

function showDetail(f, fromGroup = null) {
  const d = $("#detail");
  const aiBox = h("div", { class: "ai" });
  const fixBox = h("div", { class: "fix" });
  const agentBox = h("div", { class: "ai" });
  const mission = h("select", { title: "SSVC Mission & Well-being impact: how much harm a compromise of this app would do. Your call; Tracii cannot know it." },
    ["low", "medium", "high"].map((v) => h("option", { value: v, selected: v === "medium" }, `mission impact: ${v}`)));
  const direct = f.paths.some((p) => p.nodes.length === 2);
  d.replaceChildren(
    fromGroup ? h("button", { class: "linklike small", onclick: () => showPackage(fromGroup) }, `← all ${fromGroup.findings.length} findings on ${fromGroup.package}`) : null,
    h("div", { class: `type-banner ${isKnownMalware(f) ? "mal" : f.category === "malicious_indicator" ? "sus" : "vuln"}` }, TYPE_LABEL(f)),
    h("h3", {}, f.title),
    h("div", { class: "row" }, h("span", { class: `sev ${f.severity}` }, f.severity),
      h("span", { class: "tag", title: "high = exact advisory match on the exact installed version; medium = correlated behaviour with a code location; low = a single, often benign signal" }, `confidence: ${f.confidence}`),
      h("span", { class: "tag" }, `source: ${srcLabel(f.source)}`),
      f.paths.length ? h("span", { class: "tag" }, direct ? "direct dependency" : "transitive dependency") : null,
      f.paths.length && f.paths.every((p) => p.dev_only) ? h("span", { class: "tag" }, "dev only") : null),
    h("p", { class: "mono muted small" }, `${f.package}@${f.version} · ${f.rule_or_advisory}`, f.aliases.length ? ` (${f.aliases.join(", ")})` : ""),
    h("dl", { class: "facts" },
      h("dt", {}, "Installed"), h("dd", { class: "mono" }, `${f.package}@${f.version}`),
      h("dt", {}, "Reaches your app"), h("dd", {}, f.paths.length ? `${routeText({ package: f.package, findings: [f] })}${isDevOnly(f) ? " (dev only: not shipped)" : ""}` : "path not recorded"),
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

const AI_VERDICT = {
  known_vulnerability_applies: ["The AI agrees this problem affects the version you have installed.", "bad"],
  consistent_with_malicious: ["The AI thinks this looks like real malicious behaviour.", "bad"],
  consistent_with_benign: ["The AI thinks this is probably harmless.", "ok"],
  insufficient_evidence: ["The AI says there is not enough evidence to tell either way.", "warn"],
  unclear: ["The AI could not reach a clear conclusion.", "warn"],
};
const plainCat = (c) => ({ known_vulnerability: "Known vulnerability", malicious_indicator: "Malware / suspicious code",
  repository_posture: "Repository posture", version_diff: "Version change" }[c] || c);
const tidy = (t) => String(t || "").replace(HEX_ID, "").replace(/\s{2,}/g, " ").trim();

async function explain(f, box, deep, independent) {
  box.replaceChildren(h("p", { class: "muted" }, deep ? "Running a deeper AI investigation… (up to a minute)" : "Asking the AI… (usually 10–30 seconds)"));
  try {
    const r = await post(`/api/scans/${scan.scan_id}/findings/${f.id}/explain`, { deep, independent });
    const ok = r.ai_status === "ok";
    const [verdict, tone] = AI_VERDICT[r.assessment] || [r.assessment, "warn"];
    const evLink = (ids) => ids.length ? h("a", { href: `#ev-${ids[0]}`, class: "cite", title: "Open the evidence this is based on",
      onclick: (e) => { e.preventDefault(); const d = document.querySelector("#detail details.fold:nth-of-type(2)"); if (d) d.open = true; document.getElementById(`ev-${ids[0]}`)?.scrollIntoView({ block: "center" }); } }, "evidence") : null;
    box.replaceChildren(h("div", { class: "explain" },
      h("div", { class: "explain-head" }, h("span", { class: "chip ai-chip" }, ok ? `🤖 AI explanation · ${r.model}` : "AI not available: plain summary from the scanner"),
        ok ? h("span", { class: "muted small" }, `AI confidence: ${r.confidence}`) : null),
      ok ? h("p", { class: `explain-verdict ${tone}` }, verdict) : null,
      r.observed ? h("div", {}, h("h5", {}, "What was found"), h("p", {}, tidy(r.observed))) : null,
      r.why_it_matters ? h("div", {}, h("h5", {}, "Why it matters"), h("p", {}, tidy(r.why_it_matters))) : null,
      r.claims.length ? h("div", {}, h("h5", {}, "Key points"), h("ul", { class: "answer-list" }, r.claims.map((c) => h("li", {}, tidy(c.text), " ", evLink(c.evidence_ids))))) : null,
      r.next_action ? h("div", { class: "action" }, h("b", {}, "What to do next: "), tidy(r.next_action)) : null,
      r.benign_explanations.length ? h("details", { class: "fold" }, h("summary", {}, "Could it be harmless?"),
        h("ul", {}, r.benign_explanations.map((x) => h("li", { class: "muted" }, tidy(x))))) : null,
      r.discarded_claims.length ? h("details", { class: "fold" }, h("summary", {}, `${plural(r.discarded_claims.length, "AI claim")} removed (no evidence to back it)`),
        h("ul", {}, r.discarded_claims.map((c) => h("li", { class: "muted" }, tidy(c.text))))) : null,
      r.slices?.length ? h("details", { class: "fold" }, h("summary", {}, `Code the AI was shown (${r.slices.length})`),
        r.slices.map((x) => h("pre", { class: "snippet" }, `${x.file}:${x.start}-${x.end}\n${x.code}`))) : null,
      (r.independent_assessments || []).length ? h("div", {}, h("h5", {}, "Second opinions"),
        r.independent_assessments.map((a) => h("div", { class: "row" }, h("span", { class: "chip" }, a.model),
          a.status === "ok" ? h("span", { class: `tag ${a.agrees_with_primary ? "ok" : "unavailable"}` }, a.agrees_with_primary ? "agrees" : "disagrees",
            ": ", (AI_VERDICT[a.assessment] || [a.assessment])[0].replace(/^The AI /, ""))
          : h("span", { class: "tag unavailable", title: a.error || "" }, a.status === "timeout" ? "took too long (free hosted model)" : "not available"))))
        : independent ? h("p", { class: "muted small" }, "No second-opinion model is configured on this server.") : null,
      h("p", { class: "muted small" }, `The scanner's result stays: ${plainCat(r.scanner_category)} · ${r.scanner_severity}. The AI explains it; it cannot change it.`)));
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
// Plain answer: a short paragraph, bullet lines as a list, ID codes kept out of the prose.
const HEX_ID = /\s*\((?:[0-9a-f]{12}(?:[,;\s]+)?)+\)/g;          // "(1271ff503cfb)" or "(a, b, c)"
function answerBody(text) {
  const clean = (t) => t.replace(HEX_ID, "").replace(/\s{2,}/g, " ").trim();
  // models sometimes put bullets inline (" - a - b"); split those into lines first
  const lines = text.replace(/\s+-\s+(?=[\w@][^\n]{0,80}?:)/g, "\n- ").split(/\n+/).map(clean).filter(Boolean);
  const out = [];
  let list = null;
  for (const line of lines) {
    if (/^[-•*]\s+/.test(line)) { (list ??= h("ul", { class: "answer-list" })).append(h("li", {}, line.replace(/^[-•*]\s+/, ""))); continue; }
    if (list) { out.push(list); list = null; }
    out.push(h("p", {}, line));
  }
  if (list) out.push(list);
  return out;
}
function showAnswer(r) {
  const byId = Object.fromEntries(scan.result.findings.map((f) => [f.id, f]));
  const cited = r.cited_finding_ids.map((id) => byId[id]).filter(Boolean);
  const groups = groupByPackage(cited);
  const chip = (g) => h("button", { class: "chip", onclick: () => openFinding(g.findings[0].id),
    title: g.findings.map((f) => f.title).join("\n") }, `${g.package} ${g.version}`, g.findings.length > 1 ? h("span", { class: "tab-n" }, g.findings.length) : null);
  const chips = h("div", { class: "row chips" }, groups.slice(0, 8).map(chip));
  if (groups.length > 8) chips.append(h("button", { class: "linklike small", onclick: (e) => { e.target.replaceWith(...groups.slice(8).map(chip)); } }, `+ ${groups.length - 8} more`));
  $("#answer").replaceChildren(h("div", { class: "answer" },
    r.transcript ? h("p", { class: "muted" }, `You asked: “${r.transcript}”`) : null,
    r.ai_status && r.ai_status !== "ok" ? h("p", { class: "warn" }, r.answer) : answerBody(r.answer || ""),
    groups.length ? h("div", { class: "sources" }, h("div", { class: "muted small" }, `Based on ${plural(cited.length, "finding")} in ${plural(groups.length, "package")} (click to open):`), chips) : null,
    h("p", { class: "muted small" }, "AI answer based only on this scan's findings. It never changes the scanner's results.")));
}
$("#ask-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#answer").replaceChildren(h("p", { class: "muted" }, "Thinking… (usually 5–20 seconds)"));
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
// The fix plan: remove known malware first, then the package upgrades that clear the most vulnerabilities.
function fixPlan(findings) {
  const steps = [];
  for (const g of groupByPackage(findings.filter(isKnownMalware)))
    steps.push({ kind: "remove", g, fixes: g.findings.length, label: `Remove ${g.package} ${g.version}`, note: "known malware" });
  for (const g of groupByPackage(findings.filter((f) => f.category === "known_vulnerability"))) {
    const fx = packageFix(g.findings);
    if (fx.target) steps.push({ kind: "upgrade", g, fx, fixes: fx.fixes, label: `Upgrade ${g.package} ${g.version} → ${fx.target}`,
      note: g.findings.some(isDirect) ? "direct dependency" : `comes in via ${viaOf(g.findings).join(", ")}` });
  }
  const sevRank = (st) => SEV_ORDER.indexOf(st.g.findings[0].severity);
  // malware removals, then anything critical, then the upgrades that fix the most
  const tier = (st) => (st.kind === "remove" ? 0 : st.g.findings[0].severity === "critical" ? 1 : 2);
  steps.sort((a, b) => tier(a) - tier(b) || b.fixes - a.fixes || sevRank(a) - sevRank(b));
  return steps;
}

async function renderVerdict() {
  const r = scan.result;
  const box = $("#verdict");
  const mal = r.findings.filter(isKnownMalware);
  const sus = r.findings.filter((f) => f.category === "malicious_indicator" && !isKnownMalware(f) && f.severity !== "info");
  const vulns = r.findings.filter((f) => f.category === "known_vulnerability");
  let g = scan.savedGate || null;
  if (!readOnly) { try { g = await api(`/api/scans/${encodeURIComponent(r.scan_id)}/gate`); scan.savedGate = g; saveLastScan(); } catch { /* shown as unknown */ } }
  const outcome = g?.outcome || "unknown";
  const badge = $("#nav-gate");
  badge.textContent = mal.length ? "malware" : outcome === "unknown" ? "" : outcome;
  badge.className = `badge b-${mal.length ? "fail" : outcome}`;
  const level = mal.length ? "critical" : outcome === "fail" ? "fail" : outcome === "pass" ? "pass" : "warn";
  const headline = mal.length ? `${plural(mal.length, "known malicious package")} in your project`
    : outcome === "fail" ? `${plural(g.blocking.length, "serious problem")} to fix before shipping`
    : outcome === "pass" ? "No serious problems found by these checks" : outcome === "incomplete" ? "Scan incomplete: a required check did not run" : "Results loaded";
  const sub = mal.length ? "Remove it first: it is a package already reported as malware."
    : outcome === "fail" ? "These are high or critical issues. The CI gate would block this build."
    : outcome === "pass" ? "Nothing at high or critical. That is not a guarantee of safety; see Scan details for what was checked."
    : "";
  const goto = (tab) => () => { activeCat = tab; render(); showView("findings"); };
  const pkgs = (list) => groupByPackage(list).length;
  box.className = `verdict card v-${level}`;
  box.replaceChildren(
    h("div", { class: "v-top" },
      h("div", { class: "v-main" },
        h("div", { class: "v-kicker" }, `CI gate: ${outcome === "unknown" ? "not available" : outcome.toUpperCase()}`),
        h("div", { class: "v-head" }, headline),
        sub ? h("div", { class: "muted" }, sub) : null),
      h("div", { class: "v-stats" },
        statBtn(mal.length, "known malware", "mal", goto("malware"), mal.length ? `in ${plural(pkgs(mal), "package")}` : "none found"),
        statBtn(vulns.length, "vulnerabilities", "vuln", goto("vuln"), vulns.length ? `in ${plural(pkgs(vulns), "package")}` : "none found"),
        statBtn(sus.length, "suspicious code", "sus", goto("suspicious"), sus.length ? `in ${plural(pkgs(sus), "package")}` : "none found"))));
  renderFixPlan();
  if (!readOnly) renderGate();
}
const statBtn = (n, label, cls, onclick, hint) => h("button", { type: "button", class: `v-stat ${cls} ${n ? "" : "zero"}`, onclick },
  h("b", {}, n), h("span", {}, label), h("small", { class: "muted" }, hint));

function renderFixPlan() {
  const r = scan.result;
  const box = $("#fix-plan");
  const vulnTotal = r.findings.filter((f) => f.category === "known_vulnerability").length;
  const steps = fixPlan(r.findings);
  if (!steps.length) {
    box.replaceChildren(h("h2", {}, "Fix plan"), h("p", { class: "muted" }, vulnTotal
      ? "None of the vulnerabilities has a published fixed version. Open Findings to review them."
      : "Nothing to fix from the checks that ran."));
    return;
  }
  const ups = steps.filter((x) => x.kind === "upgrade");
  const top = ups.slice(0, 3);
  const topFix = top.reduce((a, x) => a + x.fixes, 0), allFix = ups.reduce((a, x) => a + x.fixes, 0);
  const removes = steps.filter((x) => x.kind === "remove");
  const summary = [removes.length ? `Remove ${removes.map((x) => x.g.package).join(", ")} first.` : "",
    top.length ? `${plural(top.length, "upgrade")} (${top.map((x) => x.g.package).join(", ")}) fix ${topFix} of ${plural(vulnTotal, "vulnerability", "vulnerabilities")}`
      + (ups.length > top.length ? `; all ${ups.length} upgrades fix ${allFix}.` : ".") : ""].filter(Boolean).join(" ");
  box.replaceChildren(
    h("div", { class: "card-head" }, h("h2", {}, "Fix plan"), h("span", { class: "muted small" }, "based on the fixed versions in the advisories")),
    h("p", { class: "plan-sum" }, summary),
    h("ol", { class: "plan" }, steps.slice(0, 8).map((st) => h("li", { class: st.kind },
      h("button", { class: "plan-btn", onclick: () => { activeCat = st.kind === "remove" ? "malware" : "vuln"; render(); showPackage(st.g); showView("findings"); } },
        h("b", {}, st.label), st.fx?.major ? h("span", { class: "tag" }, "major version") : null,
        h("span", { class: "muted" }, ` · ${st.kind === "remove" ? st.note : `fixes ${plural(st.fixes, "vulnerability", "vulnerabilities")} · ${st.note}`}`))))),
    steps.length > 8 ? h("p", { class: "muted small" }, `+ ${steps.length - 8} more in Findings.`) : null,
    h("p", { class: "muted small" }, "Open a step, then Propose fix → Simulate fix and rescan to confirm it really works. Nothing is changed in your repository."));
}

// ---------- keep the last scan in this browser ----------
const LAST_KEY = "tracii:lastScan";
function saveLastScan() {
  if (!scan || readOnly) return;
  try { localStorage.setItem(LAST_KEY, JSON.stringify({ saved_at: Date.now(), scan })); }
  catch { /* storage full or disabled: the scan still works, it just is not kept */ }
}
function loadLastScan() {
  try { return JSON.parse(localStorage.getItem(LAST_KEY) || "null"); } catch { return null; }
}
async function openSaved(saved) {
  let live = null;
  try { live = await api(`/api/scans/${encodeURIComponent(saved.scan.scan_id)}`); } catch { /* server restarted */ }
  readOnly = !(live && live.status === "done");
  scan = readOnly ? saved.scan : { ...live, savedGate: saved.scan.savedGate };
  activeCat = firstTab(scan.result.findings);
  $("#results").classList.remove("hidden");
  enableScanViews();
  render();
  renderVerdict();
  renderImpactMap(scan, { onOpen: openFinding });
  if (!readOnly) initGraph(scan, { onOpenFinding: openFinding });
  $("#saved-banner")?.remove();
  if (readOnly) $("#view-overview").prepend(h("div", { id: "saved-banner", class: "card saved-banner" },
    h("b", {}, `Saved result from ${new Date(saved.saved_at).toLocaleString()}. `),
    "The server has restarted since, so exports, AI explanations, fixes and the 3D view need a fresh scan. ",
    rerunButton(scan.result.source)));
  showView("overview");
}
function rerunButton(src) {
  if (src.kind === "fixture") return h("button", { class: "sm", onclick: () => { readOnly = false; start(() => post("/api/scan/fixture", { name: src.label })); showView("scan"); } }, "Re-run this scan");
  if (src.kind === "github") return h("button", { class: "sm", onclick: () => { readOnly = false; start(() => post("/api/scan/github", { url: `https://github.com/${src.label}${src.ref ? "/tree/" + src.ref : ""}`, subdir: src.subdir || "" })); showView("scan"); } }, "Re-run this scan");
  return h("span", { class: "muted" }, "Upload the files again on New scan to refresh it.");
}
function renderLastScanCard() {
  const saved = loadLastScan();
  $("#last-scan")?.remove();
  if (!saved?.scan?.result || scan) return;
  const src = saved.scan.result.source;
  $("#intake").before(h("div", { id: "last-scan", class: "card last-scan" },
    h("div", {}, h("b", {}, "Your last scan: "), `${src.kind === "fixture" ? "demo " : ""}${src.label}`,
      h("span", { class: "muted" }, ` · ${new Date(saved.saved_at).toLocaleString()}`)),
    h("div", { class: "row" }, h("button", { class: "sm", onclick: () => openSaved(saved) }, "Open"),
      h("button", { class: "ghost sm", onclick: () => { localStorage.removeItem(LAST_KEY); $("#last-scan").remove(); } }, "Forget"))));
}
renderLastScanCard();

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
    h("h3", {}, "About TRACII"),
    h("p", {}, "TRACII checks npm projects for known vulnerabilities, known malware and suspicious package code, shows how each risk reaches your app and proposes fixes you can verify by rescanning."),
    h("h4", {}, "AI models and their status"),
    h("p", { class: "muted" }, "Scanners decide; AI models explain. Each model only sees the scanner's evidence and must cite it. Without credentials every AI feature falls back to a plain summary."),
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
