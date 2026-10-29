// 3D dependency graph of the scanned project + attack replays on top of it.
// Node colour = what the scanners found (categories never merged); node size = how
// many packages in this project depend on it (blast radius inside the project).
import { $, h, api, post, attackUrl } from "./ui.js";

const LIB = "https://cdn.jsdelivr.net/npm/3d-force-graph@1.80.1/dist/3d-force-graph.min.js";
const SEV = ["critical", "high", "medium", "low", "info", "unknown"];
const STAGE_MS = 1900;
const WAVE_MS = 650;
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

let libPromise = null;
function loadLib() {
  libPromise ??= new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = LIB;
    s.onload = () => (window.ForceGraph3D ? resolve(window.ForceGraph3D) : reject(new Error("3D library did not load")));
    s.onerror = () => reject(new Error("could not load the 3D library from cdn.jsdelivr.net"));
    document.head.append(s);
  });
  return libPromise;
}

const G = {
  fg: null, scanId: null, raw: null, parents: new Map(), byId: new Map(), onOpenFinding: null,
  flaggedOnly: false, hlNodes: new Set(), hlLinks: new Set(), wave: new Set(), targets: new Set(),
  ghost: null, timers: [],
};

// info-level indicators (e.g. "has an install script") are context, not behaviour: not coloured as malicious
const significant = (list) => (list || []).filter((f) => f.severity !== "info");
const worst = (list) => list.map((f) => f.severity).sort((a, b) => SEV.indexOf(a) - SEV.indexOf(b))[0];
const linkKey = (l) => `${l.source.id ?? l.source}>${l.target.id ?? l.target}`;

function ancestors(id) {
  const seen = new Set([id]);
  const stack = [id];
  while (stack.length) for (const p of G.parents.get(stack.pop()) || []) if (!seen.has(p)) { seen.add(p); stack.push(p); }
  return seen;
}

function nodeColor(n) {
  if (n.ghost || G.targets.has(n.id)) return css(n.ghost ? "--g-ghost" : "--g-target");
  if (G.wave.has(n.id)) return css("--g-wave");
  if (G.hlNodes.size && !G.hlNodes.has(n.id)) return css("--g-dim");
  if (n.app) return css("--accent");
  if (significant(n.findings?.malicious_indicator).length) return css("--g-mal");
  if (n.findings?.known_vulnerability) return css({ critical: "--crit", high: "--high", medium: "--med", low: "--low" }[worst(n.findings.known_vulnerability)] || "--info");
  return css(n.dev_only ? "--g-dev" : "--g-clean");
}
const nodeVal = (n) => (n.app ? 14 : n.ghost ? 8 : 1 + Math.min(n.dependents || 0, 30) / 3 + (Object.values(n.findings || {}).some((l) => significant(l).length) ? 3 : 0) + (G.targets.has(n.id) ? 6 : 0));
const linkOn = (l) => G.hlLinks.has(linkKey(l));
function nodeLabel(n) {
  if (n.app) return "your app";
  if (n.ghost) return `<b>${esc(n.label)}</b><br>${esc(n.note)}`;
  const f = n.findings || {};
  const bits = [n.direct ? "direct" : "transitive", n.dev_only ? "dev only" : "production", `${n.dependents} dependents in this project`];
  if (n.install_script) bits.push("has install script");
  const fl = Object.entries(f).map(([cat, l]) => `${l.length} ${cat.replace("_", " ")} (${worst(l)})`);
  return `<b>${esc(n.label)}</b><br>${esc(bits.join(" · "))}${fl.length ? "<br>" + esc(fl.join(", ")) : ""}`;
}

function visibleData() {
  const { nodes, edges } = G.raw;
  let keep = null;
  if (G.flaggedOnly) {
    keep = new Set([G.raw.app]);
    for (const n of nodes) if (Object.values(n.findings || {}).some((l) => significant(l).length)) for (const a of ancestors(n.id)) keep.add(a);
  }
  const ns = nodes.filter((n) => !keep || keep.has(n.id)).map((n) => ({ ...n }));
  const ls = edges.filter((e) => !keep || (keep.has(e.source) && keep.has(e.target))).map((e) => ({ ...e }));
  if (G.ghost) { ns.push({ ...G.ghost.node }); ls.push({ ...G.ghost.link }); }
  return { nodes: ns, links: ls };
}

function refresh() {
  if (!G.fg) return;
  G.fg.nodeColor(nodeColor).nodeVal(nodeVal)
    .linkColor((l) => css(linkOn(l) ? "--g-hl" : "--g-link")).linkWidth((l) => (linkOn(l) ? 1.6 : 0.3))
    .linkDirectionalParticles((l) => (linkOn(l) ? 3 : 0));
}

function highlightAncestors(id) {
  G.hlNodes = ancestors(id);
  G.hlLinks = new Set(G.raw.edges.filter((e) => G.hlNodes.has(e.source) && G.hlNodes.has(e.target)).map(linkKey));
  refresh();
}

function showNodeInfo(n) {
  const box = $("#graph-info");
  if (!n || n.app || n.ghost) { box.replaceChildren(h("p", { class: "muted" }, n?.ghost ? n.note : "Your app: the root of every path.")); return; }
  const findings = Object.values(n.findings || {}).flat();
  box.replaceChildren(
    h("h3", { class: "mono" }, n.label),
    h("div", { class: "row" }, h("span", { class: "tag" }, n.direct ? "direct" : "transitive"), h("span", { class: "tag" }, n.dev_only ? "dev only" : "production"),
      h("span", { class: "tag" }, `${n.dependents} dependents`), n.install_script ? h("span", { class: "tag" }, "install script") : null),
    findings.length ? h("ul", {}, findings.map((f) => h("li", {}, h("span", { class: `sev ${f.severity}` }, f.severity), " ",
      h("button", { class: "linklike mono", onclick: () => G.onOpenFinding?.(f.id) }, f.rule)))) : h("p", { class: "muted" }, "No finding on this package from the checks that ran."),
    h("p", { class: "muted" }, "Highlighted: every package above it, up to your app."));
}

function focus(n) {
  highlightAncestors(n.id);
  showNodeInfo(n);
  const d = 90 / Math.hypot(n.x || 1, n.y || 1, n.z || 1);
  G.fg.cameraPosition({ x: (n.x || 0) * (1 + d), y: (n.y || 0) * (1 + d), z: (n.z || 0) * (1 + d) }, n, 900);
}

export function focusPackage(label) {
  const n = G.fg?.graphData().nodes.find((x) => x.label === label);
  if (!n) return false;
  $("#graph-card").scrollIntoView({ behavior: "smooth", block: "start" });
  focus(n);
  return true;
}

export async function initGraph(scan, { onOpenFinding }) {
  G.onOpenFinding = onOpenFinding;
  G.scanId = scan.scan_id;
  stopReplay(true);
  const el = $("#graph3d");
  el.replaceChildren(h("p", { class: "muted pad" }, "Loading 3D view…"));
  try {
    const [ForceGraph3D, raw] = await Promise.all([loadLib(), api(`/api/scans/${scan.scan_id}/graph`)]);
    G.raw = raw;
    G.parents = new Map();
    for (const e of raw.edges) (G.parents.get(e.target) || G.parents.set(e.target, []).get(e.target)).push(e.source);
    G.flaggedOnly = raw.nodes.length > 600;
    $("#graph-flagged").checked = G.flaggedOnly;
    el.replaceChildren();
    G.fg?._destructor?.();
    G.fg = ForceGraph3D()(el)
      .backgroundColor(css("--g-bg")).width(el.clientWidth).height(el.clientHeight)
      .nodeId("id").nodeLabel(nodeLabel).nodeOpacity(0.95).nodeResolution(12)
      .linkDirectionalArrowLength(2.5).linkDirectionalArrowRelPos(1).linkDirectionalParticleWidth(2)
      .onNodeClick(focus)
      .onBackgroundClick(() => { G.hlNodes.clear(); G.hlLinks.clear(); refresh(); showNodeInfo(null); })
      .cooldownTicks(120)
      .graphData(visibleData());
    let fitted = false;
    G.fg.onEngineStop(() => { if (!fitted) { fitted = true; G.fg.zoomToFit(600, 30); } });
    refresh();
    new ResizeObserver(() => G.fg?.width(el.clientWidth)).observe(el);
    $("#graph-stats").textContent = `${raw.nodes.length - 1} packages · ${raw.edges.length} edges` + (G.flaggedOnly ? " · large graph: showing paths to findings only" : "");
  } catch (err) {
    el.replaceChildren(h("p", { class: "error pad" }, `3D view unavailable: ${err.message}. The findings table and impact paths below still work.`));
  }
}

$("#graph-flagged").addEventListener("change", (e) => {
  G.flaggedOnly = e.target.checked;
  if (G.fg) { G.fg.graphData(visibleData()); refresh(); }
});

// ---------- attack replays ----------

api("/api/replays").then((list) => $("#replay-select").replaceChildren(
  ...list.map((s) => h("option", { value: s.id }, s.title)))).catch(() => {});

function stopReplay(clearGraph) {
  G.timers.forEach(clearTimeout);
  G.timers = [];
  if (clearGraph) {
    G.ghost = null; G.wave.clear(); G.targets.clear(); G.hlNodes.clear(); G.hlLinks.clear();
    if (G.fg) { G.fg.graphData(visibleData()); refresh(); }
    $("#replay-out").replaceChildren();
  }
}
$("#replay-reset").addEventListener("click", () => stopReplay(true));

const RESULT_LABEL = { measured: "measured", by_rule_design: "by rule design (not run)", uncertain: "uncertain", not_detected: "not detected" };

function timeline(r) {
  const s = r.scenario;
  const t0 = r.targets[0];
  return h("div", {},
    h("div", { class: `replay-note ${r.mode}` }, r.note),
    t0 ? h("p", {}, h("b", {}, `${t0.label}: `), `${t0.affected_packages} package(s) above it`,
      t0.affected_direct.length ? ` · reaches your app through ${t0.affected_direct.join(", ")}` : "",
      t0.dev_only ? " · dev-only path" : "") : null,
    h("ol", { class: "timeline" }, s.steps.map((st, i) => h("li", { id: `step-${i}` },
      h("div", { class: "row" }, h("span", { class: "tag" }, st.date), h("span", { class: `tag stage-${st.stage}` }, st.stage),
        st.techniques.map((t) => h("a", { class: "tag", href: attackUrl(t), target: "_blank", rel: "noopener noreferrer" }, t))),
      h("div", {}, st.text),
      h("div", { class: "muted" }, "Sources: ", st.sources.map((u, j) => [j ? " · " : "", h("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, new URL(u).hostname + "↗")]))))),
    h("h4", {}, "Would Tracii have caught it?"),
    h("ul", {}, s.detection.map((d) => h("li", {}, h("span", { class: `tag det-${d.result}` }, RESULT_LABEL[d.result]), " ", h("b", {}, d.check + ": "), d.text))),
    h("p", { class: "muted" }, "Advisories: ", s.advisories.map((a, j) => [j ? ", " : "", h("a", { href: `https://osv.dev/vulnerability/${a}`, target: "_blank", rel: "noopener noreferrer" }, a)])));
}

function activate(i) {
  document.querySelectorAll(".timeline li").forEach((li, j) => li.classList.toggle("active", j === i));
  document.getElementById(`step-${i}`)?.scrollIntoView({ block: "nearest" });
}

$("#replay-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!G.scanId) return;
  stopReplay(true);
  const out = $("#replay-out");
  out.replaceChildren(h("p", { class: "muted" }, "Loading replay…"));
  let r;
  try { r = await post(`/api/scans/${G.scanId}/replays/${$("#replay-select").value}`); }
  catch (err) { out.replaceChildren(h("p", { class: "error" }, err.message)); return; }
  out.replaceChildren(timeline(r));
  const t = r.targets[0];
  if (!t || !G.fg) return;
  // make sure the target and its dependents are drawn even in "paths to findings" mode
  if (G.flaggedOnly) { G.flaggedOnly = false; $("#graph-flagged").checked = false; }
  let at = 0;
  r.scenario.steps.forEach((st, i) => {
    G.timers.push(setTimeout(() => {
      activate(i);
      if (st.stage === "inject") {
        G.targets = new Set([t.id]);
        if (r.injected) {
          const id = `ghost:${r.injected.package}`;
          G.ghost = { node: { id, ghost: true, label: `${r.injected.package}@${r.injected.version}`,
                              note: r.mode === "simulated" ? "Simulated injected dependency (historical name)" : "Injected dependency from the historical attack (not in your lockfile)" },
                      link: { source: t.id, target: id } };
        }
        G.fg.graphData(visibleData());
        refresh();
        const n = G.fg.graphData().nodes.find((x) => x.id === t.id);
        if (n) setTimeout(() => focus(n), 400);
      } else if (st.stage === "spread" || (st.stage === "payload" && !r.scenario.steps.some((x) => x.stage === "spread"))) {
        t.waves.forEach((w, k) => G.timers.push(setTimeout(() => {
          w.forEach((id) => G.wave.add(id));
          G.hlNodes = new Set([t.id, ...G.wave]);
          G.hlLinks = new Set(G.raw.edges.filter((ed) => G.hlNodes.has(ed.source) && G.hlNodes.has(ed.target)).map(linkKey));
          refresh();
        }, k * WAVE_MS)));
      }
    }, at));
    at += STAGE_MS + (st.stage === "spread" ? t.waves.length * WAVE_MS : 0);
  });
  // scenarios without a spread step still show the blast radius at the end
  G.timers.push(setTimeout(() => {
    if (!G.wave.size) t.waves.flat().forEach((id) => G.wave.add(id));
    G.hlNodes = new Set([t.id, ...G.wave]);
    G.hlLinks = new Set(G.raw.edges.filter((ed) => G.hlNodes.has(ed.source) && G.hlNodes.has(ed.target)).map(linkKey));
    refresh();
  }, at));
});
