// Tracii frontend: no build step. All package-derived text is untrusted and is
// rendered with textContent only (never innerHTML).
import { $, h, api, post } from "./ui.js";
import { initGraph, focusPackage } from "./graph3d.js";
import { runAgents } from "./agents-view.js";

const SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];
const CAT_LABEL = {
  known_vulnerability: "Known vulnerabilities",
  malicious_indicator: "Malicious-behaviour indicators",
  repository_posture: "Repository posture",
  version_diff: "Version diff",
};
let scan = null;
let activeCat = "known_vulnerability";

// ---------- intake ----------
document.querySelectorAll("#intake .tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("#intake .tabs button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll("#intake .tab-panel").forEach((p) => p.classList.toggle("hidden", p.id !== `form-${b.dataset.tab}`));
}));

api("/api/fixtures").then((names) => names.forEach((n) => $("#fixture-select").append(h("option", { value: n }, n)))).catch(() => {});

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
  prog.classList.remove("hidden");
  prog.replaceChildren(h("div", {}, "Starting scan…"));
  try {
    const { scan_id } = await kickoff();
    await poll(scan_id);
  } catch (err) {
    prog.replaceChildren(h("div", { class: "error" }, `Scan failed: ${err.message}`));
  }
}

async function poll(id) {
  const prog = $("#progress");
  for (;;) {
    const s = await api(`/api/scans/${id}`);
    prog.replaceChildren(...s.progress.map((p) => h("div", {}, "✓ " + p)));
    if (s.status === "done") {
      scan = s;
      render();
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
    ` · ${r.inventory.packages.length} packages · lockfile v${r.inventory.lockfile_version}`;
  $("#checks").replaceChildren(...r.checks.map((c) =>
    h("li", { class: `check ${c.status}` }, h("b", {}, c.name), ` ${c.status}`, c.packages_checked ? ` · ${c.packages_checked} pkgs` : "", h("div", { class: "muted" }, c.detail))));
  $("#warnings").replaceChildren(...r.inventory.warnings.map((w) => h("div", { class: "warn" }, "⚠ " + w)));

  const counts = scan.summary.by_category;
  $("#summary").replaceChildren(...Object.keys(CAT_LABEL).map((cat) => {
    const c = counts[cat] || {};
    const total = Object.values(c).reduce((a, b) => a + b, 0);
    return h("div", { class: "sum-card" }, h("div", { class: "sum-n" }, total), h("div", {}, CAT_LABEL[cat]),
      h("div", { class: "sevs" }, SEV_ORDER.filter((s) => c[s]).map((s) => h("span", { class: `sev ${s}` }, `${c[s]} ${s}`))),
      total === 0 ? h("div", { class: "muted" }, "no issue detected by these checks") : null);
  }));

  $("#cat-tabs").replaceChildren(...Object.keys(CAT_LABEL).map((cat) =>
    h("button", { class: cat === activeCat ? "active" : "", onclick: () => { activeCat = cat; render(); } }, CAT_LABEL[cat])));
  renderTable();
}

function renderTable() {
  const q = $("#filter").value.trim().toLowerCase();
  const rows = scan.result.findings
    .filter((f) => f.category === activeCat && (!q || f.package.includes(q)))
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  $("#findings tbody").replaceChildren(...(rows.length ? rows.map((f) => h("tr", { onclick: () => showDetail(f) },
    h("td", {}, h("span", { class: `sev ${f.severity}` }, f.severity)),
    h("td", { class: "mono" }, `${f.package}@${f.version}`),
    h("td", { class: "mono" }, f.rule_or_advisory),
    h("td", {}, f.source),
    h("td", { class: "muted" }, f.paths[0] ? (f.paths[0].dev_only ? "dev · " : "") + f.paths[0].direct_dependency : "—"),
  )) : [h("tr", {}, h("td", { colspan: 5, class: "muted" }, "No findings in this category from the checks that ran."))]));
}
$("#filter").addEventListener("input", () => scan && renderTable());

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
  $("#detail").scrollIntoView({ behavior: "smooth", block: "start" });
}

function showDetail(f) {
  const d = $("#detail");
  const aiBox = h("div", { class: "ai" });
  const fixBox = h("div", { class: "fix" });
  const agentBox = h("div", { class: "ai" });
  const mission = h("select", { title: "SSVC Mission & Well-being impact: how much harm a compromise of this app would do. Your call; Tracii cannot know it." },
    ["low", "medium", "high"].map((v) => h("option", { value: v, selected: v === "medium" }, `mission impact: ${v}`)));
  d.replaceChildren(
    h("h3", {}, f.title),
    h("div", { class: "row" }, h("span", { class: `sev ${f.severity}` }, f.severity), h("span", { class: "tag" }, CAT_LABEL[f.category]),
      h("span", { class: "tag" }, `confidence: ${f.confidence}`), h("span", { class: "tag" }, `source: ${f.source}`)),
    h("p", { class: "mono" }, `${f.package}@${f.version} · ${f.rule_or_advisory}`, f.aliases.length ? ` (${f.aliases.join(", ")})` : ""),
    h("h4", {}, "Evidence"), evidenceList(f),
    h("h4", {}, "Impact path"), pathView(f),
    h("button", { class: "ghost", onclick: (e) => { if (!focusPackage(`${f.package}@${f.version}`)) e.target.textContent = "Not drawn in the 3D view"; } }, "Show in 3D graph"),
    h("h4", {}, "Unknowns / limitations"), h("ul", {}, f.limitations.map((l) => h("li", { class: "muted" }, l))),
    h("h4", {}, "AI investigation"),
    h("div", { class: "row" },
      h("button", { onclick: () => explain(f, aiBox, false, false) }, "Explain with evidence"),
      h("button", { class: "ghost", onclick: () => explain(f, aiBox, true, false) }, "Deep investigation (Wonder)"),
      h("button", { class: "ghost", onclick: () => explain(f, aiBox, false, true) }, "+ independent assessment")),
    aiBox,
    h("h4", {}, "Multi-agent investigation"),
    h("p", { class: "muted" }, "Methodology agents (SSVC + EPSS + KEV, MITRE ATT&CK, SLSA provenance + OpenSSF Scorecard, STRIDE) run in parallel; a judge reconciles them and Spark Open reviews independently."),
    h("div", { class: "row" }, h("button", { onclick: () => runAgents(scan.scan_id, f, agentBox, mission.value) }, "Run investigation agents"), mission),
    agentBox,
    h("h4", {}, "Next step"),
    h("div", { class: "row" }, h("button", { onclick: () => proposeFix(f, fixBox) }, "Propose fix")),
    fixBox,
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
        r.independent_assessments.map((a) => h("div", { class: "tag" }, `${a.assessor} (${a.model}): ${a.status === "ok" ? a.assessment + (a.agrees_with_primary ? " · agrees" : " · disagrees") : a.status}`)))
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
    out.replaceChildren(
      h("p", { class: "muted" }, r.note),
      kv("Install scripts added/changed", r.install_scripts_added_or_changed), kv("Hosts added", r.hosts_added),
      kv("Capabilities added", Object.keys(r.capabilities_added)), kv("Dependencies added", r.dependencies_added),
      kv("Files added", r.files_added.slice(0, 40)),
      h("ul", {}, r.findings.map((x) => h("li", {}, h("span", { class: `sev ${x.severity}` }, x.severity), " ", x.title,
        h("ul", {}, x.evidence.map((ev) => h("li", { class: "mono muted" }, `${ev.summary}${ev.file ? " " + ev.file + (ev.line ? ":" + ev.line : "") : ""}`)))))));
  } catch (err) { out.textContent = err.message; }
});

// ---------- model status ----------
$("#models-btn").addEventListener("click", async () => {
  const rows = await api("/api/models/status");
  $("#models-body").replaceChildren(h("h3", {}, "Model integrations"), h("table", {},
    h("tr", {}, ["Role", "Model", "Feature", "Status"].map((x) => h("th", {}, x))),
    rows.map((r) => h("tr", {}, h("td", {}, r.role), h("td", { class: "mono" }, r.model), h("td", {}, r.feature), h("td", {}, h("span", { class: `tag ${r.status}` }, r.status))))),
    h("p", { class: "muted" }, "“verified” only appears after a real call succeeds in this server process."));
  $("#models-dialog").showModal();
});
