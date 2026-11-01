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
// Malicious-indicator findings come from two very different sources; never present a heuristic as confirmed malware.
const isKnownMalware = (f) => f.category === "malicious_indicator" && /^MAL-/.test(f.rule_or_advisory);
const TYPE_LABEL = (f) => f.category === "known_vulnerability" ? "Known vulnerability (advisory)"
  : isKnownMalware(f) ? "Known malicious package (OSV MAL- record)"
  : f.category === "malicious_indicator" ? "Suspicious behaviour (heuristic indicator, not confirmed malware)"
  : CAT_LABEL[f.category];
let scan = null;
let activeCat = "known_vulnerability";

// ---------- intake ----------
document.querySelectorAll("#intake .tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("#intake .tabs button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll("#intake .tab-panel").forEach((p) => p.classList.toggle("hidden", p.id !== `form-${b.dataset.tab}`));
}));

document.querySelectorAll("[data-example]").forEach((b) => b.addEventListener("click", () => {
  $("#form-github [name=url]").value = b.dataset.example;
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
      render();
      renderVerdict();
      $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
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
  const base = `${window.TRACII_API}/api/scans/${encodeURIComponent(r.scan_id)}`;
  $("#exports").replaceChildren(h("span", { class: "muted" }, "Export"),
    h("a", { class: "btn", href: `${base}/sbom`, download: `tracii-${r.scan_id}.cdx.json`, title: "CycloneDX 1.5 JSON: every name@version with purl, hash, scope and the OSV advisories" }, "SBOM · CycloneDX"),
    h("a", { class: "btn", href: `${base}/sarif`, download: `tracii-${r.scan_id}.sarif`, title: "SARIF 2.1.0 for GitHub code scanning; each result points at package-lock.json" }, "SARIF"),
    h("button", { class: "btn", type: "button", onclick: downloadGateReport, title: "Markdown report from the CI gate policy (fail on high)" }, "CI gate report"));
  $("#checks").replaceChildren(...r.checks.map((c) =>
    h("li", { class: `check ${c.status}` }, h("b", {}, c.name), ` ${c.status}`, c.packages_checked ? ` · ${c.packages_checked} pkgs` : "", h("div", { class: "muted" }, c.detail))));
  $("#warnings").replaceChildren(...r.inventory.warnings.map((w) => h("div", { class: "warn" }, "⚠ " + w)));

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
      onclick: () => { activeCat = cat; render(); $("#findings").scrollIntoView({ behavior: "smooth", block: "center" }); } },
      h("div", { class: "sum-n" }, list.length), h("div", { class: "sum-l" }, label),
      h("div", { class: "sevs" }, SEV_ORDER.filter((s) => c[s]).map((s) => h("span", { class: `sev ${s}` }, `${c[s]} ${s}`))),
      h("div", { class: "muted" }, list.length ? help : "No issue detected by these checks."));
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
    h("td", { class: "mono" }, `${f.package}@${f.version}`, isKnownMalware(f) ? h("span", { class: "tag malware" }, "known malware") : null),
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
  const direct = f.paths.some((p) => p.nodes.length === 2);
  d.replaceChildren(
    h("div", { class: `type-banner ${isKnownMalware(f) ? "mal" : f.category === "malicious_indicator" ? "sus" : "vuln"}` }, TYPE_LABEL(f)),
    h("h3", {}, f.title),
    h("div", { class: "row" }, h("span", { class: `sev ${f.severity}` }, f.severity),
      h("span", { class: "tag" }, `confidence: ${f.confidence}`), h("span", { class: "tag" }, `source: ${f.source}`),
      f.paths.length ? h("span", { class: "tag" }, direct ? "direct dependency" : "transitive dependency") : null,
      f.paths.length && f.paths.every((p) => p.dev_only) ? h("span", { class: "tag" }, "dev only") : null),
    h("p", { class: "mono" }, `${f.package}@${f.version} · ${f.rule_or_advisory}`, f.aliases.length ? ` (${f.aliases.join(", ")})` : ""),
    f.category === "known_vulnerability"
      ? h("p", {}, h("b", {}, "Fixed in: "), f.fixed_versions.length ? f.fixed_versions.join(", ") : h("span", { class: "warn" }, "no fixed version published"))
      : isKnownMalware(f) ? h("p", { class: "error" }, h("b", {}, "Action: "), "remove this version from your dependency tree. Only replace it with a version outside the affected range in the OSV record above, and treat any secrets on machines that installed it as exposed.") : null,
    h("h4", {}, "Evidence"), evidenceList(f),
    h("h4", {}, "Impact path"), pathView(f),
    h("button", { class: "ghost", onclick: (e) => { if (!focusPackage(`${f.package}@${f.version}`)) e.target.textContent = "Not drawn in the 3D view"; } }, "Show in 3D graph"),
    h("h4", {}, "Unknowns / limitations"), h("ul", {}, f.limitations.map((l) => h("li", { class: "muted" }, l))),
    h("h4", {}, "AI investigation"),
    h("p", { class: "muted" }, "Model output is an assessment, not a finding. Every claim must cite the evidence IDs above; uncited claims are discarded and the scanner verdict is never changed."),
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

// ---------- verdict + gate report ----------
async function renderVerdict() {
  const r = scan.result;
  const box = $("#verdict");
  const mal = r.findings.filter(isKnownMalware);
  const sus = r.findings.filter((f) => f.category === "malicious_indicator" && !isKnownMalware(f) && !["info", "low"].includes(f.severity));
  const vulns = r.findings.filter((f) => f.category === "known_vulnerability");
  const top = r.findings.filter((f) => f.severity !== "info").map((f) => f.severity).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0] || "none";
  const direct = r.inventory.packages.filter((p) => p.direct).length;
  let gateOut = null;
  try { gateOut = await api(`/api/scans/${encodeURIComponent(r.scan_id)}/gate`); } catch { /* shown as unknown */ }
  const outcome = gateOut?.outcome || "unknown";
  const level = mal.length ? "critical" : outcome === "fail" ? "fail" : outcome === "pass" ? "pass" : "warn";
  const headline = mal.length ? `${mal.length} known malicious package${mal.length > 1 ? "s" : ""} in your dependency tree`
    : outcome === "fail" ? `${gateOut.blocking.length} blocking finding${gateOut.blocking.length === 1 ? "" : "s"} at severity high or above`
    : outcome === "pass" ? "No blocking findings from these checks" : "Scan incomplete: some checks could not run";
  box.className = `verdict card v-${level}`;
  box.replaceChildren(
    h("div", { class: "v-main" },
      h("div", { class: "v-kicker" }, `CI gate (fail on high): ${outcome.toUpperCase()}`),
      h("div", { class: "v-head" }, headline),
      h("div", { class: "muted" }, `${r.source.kind === "fixture" ? "Demo project" : r.source.kind}: ${r.source.label} · highest severity: ${top} · deterministic scanner verdict, no AI involved`)),
    h("div", { class: "v-stats" },
      stat(mal.length, "known malware", "mal"), stat(vulns.length, "vulnerabilities", "vuln"), stat(sus.length, "suspicious (medium+)", "sus"),
      stat(r.inventory.packages.length, `packages · ${direct} direct`, "")));
}
const stat = (n, label, cls) => h("div", { class: `v-stat ${cls}` }, h("b", {}, n), h("span", {}, label));

async function downloadGateReport() {
  try {
    const g = await api(`/api/scans/${encodeURIComponent(scan.scan_id)}/gate`);
    const a = h("a", { href: URL.createObjectURL(new Blob([g.markdown], { type: "text/markdown" })), download: `tracii-${scan.scan_id}-gate.md` });
    document.body.append(a); a.click(); a.remove();
  } catch (err) { alert(`Gate report failed: ${err.message}`); }
}

// ---------- model intelligence ----------
const STATUS_TEXT = { verified: "connected", failed: "failed", configured: "configured · not yet called", not_configured: "not configured" };
const ROLE_NAME = { investigator: "Muse Spark", deep: "Muse Wonder", image: "Muse Image", voice: "Muse Voice Transcribe", segment: "SAM 3.1",
  independent_glimmer: "Muse Glimmer", independent_spark_open: "Muse Spark Open", dev_agent: "Muse Code" };

function modelRows(rows, checks = []) {
  const byRole = Object.fromEntries(checks.map((c) => [c.role, c]));
  return h("div", { class: "models" }, rows.map((r) => {
    const c = byRole[r.role];
    const st = r.role === "dev_agent" ? "dev" : r.status;
    return h("div", { class: `model m-${st}` },
      h("div", { class: "row" }, h("b", {}, ROLE_NAME[r.role] || r.role), h("span", { class: "mono muted" }, r.model),
        h("span", { class: `tag ${st}` }, r.role === "dev_agent" ? "development-time only" : STATUS_TEXT[r.status] || r.status),
        c?.ok ? h("span", { class: "muted" }, `${c.latency_s}s`) : null),
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
