// Multi-agent investigation panel: one card per methodology agent, then the judge
// and the open-weight reviewer. Every claim links to an evidence item by ID.
import { h, api, post, attackUrl } from "./ui.js";

const PRIORITY_LABEL = { act_now: "act now", attend: "attend", track: "track", insufficient_evidence: "insufficient evidence" };

const cites = (ids) => ids.map((id) => h("a", { href: `#ev-${id}`, class: "cite" }, `[${id.split("-").slice(1).join("-")}]`));
const claimList = (claims) => (claims.length ? h("ul", {}, claims.map((c) => h("li", {}, c.text, " ", cites(c.evidence_ids)))) : null);
const discarded = (list) => (list.length ? h("details", {}, h("summary", { class: "muted" }, `${list.length} ungrounded item(s) discarded`),
  h("ul", {}, list.map((c) => h("li", { class: "muted" }, c.text)))) : null);

function ssvcView(a) {
  const s = a.ssvc;
  const row = (k, label) => {
    const dp = a.method[k] || {};
    return h("tr", {}, h("td", {}, label), h("td", { class: "mono" }, dp.value ?? "open (not established)"), h("td", {}, cites(dp.evidence_ids || [])));
  };
  return h("div", {},
    h("table", { class: "mini" }, h("tr", {}, h("th", {}, "SSVC decision point"), h("th", {}, "Value"), h("th", {}, "Evidence")),
      row("exploitation", "Exploitation"), row("automatable", "Automatable"), row("technical_impact", "Technical impact"),
      h("tr", {}, h("td", {}, "Mission & well-being"), h("td", { class: "mono" }, s.inputs.mission_impact), h("td", { class: "muted" }, "your input"))),
    h("p", {}, h("b", {}, "SSVC outcome: "), h("span", { class: `tag ssvc-${s.decision.replace("*", "s")}` }, s.decision),
      s.settled ? "" : ` (range ${s.range.join(" → ")}; open decision points could change it)`,
      h("span", { class: "muted" }, ` · computed by Tracii from the ${s.table}, not chosen by the model`)));
}

function methodView(a) {
  if (a.agent === "vuln_triage") return ssvcView(a);
  if (a.agent === "attack_mapping") return a.method.techniques.length
    ? h("ul", {}, a.method.techniques.map((t) => h("li", {}, h("a", { href: attackUrl(t.technique_id), target: "_blank", rel: "noopener noreferrer", class: "tag" }, t.technique_id),
      ` ${t.name}: ${t.rationale} `, cites(t.evidence_ids))))
    : h("p", { class: "muted" }, "No technique supported by the evidence.");
  if (a.agent === "integrity") return a.method.controls.length
    ? h("ul", {}, a.method.controls.map((c) => h("li", {}, h("span", { class: `tag ctl-${c.status}` }, c.status), ` ${c.control.replace("_", " ")} `, cites(c.evidence_ids))))
    : h("p", { class: "muted" }, "No control covered by the evidence.");
  if (a.agent === "threat_model") return a.method.threats.length
    ? h("ul", {}, a.method.threats.map((t) => h("li", {}, h("span", { class: "tag" }, t.stride.replaceAll("_", " ")), ` ${t.threat} `, cites(t.evidence_ids))))
    : h("p", { class: "muted" }, "No STRIDE threat supported by the evidence.");
  return null;
}

function agentCard(a) {
  return h("div", { class: "agent" },
    h("div", { class: "row" }, h("b", {}, a.methodology),
      h("span", { class: `tag ${a.ai_status}` }, a.ai_status === "ok" ? `${a.model} · ${a.latency_s}s` : "model unavailable: deterministic")),
    a.summary ? h("p", {}, a.summary) : null,
    methodView(a), claimList(a.claims), discarded(a.discarded_claims),
    a.unknowns.length ? h("p", { class: "muted" }, "Unknowns: " + a.unknowns.join("; ")) : null);
}

export async function runAgents(scanId, f, box, missionImpact) {
  box.replaceChildren(h("p", { class: "muted" }, "Fetching EPSS / KEV / provenance / Scorecard, then running the methodology agents in parallel and the judge (usually 40–70 s)…"));
  let r;
  try { r = await post(`/api/scans/${scanId}/findings/${f.id}/agents`, { mission_impact: missionImpact }); }
  catch (err) { box.replaceChildren(h("p", { class: "error" }, err.message)); return; }
  const j = r.judge;
  const reviewBox = h("div", {});
  renderReviews(reviewBox, r.independent_review);
  if (r.review_id) pollReviews(r.review_id, reviewBox);
  box.replaceChildren(
    h("p", { class: "muted" }, `Scanner verdict unchanged: ${r.scanner_category} / ${r.scanner_severity} · ${r.elapsed_s}s total`),
    r.enrichment.evidence.length ? h("details", { open: true }, h("summary", {}, `Threat-intel & provenance evidence (${r.enrichment.evidence.length})`),
      h("ol", { class: "evidence" }, r.enrichment.evidence.map((e) => h("li", { id: `ev-${e.id}` }, h("span", { class: "tag" }, e.kind), " ", e.summary,
        e.url ? h("a", { href: e.url, target: "_blank", rel: "noopener noreferrer" }, " source ↗") : null, h("div", { class: "muted mono" }, e.id))))) : null,
    r.enrichment.limitations.length ? h("ul", {}, r.enrichment.limitations.map((l) => h("li", { class: "warn" }, l))) : null,
    h("div", { class: "agents" }, r.agents.map(agentCard)),
    r.skipped_agents.length ? h("p", { class: "muted" }, "Not applicable here: " + r.skipped_agents.map((s) => s.methodology).join(", ")) : null,
    h("div", { class: "judge" },
      h("div", { class: "row" }, h("b", {}, "Judge"), h("span", { class: `tag prio-${j.priority}` }, PRIORITY_LABEL[j.priority]),
        h("span", { class: `tag ${j.ai_status}` }, j.ai_status === "ok" ? `${j.model} · ${j.latency_s}s` : "model unavailable")),
      h("p", {}, j.verdict), claimList(j.claims), discarded(j.discarded_claims),
      j.agreements.length ? h("div", {}, h("h4", {}, "Methods agree"), h("ul", {}, j.agreements.map((x) => h("li", {}, x)))) : null,
      j.conflicts.length ? h("div", {}, h("h4", {}, "Methods conflict"), h("ul", {}, j.conflicts.map((x) => h("li", {}, x)))) : null,
      j.next_steps.length ? h("div", {}, h("h4", {}, "Next steps"), h("ol", {}, j.next_steps.map((x) => h("li", {}, x)))) : null,
      j.unknowns.length ? h("p", { class: "muted" }, "Unknowns: " + j.unknowns.join("; ")) : null),
    reviewBox,
  );
}

function renderReviews(box, reviews) {
  if (!reviews.length) { box.replaceChildren(h("p", { class: "muted" }, "No open-weight reviewer configured (SPARK_OPEN_* / GLIMMER_*).")); return; }
  box.replaceChildren(h("h4", {}, "Independent review (open weights)"),
    ...reviews.map((x) => h("div", { class: "row" }, h("span", { class: "tag" }, `${x.assessor} · ${x.model}`),
      x.status === "pending" ? h("span", { class: "muted" }, "running… (free hosted tiers can take a few minutes)")
      : x.status === "ok" ? [h("span", { class: `tag prio-${x.priority}` }, PRIORITY_LABEL[x.priority]),
        h("span", { class: `tag ${x.agrees_with_judge ? "ok" : "unavailable"}` }, x.agrees_with_judge ? "agrees with judge" : "disagrees with judge"),
        h("span", { class: "muted" }, `${x.latency_s}s`)]
      : h("span", { class: "tag unavailable" }, x.error || x.status))));
}

// Reviews keep running on the server after the judge answers; poll until all are done (max ~6 min).
async function pollReviews(id, box) {
  for (let i = 0; i < 120; i++) {
    await new Promise((res) => setTimeout(res, 3000));
    if (!box.isConnected) return;   // user opened another finding
    let s;
    try { s = await api(`/api/reviews/${id}`); } catch { return; }
    renderReviews(box, s.reviews);
    if (s.done) return;
  }
}
