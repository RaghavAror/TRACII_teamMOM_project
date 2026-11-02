// Impact map: a 2D tree of only the dependency paths that lead to findings.
// Built from the paths each finding already carries (["<app>", "express@4.17.1", "qs@6.7.0"]);
// packages without findings are summarised as a count instead of drawn.
import { $, h } from "./ui.js";

const SEV = ["critical", "high", "medium", "low", "info", "unknown"];
const isKnownMalware = (f) => f.category === "malicious_indicator" && /^MAL-/.test(f.rule_or_advisory);
const kindOf = (f) => isKnownMalware(f) ? "malware" : f.category === "malicious_indicator" ? "suspicious" : "vuln";
// lower = worse: known malware first, then severity
const rank = (f) => (isKnownMalware(f) ? -1 : SEV.indexOf(f.severity));

let state = { scan: null, onOpen: null, showInfo: false };

function buildTree(findings) {
  const root = { label: "<app>", children: new Map(), own: [], dev: false };
  const unplaced = [];
  for (const f of findings) {
    if (!f.paths.length) { unplaced.push(f); continue; }
    for (const p of f.paths) {
      let node = root;
      p.nodes.slice(1).forEach((label, i) => {
        if (!node.children.has(label)) node.children.set(label, { label, children: new Map(), own: [], dev: false });
        node = node.children.get(label);
        if (i === 0 && p.dev_only) node.dev = true;
      });
      if (!node.own.includes(f)) node.own.push(f);
    }
  }
  // worst finding and number of distinct risky packages at or below each node
  const annotate = (n) => {
    const below = new Set(n.own.length ? [n.label] : []);
    let worst = n.own.length ? Math.min(...n.own.map(rank)) : 99;
    for (const c of n.children.values()) {
      annotate(c);
      c.below.forEach((x) => below.add(x));
      worst = Math.min(worst, c.worst);
    }
    n.below = below;
    n.worst = worst;
  };
  annotate(root);
  return { root, unplaced };
}

const worstClass = (r) => r === -1 ? "malware" : SEV[r] || "none";
const sorted = (n) => [...n.children.values()].sort((a, b) => a.worst - b.worst || b.below.size - a.below.size || a.label.localeCompare(b.label));

function counts(own) {
  const by = {};
  for (const f of own) {
    const k = isKnownMalware(f) ? "known malware" : f.category === "malicious_indicator" ? `suspicious ${f.severity}` : f.severity;
    by[k] = (by[k] || 0) + 1;
  }
  return Object.entries(by).sort((a, b) => (a[0] === "known malware" ? -1 : b[0] === "known malware" ? 1 : SEV.indexOf(a[0].replace("suspicious ", "")) - SEV.indexOf(b[0].replace("suspicious ", ""))));
}

function row(n, depth) {
  const own = n.own.slice().sort((a, b) => rank(a) - rank(b));
  // A risky package opens its findings (without toggling the row it sits in); others are plain text,
  // so a click on them expands or collapses their branch.
  const name = own.length
    ? h("button", { class: "im-pkg risky", type: "button", title: "Open in Findings",
        onclick: (e) => { e.preventDefault(); state.onOpen(own[0].id); } }, n.label)
    : h("span", { class: "im-pkg", title: n.children.size ? "No finding on this package itself; expand to see what it brings in" : "" }, n.label);
  return h("div", { class: `im-row w-${worstClass(n.worst)}`, "data-label": n.label },
    h("span", { class: `im-dot w-${worstClass(n.worst)}`, "aria-hidden": "true" }),
    name,
    depth === 1 ? h("span", { class: "tag" }, "direct") : null,
    n.dev ? h("span", { class: "tag" }, "dev only") : null,
    own.length ? h("span", { class: "im-sevs" }, counts(own).map(([k, c]) =>
      h("span", { class: `sev ${k === "known malware" ? "critical mal" : k.replace("suspicious ", "")} ${k.startsWith("suspicious") ? "sus" : ""}` }, `${c} ${k}`))) : null,
    n.children.size ? h("span", { class: "muted im-below" },
      `${n.below.size - (own.length ? 1 : 0)} risky package${n.below.size - (own.length ? 1 : 0) === 1 ? "" : "s"} below`) : null,
  );
}

function branch(n, depth, expandAll) {
  if (!n.children.size) return h("li", {}, row(n, depth));
  return h("li", {}, h("details", { open: expandAll || depth < 2 },
    h("summary", {}, row(n, depth)),
    h("ul", { class: "im-tree" }, sorted(n).map((c) => branch(c, depth + 1, expandAll)))));
}

export function renderImpactMap(scan, { onOpen }) {
  state = { ...state, scan, onOpen };
  draw();
}

function draw() {
  const { scan } = state;
  const r = scan.result;
  const findings = r.findings.filter((f) => state.showInfo || f.severity !== "info");
  const { root, unplaced } = buildTree(findings);
  const direct = sorted(root);
  const risky = new Set(findings.map((f) => `${f.package}@${f.version}`));
  const clean = Math.max(0, new Set(r.inventory.packages.map((p) => `${p.name}@${p.version}`)).size - risky.size);
  const nodes = (n) => [...n.children.values()].reduce((s, c) => s + 1 + nodes(c), 0);
  const expandAll = nodes(root) <= 40;
  const infoCount = r.findings.filter((f) => f.severity === "info").length;

  $("#impact-map").replaceChildren(
    h("p", { class: "im-lead" }, risky.size
      ? `${risky.size} risky package${risky.size === 1 ? "" : "s"} reach${risky.size === 1 ? "es" : ""} your app through ${direct.length} direct dependenc${direct.length === 1 ? "y" : "ies"}. ${clean} other package${clean === 1 ? " has" : "s have"} no findings and ${clean === 1 ? "is" : "are"} not shown.`
      : `No risky packages from the checks that ran. ${clean} package${clean === 1 ? "" : "s"} scanned.`),
    risky.size ? h("p", { class: "muted" }, "Each line is a route into your app, coloured by the worst finding on it. Fixing a direct dependency near the top can clear everything below it. Click a red, amber or blue package to open its findings.") : null,
    infoCount ? h("label", { class: "muted im-toggle" },
      h("input", { type: "checkbox", checked: state.showInfo, onchange: (e) => { state.showInfo = e.target.checked; draw(); } }),
      ` also show ${infoCount} context-only signal${infoCount === 1 ? "" : "s"} (e.g. "has an install script")`) : null,
    risky.size ? h("div", { class: "im-root" },
      h("div", { class: "im-row im-app" }, h("span", { class: "im-dot w-app", "aria-hidden": "true" }), h("b", {}, "Your app")),
      h("ul", { class: "im-tree" }, direct.map((n) => branch(n, 1, expandAll)))) : null,
    unplaced.length ? h("details", {}, h("summary", {}, `${unplaced.length} finding(s) with no recorded path`),
      h("ul", {}, unplaced.map((f) => h("li", {}, h("button", { class: "linklike", onclick: () => state.onOpen(f.id) }, `${f.package}@${f.version} ${f.rule_or_advisory}`))))) : null,
  );
}

// Highlight every row for one package (opening its parents) and scroll the first into view.
export function highlightInMap(label) {
  const rows = [...document.querySelectorAll("#impact-map .im-row")].filter((el) => el.dataset.label === label);
  document.querySelectorAll("#impact-map .im-row.hl").forEach((el) => el.classList.remove("hl"));
  rows.forEach((el) => {
    el.classList.add("hl");
    for (let d = el.closest("details"); d; d = d.parentElement.closest("details")) d.open = true;
  });
  rows[0]?.scrollIntoView({ block: "center", behavior: "smooth" });
  return rows.length > 0;
}
