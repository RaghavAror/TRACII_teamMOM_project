// Shared DOM + API helpers. All package-derived text is untrusted and is
// rendered with textContent only (never innerHTML).
export const API = window.TRACII_API;
export const $ = (s, r = document) => r.querySelector(s);

export function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) el.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

export async function api(path, opts = {}) {
  const res = await fetch(API + path, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
  return body;
}
export const post = (path, data) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data || {}) });

// MITRE ATT&CK technique page, e.g. T1552.001 -> /techniques/T1552/001/
export const attackUrl = (tid) => `https://attack.mitre.org/techniques/${tid.replace(".", "/")}/`;
