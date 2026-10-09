// Tiny DOM helpers. Text is only ever set through textContent / text nodes, never as HTML.
const SVG_NS = 'http://www.w3.org/2000/svg';

export function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  if (Array.isArray(props) || props instanceof Node || (props != null && typeof props !== 'object')) { kids.unshift(props); props = null; }
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (v === true) el.setAttribute(k, '');
      else el.setAttribute(k, String(v));
    }
  }
  add(el, kids);
  return el;
}

export function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}

export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

export function s(tag, props, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  if (props) for (const [k, v] of Object.entries(props)) if (v != null) el.setAttribute(k, String(v));
  for (const k of kids.flat(Infinity)) if (k != null) el.append(k);
  return el;
}

const ICONS = {
  allow: ['<circle cx="8" cy="8" r="6.25"/>', '<path d="M5 8.2l2 2 4-4.4"/>'],
  hold: ['<path d="M8 2.1L14.5 13.6H1.5Z"/>', '<path d="M8 6.3v3.3"/>', '<path d="M8 11.5v.2"/>'],
  deny: ['<path d="M5.2 1.8h5.6l3.4 3.4v5.6l-3.4 3.4H5.2L1.8 10.8V5.2Z"/>', '<path d="M5.7 5.7l4.6 4.6M10.3 5.7l-4.6 4.6"/>'],
  overview: ['<rect x="2" y="2" width="5" height="5" rx="1"/>', '<rect x="9" y="2" width="5" height="5" rx="1"/>', '<rect x="2" y="9" width="5" height="5" rx="1"/>', '<rect x="9" y="9" width="5" height="5" rx="1"/>'],
  sessions: ['<path d="M2 4h12M2 8h12M2 12h8"/>'],
  approvals: ['<circle cx="8" cy="8" r="6.25"/>', '<path d="M8 4.6V8l2.3 1.6"/>'],
  audit: ['<path d="M6.5 9.5l3-3"/>', '<path d="M7 4.5l1-1a2.8 2.8 0 014 4l-1 1"/>', '<path d="M9 11.5l-1 1a2.8 2.8 0 01-4-4l1-1"/>'],
  policy: ['<path d="M2.5 4.5h6M11.5 4.5h2M2.5 11.5h2M7.5 11.5h6"/>', '<circle cx="10" cy="4.5" r="1.5"/>', '<circle cx="6" cy="11.5" r="1.5"/>'],
  demo: ['<path d="M4.5 2.8l8 5.2-8 5.2Z"/>'],
  info: ['<circle cx="8" cy="8" r="6.25"/>', '<path d="M8 7.2v4"/>', '<path d="M8 4.7v.2"/>'],
  lock: ['<rect x="3.5" y="7" width="9" height="6.5" rx="1.3"/>', '<path d="M5.5 7V5.2a2.5 2.5 0 015 0V7"/>'],
  arrow: ['<path d="M3 8h10M9.5 4.5L13 8l-3.5 3.5"/>'],
};

export function icon(name, size = 16) {
  const el = document.createElementNS(SVG_NS, 'svg');
  el.setAttribute('viewBox', '0 0 16 16');
  el.setAttribute('width', size);
  el.setAttribute('height', size);
  el.setAttribute('fill', 'none');
  el.setAttribute('stroke', 'currentColor');
  el.setAttribute('stroke-width', '1.5');
  el.setAttribute('stroke-linecap', 'round');
  el.setAttribute('stroke-linejoin', 'round');
  el.setAttribute('aria-hidden', 'true');
  el.setAttribute('focusable', 'false');
  // The icon markup is a fixed constant above, never data from the server.
  el.innerHTML = (ICONS[name] || []).join('');
  return el;
}

export const pad = (n) => String(n).padStart(2, '0');
export function fmtClock(ts) {
  if (ts == null) return '–';
  const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
export function fmtDateTime(ts) {
  if (ts == null) return '–';
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${fmtClock(ts)}`;
}
export function ago(ts, now = Date.now() / 1000) {
  if (ts == null) return 'never';
  const d = Math.max(0, now - ts);
  if (d < 2) return 'just now';
  if (d < 90) return `${Math.round(d)} s ago`;
  if (d < 5400) return `${Math.round(d / 60)} min ago`;
  if (d < 172800) return `${Math.round(d / 3600)} h ago`;
  return `${Math.round(d / 86400)} d ago`;
}
export function until(ts, now = Date.now() / 1000) {
  const d = ts - now;
  if (d <= 0) return 'expired';
  if (d < 90) return `${Math.round(d)} s left`;
  return `${Math.floor(d / 60)} min ${pad(Math.round(d % 60))} s left`;
}
