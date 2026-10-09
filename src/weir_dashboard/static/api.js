// All traffic goes to this page's own origin. Reads are GETs; the only POSTs are approval decisions and demo loading.
const meta = (n) => document.querySelector(`meta[name="${n}"]`)?.content || '';
const token = meta('weir-token');

export const prefs = { mask: false, theme: null };
try {
  const m = localStorage.getItem('weir.mask');
  prefs.mask = m === null ? meta('weir-mask-default') === '1' : m === '1';
  prefs.theme = localStorage.getItem('weir.theme');
} catch { prefs.mask = meta('weir-mask-default') === '1'; }

export function savePref(k, v) { try { localStorage.setItem(`weir.${k}`, v); } catch { /* storage unavailable: the choice lasts for this page only */ } }

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error?.message || body?.message || `HTTP ${status}`);
    this.status = status; this.state = body?.error?.state || body?.code || 'error'; this.body = body;
  }
}

async function parse(r) {
  let body = null;
  try { body = await r.json(); } catch { /* not JSON */ }
  if (!r.ok) throw new ApiError(r.status, body);
  return body;
}

export async function get(path, params = {}) {
  const q = new URLSearchParams({ mask: prefs.mask ? '1' : '0', ...params });
  return parse(await fetch(`/api/${path}?${q}`, { headers: { Accept: 'application/json' }, cache: 'no-store', credentials: 'same-origin' }));
}

export async function post(path, body) {
  return parse(await fetch(`/api/${path}`, {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-Weir-Token': token },
    body: JSON.stringify(body),
  }));
}
