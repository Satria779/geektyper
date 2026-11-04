import { API_BASE, ROUTES } from './config.js';
const cache = new Map();
export const abs = u => !u ? '' : /^(https?:|data:|blob:)/i.test(u) ? u : new URL(u, API_BASE + '/').href;
async function get(path, params = {}) {
  const url = new URL(API_BASE + path);
  for (const [k, v] of Object.entries(params)) if (v != null && v !== '') [].concat(v).forEach(x => url.searchParams.append(k, x));
  const key = url.href;
  if (cache.has(key)) return cache.get(key);
  const p = (async () => {
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 15000);
    try {
      const r = await fetch(url, { headers: { accept: 'application/json' }, signal: ctl.signal });
      if (!r.ok) throw new Error('Server membalas ' + r.status);
      const j = await r.json();
      if (!j || j.success !== true) throw new Error('Respons API tidak valid');
      return j;
    } finally { clearTimeout(t); }
  })();
  cache.set(key, p);
  p.catch(() => cache.delete(key));
  return p;
}
export const hero = () => get(ROUTES.hero, { limit: 5 });
export const latest = (o = {}) => get(ROUTES.latest, { limit: 20, ...o });
export const popular = () => get(ROUTES.popular, { limit: 10 });
export const filter = o => get(ROUTES.filter, { order_by: 'update', limit: 20, ...o });
export const search = (q, genres = '') => get(ROUTES.search, { q, genres });
export const detail = s => get(ROUTES.detail(s));
export const reading = s => get(ROUTES.reading(s));
