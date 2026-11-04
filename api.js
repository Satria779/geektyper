import { API_BASE, LANGS, QUALITY, RATINGS } from './config.js';
const cache = new Map();
export const abs = u => u || '';
async function get(path, params = {}) {
  const url = new URL(API_BASE + path, location.origin);
  for (const [k, v] of Object.entries(params)) if (v != null && v !== '') [].concat(v).forEach(x => url.searchParams.append(k, x));
  const key = url.href;
  if (cache.has(key)) return cache.get(key);
  const p = (async () => {
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 15000);
    try {
      const r = await fetch(url, { signal: ctl.signal });
      if (r.status === 429) throw new Error('Terlalu banyak permintaan, tunggu sebentar');
      if (!r.ok) throw new Error('Server membalas ' + r.status);
      return await r.json();
    } finally { clearTimeout(t); }
  })();
  cache.set(key, p); p.catch(() => cache.delete(key));
  return p;
}
const TYPES = { ja: 'manga', ko: 'manhwa', zh: 'manhua', 'zh-hk': 'manhua' };
const text = o => o ? (o.id || o.en || Object.values(o)[0] || '') : '';
const rel = (m, t) => m.relationships?.find(r => r.type === t);
function norm(m) {
  const a = m.attributes, cf = rel(m, 'cover_art')?.attributes?.fileName;
  const genres = (a.tags || []).filter(t => t.attributes.group === 'genre').map(t => t.attributes.name.en);
  return { slug: m.id, title: text(a.title), cover: cf ? `/cover/${m.id}/${cf}.512.jpg` : '', big_cover: cf ? `/cover/${m.id}/${cf}` : '',
    type: TYPES[a.originalLanguage] || 'manga', status: a.status, genres, summary: text(a.description), sinopsis: text(a.description),
    author: rel(m, 'author')?.attributes?.name, artist: rel(m, 'artist')?.attributes?.name, chapters: [] };
}
const list = j => ({ data: j.data.map(norm), total: j.total });
const base = { 'contentRating[]': RATINGS, 'includes[]': ['cover_art', 'author', 'artist'] };
const ORDER = { update: 'order[latestUploadedChapter]', popular: 'order[followedCount]' };
export async function filter({ q, type_manga, release_status, order_by = 'update', limit = 20, offset = 0 } = {}) {
  const lang = Object.entries(TYPES).filter(([, v]) => v === type_manga).map(([k]) => k);
  return list(await get('/manga', { ...base, title: q, limit, offset, 'status[]': release_status, 'originalLanguage[]': lang,
    'availableTranslatedLanguage[]': LANGS, [ORDER[order_by] || ORDER.update]: 'desc' }));
}
export const search = q => filter({ q, order_by: 'popular' });
export const hero = () => filter({ order_by: 'popular', limit: 5 });
export const popular = () => filter({ order_by: 'popular', limit: 12 });
export const latest = () => filter({ order_by: 'update', limit: 20 });
export async function detail(id) {
  const [m, f] = await Promise.all([get('/manga/' + id, { 'includes[]': base['includes[]'] }),
    get(`/manga/${id}/feed`, { limit: 500, 'translatedLanguage[]': LANGS, 'order[chapter]': 'desc', 'contentRating[]': RATINGS, 'includes[]': 'scanlation_group' })]);
  const d = norm(m.data);
  d.chapters = f.data.filter(c => !c.attributes.externalUrl && c.attributes.pages > 0).map(c => ({ slug: c.id, number: c.attributes.chapter ?? c.attributes.title ?? 'Oneshot',
    time: [rel(c, 'scanlation_group')?.attributes?.name, c.attributes.translatedLanguage, c.attributes.publishAt?.slice(0, 10)].filter(Boolean).join(' · '), redirect_link: null }));
  return { data: d };
}
export async function reading(chId) {
  const [ch, s] = await Promise.all([get('/chapter/' + chId), get('/at-home/server/' + chId)]);
  const files = s.chapter[QUALITY === 'data' ? 'data' : 'dataSaver'];
  return { data: { slugSeries: rel(ch.data, 'manga')?.id, chapters: files.map(f => `/img?u=${encodeURIComponent(`${s.baseUrl}/${QUALITY}/${s.chapter.hash}/${f}`)}`) } };
}
