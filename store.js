const ls = { get(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } }, set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} } };
export const favorites = {
  list: () => ls.get('kv:fav', []),
  has: s => favorites.list().some(x => x.slug === s),
  toggle(c) { const l = favorites.list(), i = l.findIndex(x => x.slug === c.slug); i < 0 ? l.unshift(c) : l.splice(i, 1); ls.set('kv:fav', l); return i < 0; },
};
export const history = {
  list: () => ls.get('kv:hist', []),
  save(e) { const l = history.list().filter(x => x.slug !== e.slug); l.unshift({ ...e, at: Date.now() }); ls.set('kv:hist', l.slice(0, 50)); },
  get: s => history.list().find(x => x.slug === s),
};
