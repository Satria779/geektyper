import * as api from './api.js';
import { favorites, history } from './store.js';
const $ = s => document.querySelector(s), app = $('#app');
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const slugOf = c => c.slug || c.chapter_slug || '';
const genresOf = c => (c.genres?.length ? c.genres : (c.genre || '').split(',')).map(x => x.trim?.() ?? x).filter(Boolean);
const card = c => `<a class="card" href="#/series/${encodeURIComponent(c.slug)}"><div class="im"><img loading="lazy" src="${esc(api.abs(c.cover))}" alt="" onerror="this.style.visibility='hidden'"></div><p>${esc(c.title)}</p><small>${esc(c.chapters?.[0]?.number ? 'Ch. ' + c.chapters[0].number : c.type || '')}</small></a>`;
const grid = l => l.length ? `<div class="grid">${l.map(card).join('')}</div>` : '<p class="err">Belum ada data.</p>';
const skel = () => `<div class="grid">${'<div class="card"><div class="im sk"></div></div>'.repeat(12)}</div>`;
const fail = (e, retry) => `<div class="err">Gagal memuat: ${esc(e.message)}.<br><button class="btn" onclick="${retry}">Coba lagi</button></div>`;
window.kvReload = () => route();

async function home() {
  app.innerHTML = `<div id="h"></div><h2>Popular hari ini</h2><div id="p">${skel()}</div><h2>Latest updates</h2><div id="l">${skel()}</div><div id="rc"></div>`;
  const h = history.list().slice(0, 6);
  if (h.length) $('#rc').innerHTML = `<h2>Lanjut membaca</h2><div class="grid">${h.map(x => card({ slug: x.slug, title: x.title, cover: x.cover, chapters: [{ number: x.number }] })).join('')}</div>`;
  const run = async (id, fn, fmt) => { try { $(id).innerHTML = fmt((await fn()).data); } catch (e) { $(id).innerHTML = fail(e, 'kvReload()'); } };
  run('#h', api.hero, d => d[0] ? `<div class="hero"><img src="${esc(api.abs(d[0].cover))}" alt=""><div><h2 style="margin:0">${esc(d[0].title)}</h2><p>${esc((d[0].summary || d[0].sinopsis || '').slice(0, 180))}</p><a class="btn" href="#/series/${encodeURIComponent(d[0].slug)}">Baca sekarang</a></div></div>` : '');
  run('#p', api.popular, grid); run('#l', () => api.latest(), grid);
}

async function explore(params) {
  const p = new URLSearchParams(params || '');
  app.innerHTML = `<div class="bar"><select id="ty"><option value="">Semua tipe</option><option>manga</option><option>manhwa</option><option>manhua</option></select><select id="st"><option value="">Semua status</option><option>ongoing</option><option>completed</option></select><select id="ob"><option value="update">Update terbaru</option><option value="popular">Populer</option></select></div><div id="r">${skel()}</div>`;
  $('#ty').value = p.get('type') || ''; $('#st').value = p.get('status') || '';
  const go = async () => {
    $('#r').innerHTML = skel();
    try {
      const q = p.get('q');
      let d = q ? (await api.search(q)).data : (await api.filter({ type_manga: $('#ty').value, release_status: $('#st').value, order_by: $('#ob').value })).data;
      if (q) { const t = $('#ty').value, s = $('#st').value; d = d.filter(c => (!t || (c.type || '').toLowerCase() === t) && (!s || (c.status || '').toLowerCase() === s)); }
      $('#r').innerHTML = grid(d);
    } catch (e) { $('#r').innerHTML = fail(e, 'kvReload()'); }
  };
  ['#ty', '#st', '#ob'].forEach(s => $(s).onchange = go); go();
}

async function series(slug) {
  app.innerHTML = skel();
  try {
    const d = (await api.detail(slug)).data, chs = d.chapters || [], last = history.get(slug), first = chs[chs.length - 1], cur = last?.chapter || slugOf(first || {});
    const meta = { slug, title: d.title, cover: d.cover };
    app.innerHTML = `<div class="hero"><img src="${esc(api.abs(d.big_cover || d.cover))}" alt=""><div><h2 style="margin:0">${esc(d.title)}</h2><p>${esc([d.author, d.artist].filter(Boolean).join(' / '))}</p><div class="tags">${genresOf(d).map(g => `<span>${esc(g)}</span>`).join('')}<span>${esc(d.status || '')}</span>${d.rating ? `<span>★ ${esc(d.rating)}</span>` : ''}<span>${chs.length} chapter</span></div>${cur ? `<a class="btn" href="#/read/${encodeURIComponent(cur)}">${last ? 'Lanjutkan' : 'Mulai membaca'}</a>` : ''}<button class="btn g" id="fv">${favorites.has(slug) ? 'Hapus favorit' : 'Tambah favorit'}</button></div></div><h2>Sinopsis</h2><p>${esc(d.sinopsis || d.summary || 'Tidak ada sinopsis.')}</p><h2>Chapter</h2><div class="chs">${chs.map(c => c.redirect_link ? '' : `<a href="#/read/${encodeURIComponent(slugOf(c))}"><span>Chapter ${esc(c.number ?? c.title ?? '')}</span><small>${esc(c.time || '')}</small></a>`).join('')}</div>`;
    $('#fv').onclick = e => { e.target.textContent = favorites.toggle(meta) ? 'Hapus favorit' : 'Tambah favorit'; };
  } catch (e) { app.innerHTML = fail(e, 'kvReload()'); }
}

async function reader(slug) {
  app.innerHTML = `<div id="rd"><div class="pr" id="pr"></div><div class="rt">memuat…</div></div>`;
  try {
    const r = (await api.reading(slug)).data, imgs = r.chapters || [], sl = r.slugSeries;
    let sd = null; try { sd = (await api.detail(sl)).data; } catch {}
    const list = (sd?.chapters || []).filter(c => !c.redirect_link), i = list.findIndex(c => slugOf(c) === slug);
    const next = i > 0 ? slugOf(list[i - 1]) : null, prev = i >= 0 && i < list.length - 1 ? slugOf(list[i + 1]) : null;
    const mode = localStorage.getItem('kv:mode') || 'v', saved = history.get(sl);
    history.save({ slug: sl, title: sd?.title || sl, cover: sd?.cover, chapter: slug, number: list[i]?.number, page: saved?.chapter === slug ? saved.page : 0 });
    const opt = (c, s) => `<option value="${esc(slugOf(c))}" ${slugOf(c) === s ? 'selected' : ''}>Ch. ${esc(c.number ?? '')}</option>`;
    $('#rd').innerHTML = `<div class="pr" id="pr"></div><div class="rt"><a class="btn g" href="#/series/${encodeURIComponent(sl)}">Detail</a>${prev ? `<a class="btn g" href="#/read/${encodeURIComponent(prev)}">Prev</a>` : ''}<select id="cs">${list.map(c => opt(c, slug)).join('')}</select>${next ? `<a class="btn g" href="#/read/${encodeURIComponent(next)}">Next</a>` : ''}<select id="md"><option value="v">Vertikal</option><option value="s">Satu halaman</option><option value="h">Horizontal</option></select><button class="btn g" id="fs">Fullscreen</button></div><div id="pg" class="${mode}">${imgs.map((u, n) => `<img data-n="${n}" loading="lazy" src="${esc(api.abs(u))}" alt="Halaman ${n + 1}" onerror="this.alt='Gambar gagal dimuat'">`).join('') || '<p class="err">Chapter ini tidak punya gambar.</p>'}</div>`;
    $('#md').value = mode; $('#cs').onchange = e => location.hash = '#/read/' + encodeURIComponent(e.target.value);
    $('#md').onchange = e => { localStorage.setItem('kv:mode', e.target.value); $('#pg').className = e.target.value; };
    $('#fs').onclick = () => document.fullscreenElement ? document.exitFullscreen() : $('#rd').requestFullscreen?.();
    const pg = $('#pg'), io = new IntersectionObserver(es => es.forEach(en => { if (en.isIntersecting) { const n = +en.target.dataset.n; $('#pr').style.width = ((n + 1) / imgs.length * 100) + '%'; history.save({ slug: sl, title: sd?.title || sl, cover: sd?.cover, chapter: slug, number: list[i]?.number, page: n }); } }), { threshold: .6 });
    pg.querySelectorAll('img').forEach(im => io.observe(im));
    if (saved?.chapter === slug && saved.page) pg.querySelector(`[data-n="${saved.page}"]`)?.scrollIntoView();
  } catch (e) { app.innerHTML = fail(e, 'kvReload()'); }
}

const lists = (id, l, empty) => { app.innerHTML = `<h2>${id}</h2>` + (l.length ? grid(l) : `<p class="err">${empty}</p>`); };

function route() {
  const [path, qs] = (location.hash.slice(1) || '/').split('?'), [, a, b] = path.split('/'), name = a || 'home';
  document.querySelectorAll('#nav a').forEach(x => x.classList.toggle('on', x.dataset.r === (name === 'series' || name === 'read' ? '' : name)));
  window.scrollTo(0, 0);
  if (name === 'home') home();
  else if (name === 'explore') explore(qs);
  else if (name === 'series') series(decodeURIComponent(b));
  else if (name === 'read') reader(decodeURIComponent(b));
  else if (name === 'fav') lists('Favorites', favorites.list(), 'Belum ada favorit. Buka detail komik lalu tekan Tambah favorit.');
  else if (name === 'history') lists('History', history.list(), 'Belum ada riwayat baca.');
  else app.innerHTML = '<p class="err">Halaman tidak ditemukan.</p>';
}
let t; $('#q').oninput = e => { clearTimeout(t); t = setTimeout(() => { const v = e.target.value.trim(); if (v) location.hash = '#/explore?q=' + encodeURIComponent(v); }, 400); };
$('#sf').onsubmit = e => e.preventDefault();
addEventListener('hashchange', route); route();
