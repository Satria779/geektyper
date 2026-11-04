// Jalankan: node server.js -> http://localhost:3000 (Node 18+)
// Proxy diperlukan karena MangaDex tidak mengizinkan hotlink/CORS langsung dari browser (lihat docs resmi).
const http = require('http'), fs = require('fs'), path = require('path');
const PORT = process.env.PORT || 3000, UA = 'KOMIKVERSE/1.0 (reader pribadi)';
const T = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
const okHost = h => h === 'uploads.mangadex.org' || h.endsWith('.mangadex.network');
async function pipe(res, url) {
  try {
    const r = await fetch(url, { headers: { 'user-agent': UA } });
    const h = { 'content-type': r.headers.get('content-type') || 'application/octet-stream', 'cache-control': 'public,max-age=3600' };
    res.writeHead(r.status, h); res.end(Buffer.from(await r.arrayBuffer()));
  } catch (e) { res.writeHead(502); res.end(String(e.message)); }
}
http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname.startsWith('/md/')) return pipe(res, 'https://api.mangadex.org' + u.pathname.slice(3) + u.search);
  if (u.pathname.startsWith('/cover/')) return pipe(res, 'https://uploads.mangadex.org/covers' + u.pathname.slice(6));
  if (u.pathname === '/img') {
    try { const t = new URL(u.searchParams.get('u')); if (t.protocol === 'https:' && okHost(t.hostname)) return pipe(res, t.href); } catch {}
    res.writeHead(400); return res.end('url tidak diizinkan');
  }
  const f = path.join(__dirname, u.pathname === '/' ? 'index.html' : path.normalize(u.pathname).replace(/^(\.\.[\/\\])+/, ''));
  fs.readFile(f, (e, d) => e ? (res.writeHead(404), res.end('404')) : (res.writeHead(200, { 'content-type': T[path.extname(f)] || 'application/octet-stream' }), res.end(d)));
}).listen(PORT, () => console.log('KOMIKVERSE: http://localhost:' + PORT));
