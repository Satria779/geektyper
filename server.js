// Jalankan: node server.js  -> buka http://localhost:3000  (Node 18+)
// Ganti host API: UPSTREAM=https://host-lain node server.js
const http = require('http'), fs = require('fs'), path = require('path');
const HOSTS = (process.env.UPSTREAM ? [process.env.UPSTREAM] : ['https://cdncid.csmcscns.id', 'https://dash.csmcscns.id']).map(h => h.replace(/\/+$/, ''));
const PORT = process.env.PORT || 3000;
const T = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname.startsWith('/v1/')) {
    const chunks = []; for await (const c of req) chunks.push(c);
    const body = ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks);
    let last;
    for (const h of HOSTS) {
      try {
        const r = await fetch(h + u.pathname + u.search, { method: req.method, body, headers: { accept: 'application/json', 'user-agent': 'Mozilla/5.0', 'content-type': req.headers['content-type'] || 'application/json' } });
        console.log(r.status, h + u.pathname + u.search);
        last = { status: r.status, type: r.headers.get('content-type') || 'application/json', data: Buffer.from(await r.arrayBuffer()) };
        if (r.status !== 404) break;
      } catch (e) { console.log('ERR', h, e.message); last = { status: 502, type: 'application/json', data: Buffer.from(JSON.stringify({ success: false, error: e.message })) }; }
    }
    res.writeHead(last.status, { 'content-type': last.type }); res.end(last.data); return;
  }
  const f = path.join(__dirname, u.pathname === '/' ? 'index.html' : path.normalize(u.pathname).replace(/^(\.\.[\/\\])+/, ''));
  fs.readFile(f, (e, d) => e ? (res.writeHead(404), res.end('404')) : (res.writeHead(200, { 'content-type': T[path.extname(f)] || 'application/octet-stream' }), res.end(d)));
}).listen(PORT, () => console.log('KOMIKVERSE: http://localhost:' + PORT));
