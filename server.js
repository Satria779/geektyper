// Jalankan: node server.js  -> buka http://localhost:3000  (Node 18+)
const http = require('http'), fs = require('fs'), path = require('path');
const UP = 'https://cdncid.csmcscns.id', PORT = process.env.PORT || 3000;
const T = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname.startsWith('/v1/')) {
    try {
      const chunks = []; for await (const c of req) chunks.push(c);
      const r = await fetch(UP + u.pathname + u.search, { method: req.method, headers: { accept: 'application/json', 'content-type': req.headers['content-type'] || 'application/json' }, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks) });
      res.writeHead(r.status, { 'content-type': r.headers.get('content-type') || 'application/json' });
      res.end(Buffer.from(await r.arrayBuffer()));
    } catch (e) { res.writeHead(502, { 'content-type': 'application/json' }); res.end(JSON.stringify({ success: false, error: String(e.message) })); }
    return;
  }
  const f = path.join(__dirname, u.pathname === '/' ? 'index.html' : path.normalize(u.pathname).replace(/^(\.\.[\/\\])+/, ''));
  fs.readFile(f, (e, d) => e ? (res.writeHead(404), res.end('404')) : (res.writeHead(200, { 'content-type': T[path.extname(f)] || 'application/octet-stream' }), res.end(d)));
}).listen(PORT, () => console.log('KOMIKVERSE: http://localhost:' + PORT));
