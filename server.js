// Portfolio server: serves data/index.html publicly, /admin edits it (Basic Auth).
// Node stdlib only — no npm install, no build step.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), vm = require('vm');

const DATA = process.env.DATA_DIR || '/data';
const PAGE = path.join(DATA, 'index.html'), HIST = path.join(DATA, 'history');
const { ADMIN_USER = 'admin', ADMIN_PASS = '' } = process.env;
if (ADMIN_PASS.length < 8) throw new Error('ADMIN_PASS must be set (min 8 chars)');

const sha = s => crypto.createHash('sha256').update(s).digest();
const WANT = sha(`${ADMIN_USER}:${ADMIN_PASS}`);
// Brute-force guard, per 15-minute window: 10 wrong logins lock out that client, 100 in total lock out everyone.
// The client is Cloudflare's Cf-Connecting-IP; a request that bypasses Cloudflare (LAN port) could fake it, and the total caps that.
const WINDOW = 15 * 60e3, PER_CLIENT = 10, TOTAL = 100, fails = new Map();
let total = 0, since = Date.now();
const client = req => req.headers['cf-connecting-ip'] || req.socket.remoteAddress;
const locked = ip => {
  if (Date.now() - since > WINDOW) { fails.clear(); total = 0; since = Date.now(); }
  return total >= TOTAL || (fails.get(ip) || 0) >= PER_CLIENT;
};
const authed = req => {
  const m = /^Basic (.+)$/.exec(req.headers.authorization || '');
  return !!m && crypto.timingSafeEqual(sha(Buffer.from(m[1], 'base64').toString()), WANT);
};
const ADMIN = fs.readFileSync(path.join(__dirname, 'admin.html'));
const ROBOTS = 'User-agent: *\nDisallow: /admin\nSitemap: https://portfolio.bgrlango.store/sitemap.xml\n';
// Unknown public URLs get a small page in the site's colours instead of a bare "Not found".
const NOT_FOUND = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Page not found · Supiana Sakti</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><style>@font-face{font-family:Geist;font-weight:400 600;src:url(/fonts/geist-latin.woff2) format("woff2")}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;box-sizing:border-box;font:16px/1.6 Geist,system-ui,sans-serif;background:#f6f6f4;color:#171716}main{max-width:420px}h1{font-size:27px;font-weight:500;letter-spacing:-.02em;margin:0 0 6px}p{margin:0 0 22px;color:#6b6b66}a{color:inherit;font-weight:500}@media (prefers-color-scheme:dark){body{background:#0e0e0d;color:#ededea}p{color:#84847d}}</style></head><body><main><h1>Page not found</h1><p>This page doesn't exist. <span lang="id">Halaman ini tidak ada.</span></p><a href="/">← Back to the portfolio</a></main></body></html>`;
// Files next to the page in data/: the share image and the icons. /favicon.ico gets the PNG icon (browsers sniff it fine).
const STATIC = { '/og.jpg': ['og.jpg', 'image/jpeg'], '/favicon.svg': ['favicon.svg', 'image/svg+xml'], '/apple-touch-icon.png': ['apple-touch-icon.png', 'image/png'], '/favicon.ico': ['apple-touch-icon.png', 'image/png'] };
// HTML pages may only load from this origin (+ Cloudflare's analytics beacon). Inline script/style stay allowed: the page is one file.
const SECURITY = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://cloudflareinsights.com; frame-ancestors 'self'; base-uri 'none'; form-action 'none'; object-src 'none'",
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
};
const send = (res, code, body, type = 'text/html; charset=utf-8', extra = {}) => {
  res.writeHead(code, { 'Content-Type': type, ...(type.startsWith('text/html') ? SECURITY : {}), ...extra });
  res.end(body);
};

// Refuse a save that would break the live page: a script syntax error (stops every feature on it), a translation
// dictionary that is no longer JSON, or a menu link whose section is gone. ponytail: regex over our own page, not an HTML parser.
const check = html => {
  const out = [], line = i => html.slice(0, i).split('\n').length;
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const [, attrs, code] = m;
    if (/\bsrc=/i.test(attrs)) continue;
    if (/type="[^"]*json"/i.test(attrs)) { // the #i18n dictionary and the JSON-LD profile
      try { JSON.parse(code); } catch (e) { out.push(`${/id="i18n"/.test(attrs) ? 'Kamus terjemahan (#i18n)' : 'Script JSON'} di baris ${line(m.index)} tidak valid: ${e.message}`); }
    } else {
      try { new vm.Script(code, { filename: 'page', lineOffset: line(m.index) - 1 }); } // compiles only, never runs
      catch (e) { out.push(`Error di script baris ${(/page:(\d+)/.exec(e.stack) || [, line(m.index)])[1]}: ${e.message}`); }
    }
  }
  const bare = html.replace(/<!--[\s\S]*?-->/g, ''); // a commented-out menu link doesn't count
  const ids = new Set([...bare.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
  const side = (/<aside\b[^>]*class="side\b[\s\S]*?<\/aside>/i.exec(bare) || [''])[0];
  for (const [, id] of side.matchAll(/\bhref="#([^"]+)"/g)) if (!ids.has(id)) out.push(`Link menu "#${id}" tidak punya bagian dengan id="${id}"`);
  return out;
};

const save = (req, res) => {
  const chunks = []; let size = 0;
  req.on('data', c => { size += c.length; if (size > 5e6) { send(res, 413, 'Too large', 'text/plain'); req.destroy(); } else chunks.push(c); });
  req.on('end', () => {
    if (res.writableEnded) return;
    const html = Buffer.concat(chunks);
    if (!/<html/i.test(html.toString('utf8', 0, 2000))) return send(res, 400, 'Isi bukan halaman HTML — tidak disimpan', 'text/plain; charset=utf-8');
    const problems = check(html.toString('utf8'));
    if (problems.length) return send(res, 400, 'Tidak disimpan, halaman akan rusak:\n- ' + problems.join('\n- '), 'text/plain; charset=utf-8');
    try {
      // ponytail: history grows forever (~50 KB/save); prune data/history by hand if it ever matters
      fs.mkdirSync(HIST, { recursive: true });
      fs.copyFileSync(PAGE, path.join(HIST, new Date().toISOString().replace(/[:.]/g, '-') + '.html'));
      fs.writeFileSync(PAGE + '.tmp', html);
      fs.renameSync(PAGE + '.tmp', PAGE); // atomic swap: visitors never see a half-written page
      send(res, 200, 'saved', 'text/plain');
    } catch (e) { console.error(e); send(res, 500, 'Gagal menyimpan: ' + e.code, 'text/plain; charset=utf-8'); }
  });
};

http.createServer((req, res) => {
  try {
    const url = req.url.split('?')[0];
    if (url === '/' || url === '/index.html') return send(res, 200, fs.readFileSync(PAGE), undefined, { 'Cache-Control': 'no-cache' });
    if (url === '/healthz') return send(res, 200, 'ok', 'text/plain');
    if (url === '/robots.txt') return send(res, 200, ROBOTS, 'text/plain; charset=utf-8');
    if (url === '/sitemap.xml') { // lastmod follows the page file, so every /admin save updates it
      const day = fs.statSync(PAGE).mtime.toISOString().slice(0, 10);
      return send(res, 200, `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://portfolio.bgrlango.store/</loc><lastmod>${day}</lastmod></url></urlset>\n`, 'application/xml; charset=utf-8');
    }
    const font = /^\/fonts\/([\w-]+\.woff2)$/.exec(url), file = font ? ['fonts/' + font[1], 'font/woff2'] : STATIC[url];
    if (file) {
      let buf; try { buf = fs.readFileSync(path.join(DATA, file[0])); } catch { return send(res, 404, 'Not found', 'text/plain'); }
      return send(res, 200, buf, file[1], { 'Cache-Control': font ? 'public, max-age=31536000, immutable' : 'public, max-age=86400' });
    }
    if (url !== '/admin' && !url.startsWith('/admin/')) return send(res, 404, NOT_FOUND);

    const ip = client(req);
    if (locked(ip)) return send(res, 429, 'Terlalu banyak login gagal. Coba lagi dalam 15 menit.', 'text/plain; charset=utf-8');
    if (!authed(req)) {
      if (req.headers.authorization) { fails.set(ip, (fails.get(ip) || 0) + 1); total++; } // only wrong guesses count, not the browser's first credential-less request
      return send(res, 401, 'Login required', 'text/plain', { 'WWW-Authenticate': 'Basic realm="Portfolio admin", charset="UTF-8"' });
    }
    const priv = { 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' };
    if (req.method === 'GET' && (url === '/admin' || url === '/admin/')) return send(res, 200, ADMIN, undefined, priv);
    // version history: the backup taken before every save, newest first; /admin loads one into the editor and Simpan restores it
    if (req.method === 'GET' && url === '/admin/history') {
      const list = fs.existsSync(HIST) ? fs.readdirSync(HIST).filter(f => f.endsWith('.html'))
        .map(f => { const st = fs.statSync(path.join(HIST, f)); return { name: f, size: st.size, time: st.mtimeMs }; })
        .sort((a, b) => b.time - a.time).slice(0, 60) : [];
      return send(res, 200, JSON.stringify(list), 'application/json', priv);
    }
    const ver = /^\/admin\/history\/([\w.-]+\.html)$/.exec(url); // no slashes: stays inside data/history
    if (req.method === 'GET' && ver) {
      let buf; try { buf = fs.readFileSync(path.join(HIST, ver[1])); } catch { return send(res, 404, 'Not found', 'text/plain'); }
      return send(res, 200, buf, 'text/plain; charset=utf-8', priv);
    }
    if (url === '/admin/source') {
      if (req.method === 'GET') return send(res, 200, fs.readFileSync(PAGE), 'text/plain; charset=utf-8', priv);
      // custom header forces a CORS preflight, which we never answer → other sites can't reuse the browser's cached login (CSRF)
      if (req.method === 'PUT' && req.headers['x-admin'] === '1') return save(req, res);
      return send(res, 403, 'Forbidden', 'text/plain');
    }
    send(res, 404, 'Not found', 'text/plain');
  } catch (e) { console.error(e); if (!res.headersSent) send(res, 500, 'Server error', 'text/plain'); }
}).listen(process.env.PORT || 8080, () => console.log('portfolio listening on', process.env.PORT || 8080));
