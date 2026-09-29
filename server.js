// Portfolio server: serves data/index.html publicly, /admin edits it (Basic Auth).
// Node stdlib only — no npm install, no build step.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const DATA = process.env.DATA_DIR || '/data';
const PAGE = path.join(DATA, 'index.html'), HIST = path.join(DATA, 'history');
const { ADMIN_USER = 'admin', ADMIN_PASS = '' } = process.env;
if (ADMIN_PASS.length < 8) throw new Error('ADMIN_PASS must be set (min 8 chars)');

const sha = s => crypto.createHash('sha256').update(s).digest();
const WANT = sha(`${ADMIN_USER}:${ADMIN_PASS}`);
// Brute-force guard: max 20 wrong logins per 15 min, then admin locks for everyone until the window ends.
// ponytail: one global counter, not per-IP (the client-IP header is spoofable via the LAN fallback port).
// Ceiling: an attacker can lock the owner out for 15 min; switch to per-IP on Cf-Connecting-IP if that ever happens.
let fails = 0, since = Date.now();
const locked = () => {
  if (Date.now() - since > 15 * 60e3) { fails = 0; since = Date.now(); }
  return fails >= 20;
};
const authed = req => {
  const m = /^Basic (.+)$/.exec(req.headers.authorization || '');
  return !!m && crypto.timingSafeEqual(sha(Buffer.from(m[1], 'base64').toString()), WANT);
};
const ADMIN = fs.readFileSync(path.join(__dirname, 'admin.html'));
const send = (res, code, body, type = 'text/html; charset=utf-8', extra = {}) => {
  res.writeHead(code, { 'Content-Type': type, ...extra });
  res.end(body);
};

const save = (req, res) => {
  const chunks = []; let size = 0;
  req.on('data', c => { size += c.length; if (size > 5e6) { send(res, 413, 'Too large', 'text/plain'); req.destroy(); } else chunks.push(c); });
  req.on('end', () => {
    if (res.writableEnded) return;
    const html = Buffer.concat(chunks);
    if (!/<html/i.test(html.toString('utf8', 0, 2000))) return send(res, 400, 'Isi bukan halaman HTML — tidak disimpan', 'text/plain; charset=utf-8');
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
    if (url !== '/admin' && !url.startsWith('/admin/')) return send(res, 404, 'Not found', 'text/plain');

    if (locked()) return send(res, 429, 'Terlalu banyak login gagal. Coba lagi dalam 15 menit.', 'text/plain; charset=utf-8');
    if (!authed(req)) {
      if (req.headers.authorization) fails++; // only wrong guesses count, not the browser's first credential-less request
      return send(res, 401, 'Login required', 'text/plain', { 'WWW-Authenticate': 'Basic realm="Portfolio admin", charset="UTF-8"' });
    }
    const priv = { 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' };
    if (req.method === 'GET' && (url === '/admin' || url === '/admin/')) return send(res, 200, ADMIN, undefined, priv);
    if (url === '/admin/source') {
      if (req.method === 'GET') return send(res, 200, fs.readFileSync(PAGE), 'text/plain; charset=utf-8', priv);
      // custom header forces a CORS preflight, which we never answer → other sites can't reuse the browser's cached login (CSRF)
      if (req.method === 'PUT' && req.headers['x-admin'] === '1') return save(req, res);
      return send(res, 403, 'Forbidden', 'text/plain');
    }
    send(res, 404, 'Not found', 'text/plain');
  } catch (e) { console.error(e); if (!res.headersSent) send(res, 500, 'Server error', 'text/plain'); }
}).listen(process.env.PORT || 8080, () => console.log('portfolio listening on', process.env.PORT || 8080));
