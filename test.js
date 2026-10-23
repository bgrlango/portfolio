// Self-check: node test.js  (spawns server on a temp dir, exercises auth + save + backup)
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path'), { spawn } = require('child_process');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-'));
fs.writeFileSync(path.join(dir, 'index.html'), '<!doctype html><html><body>v1</body></html>');
const PORT = '18089', base = `http://127.0.0.1:${PORT}`, auth = 'Basic ' + Buffer.from('admin:test-password-123').toString('base64');
const srv = spawn(process.execPath, [path.join(__dirname, 'server.js')], { env: { ...process.env, DATA_DIR: dir, PORT, ADMIN_PASS: 'test-password-123' } });

setTimeout(async () => {
  try {
    assert.equal((await fetch(base + '/')).status, 200);
    assert.equal((await fetch(base + '/admin')).status, 401);
    assert.equal((await fetch(base + '/admin', { headers: { authorization: 'Basic ' + Buffer.from('admin:wrong').toString('base64') } })).status, 401);
    assert.equal((await fetch(base + '/admin', { headers: { authorization: auth } })).status, 200);
    const put = (body, h = {}) => fetch(base + '/admin/source', { method: 'PUT', headers: { authorization: auth, 'x-admin': '1', ...h }, body });
    assert.equal((await fetch(base + '/admin/source', { method: 'PUT', headers: { authorization: auth }, body: '<html>x</html>' })).status, 403, 'CSRF guard');
    assert.equal((await put('not html')).status, 400);
    assert.equal((await put('<!doctype html><html><body>v2</body></html>')).status, 200);
    assert.match(await (await fetch(base + '/')).text(), /v2/);
    const hist = fs.readdirSync(path.join(dir, 'history'));
    assert.equal(hist.length, 1);
    assert.match(fs.readFileSync(path.join(dir, 'history', hist[0]), 'utf8'), /v1/, 'backup holds previous version');
    // save guard: the real page passes; a script syntax error, broken #i18n JSON or a menu link to a missing section is refused
    const page = fs.readFileSync(path.join(__dirname, 'data', 'index.html'), 'utf8');
    assert.equal((await put(page)).status, 200, 'shipped page passes the save check');
    const guardLine = page.split('\n').findIndex(l => l.startsWith('const guard=')) + 1;
    for (const [bad, why] of [
      [page.replace('const guard=', 'const guard=('), new RegExp(`Error di script baris ${guardLine}:`)],
      [page.replace('"Explore":[', '"Explore":[,'), /Kamus terjemahan/],
      [page.replace('<li><a href="#contact">Contact</a></li>', '<li><a href="#certs">Certs</a></li>'), /Link menu "#certs"/],
    ]) { const r = await put(bad); assert.equal(r.status, 400); assert.match(await r.text(), why); }
    assert.match(await (await fetch(base + '/')).text(), /const guard=\(name/, 'refused saves leave the live page untouched');
    // share image + icons are served from the data dir; a missing one is a 404, not a crash
    fs.writeFileSync(path.join(dir, 'og.jpg'), 'jpg-bytes');
    const og = await fetch(base + '/og.jpg');
    assert.equal(og.headers.get('content-type'), 'image/jpeg'); assert.equal(await og.text(), 'jpg-bytes');
    assert.equal((await fetch(base + '/favicon.svg')).status, 404);
    fs.mkdirSync(path.join(dir, 'fonts')); fs.writeFileSync(path.join(dir, 'fonts', 'geist-latin.woff2'), 'woff2');
    assert.equal((await fetch(base + '/fonts/geist-latin.woff2')).headers.get('content-type'), 'font/woff2');
    assert.match((await fetch(base + '/')).headers.get('content-security-policy'), /default-src 'self'/, 'pages carry a CSP');
    // version history: the backups (v1, v2) are listed and readable, only with the admin login, never outside data/history
    assert.equal((await fetch(base + '/admin/history')).status, 401);
    const asAdmin = u => fetch(base + u, { headers: { authorization: auth } }), versions = await (await asAdmin('/admin/history')).json();
    assert.equal(versions.length, 2);
    assert.ok((await Promise.all(versions.map(v => asAdmin('/admin/history/' + v.name).then(r => r.text())))).some(t => /v1/.test(t)), 'v1 can be loaded back');
    assert.equal((await asAdmin('/admin/history/..%2Fserver.js')).status, 404);
    // lockout: 10 wrong logins lock out that client only, the owner elsewhere still gets in; 100 in total lock out everyone
    const as = (ip, a) => fetch(base + '/admin', { headers: { authorization: a, 'cf-connecting-ip': ip } }), guess = 'Basic ' + Buffer.from('admin:guess').toString('base64');
    for (let i = 0; i < 10; i++) await as('203.0.113.1', guess);
    assert.equal((await as('203.0.113.1', auth)).status, 429, 'guessing client locked out');
    assert.equal((await as('203.0.113.2', auth)).status, 200, 'owner on another IP unaffected');
    for (let i = 0; i < 90; i++) await as('198.51.100.' + (i % 9), guess);
    assert.equal((await as('203.0.113.3', auth)).status, 429, 'locked for everyone after 100 wrong logins');
    assert.equal((await fetch(base + '/')).status, 200, 'public page unaffected by lockout');
    console.log('OK');
  } catch (e) { console.error(e); process.exitCode = 1; } finally { srv.kill(); }
}, 400);
