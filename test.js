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
    const wrong = { headers: { authorization: 'Basic ' + Buffer.from('admin:guess').toString('base64') } };
    for (let i = 0; i < 20; i++) await fetch(base + '/admin', wrong);
    assert.equal((await fetch(base + '/admin', { headers: { authorization: auth } })).status, 429, 'locked after 20 wrong logins');
    assert.equal((await fetch(base + '/')).status, 200, 'public page unaffected by lockout');
    console.log('OK');
  } catch (e) { console.error(e); process.exitCode = 1; } finally { srv.kill(); }
}, 400);
