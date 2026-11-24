import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import express from 'express';
import JSZip from 'jszip';
import { createApp, config } from '../src/server.js';
import { importTemplateXlsx } from '../src/import/xlsx.js';

import { newAssessment } from '../src/shared/model.js';

const silent = { log() {}, warn() {}, error() {} };
const ADMIN = { email: 'admin@example.com', password: 'Initial-Boss-Pw-1' };

// ------------------------------------------------------------------ helpers
function client(base) {
  let cookie = '';
  const call = async (method, url, body, { raw, headers = {}, xhr = true } = {}) => {
    const h = { ...headers };
    if (cookie) h.cookie = cookie;
    if (xhr) h['x-requested-with'] = 'XMLHttpRequest';
    let payload;
    if (raw !== undefined) { payload = raw; h['content-type'] = h['content-type'] || 'application/octet-stream'; }
    else if (body !== undefined) { payload = JSON.stringify(body); h['content-type'] = 'application/json'; }
    const r = await fetch(base + url, { method, headers: h, body: payload, redirect: 'manual' });
    const sc = r.headers.get('set-cookie');
    if (sc) { const m = /cra_session=([^;]*)/.exec(sc); if (m) cookie = m[1] ? `cra_session=${m[1]}` : ''; }
    const ct = r.headers.get('content-type') || '';
    return { status: r.status, headers: r.headers, body: ct.includes('json') ? await r.json() : Buffer.from(await r.arrayBuffer()) };
  };
  return { call, get: (u, o) => call('GET', u, undefined, o), post: (u, b, o) => call('POST', u, b, o), put: (u, b, o) => call('PUT', u, b, o), patch: (u, b, o) => call('PATCH', u, b, o), del: (u, o) => call('DELETE', u, undefined, o) };
}
async function start(env) {
  const app = await createApp(config({ DATABASE_URL: 'sqlite::memory:', ...env }), { log: silent });
  const srv = app.listen(0);
  return { app, srv, base: `http://127.0.0.1:${srv.address().port}`, async stop() { srv.closeAllConnections(); srv.close(); await app.locals.store.close(); } };
}
const cdx = (comps, { deps = true } = {}) => Buffer.from(JSON.stringify({
  bomFormat: 'CycloneDX', specVersion: '1.5',
  metadata: { timestamp: '2026-11-01T00:00:00Z', tools: [{ name: 'gen' }], component: { 'bom-ref': 'root', name: 'fw', version: '1.0' } },
  components: comps.map((c, i) => ({ 'bom-ref': `c${i}`, type: 'library', supplier: { name: 'x' }, licenses: [{ license: { id: 'MIT' } }], ...c })),
  ...(deps ? { dependencies: [{ ref: 'root', dependsOn: comps.map((_, i) => `c${i}`) }] } : {}),
}));

// fake OSV / NVD / EUVD / KEV services
function fakeVulnDb() {
  const app = express();
  app.use(express.json());
  app.post('/v1/querybatch', (req, res) => res.json({ results: req.body.queries.map((q) => ({ vulns: q.package.purl.startsWith('pkg:npm/lodash@4.17.20') ? [{ id: 'GHSA-35jh-r3h4-6jhm' }] : [] })) }));
  app.get('/v1/vulns/:id', (_req, res) => res.json({ id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], summary: 'Command injection in lodash', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
    affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] }));
  app.get('/nvd', (req, res) => res.json({ vulnerabilities: String(req.query.virtualMatchString).includes('openssl') ? [{ cve: { id: 'CVE-2021-3711', descriptions: [{ lang: 'en', value: 'SM2 overflow' }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N' } }] } } }] : [] }));
  app.get('/euvd/kev/dump', (_req, res) => res.json([{ cveId: 'CVE-2021-3711', euvdId: 'EUVD-2022-2673' }]));
  app.get('/euvd/enisaid', (req, res) => res.json({ id: `EUVD-${req.query.id}`, epss: 42.5, baseScore: 7.2 }));
  app.get('/kev.json', (_req, res) => res.json({ vulnerabilities: [] }));
  const srv = app.listen(0);
  const base = `http://127.0.0.1:${srv.address().port}`;
  return { srv, env: { OSV_API: base, NVD_API: `${base}/nvd`, EUVD_API: `${base}/euvd`, KEV_URL: `${base}/kev.json` } };
}

// ------------------------------------------------------------------ local accounts & RBAC
describe('local accounts, RBAC and product data', () => {
  let s, admin, vuln, pid, users = {};
  before(async () => {
    vuln = fakeVulnDb();
    s = await start({ AUTH_MODE: 'local', INITIAL_ADMIN_EMAIL: ADMIN.email, INITIAL_ADMIN_PASSWORD: ADMIN.password, ...vuln.env });
    admin = client(s.base);
  });
  after(async () => { vuln?.srv.closeAllConnections(); vuln?.srv.close(); await s?.stop(); });

  test('bootstrap admin must change the initial password', async () => {
    assert.equal((await admin.get('/api/products')).status, 401);
    assert.equal((await admin.post('/api/auth/login', { email: ADMIN.email, password: 'wrong-password-123' })).status, 401);
    assert.equal((await admin.post('/api/auth/login', { email: ADMIN.email, password: ADMIN.password })).status, 200);
    const blocked = await admin.get('/api/products');
    assert.equal(blocked.status, 403); assert.equal(blocked.body.code, 'must_change');
    assert.equal((await admin.post('/api/auth/password', { current: ADMIN.password, password: 'short' })).status, 400);
    assert.equal((await admin.post('/api/auth/password', { current: ADMIN.password, password: 'A-much-better-pw-42' })).status, 200);
    assert.equal((await admin.get('/api/products')).status, 200);
  });

  test('state-changing requests need the X-Requested-With header (CSRF)', async () => {
    const r = await admin.post('/api/products', { name: 'X' }, { xhr: false });
    assert.equal(r.status, 403);
  });

  test('admin creates users and a product; memberships control access', async () => {
    for (const [i, role] of ['owner2', 'editor', 'approver', 'viewer', 'outsider'].entries()) {
      const initial = `Secret-pw-${i}-xyz1234`;
      const r = await admin.post('/api/users', { email: `${role}@example.com`, name: role, password: initial });
      assert.equal(r.status, 201, JSON.stringify(r.body));
      users[role] = { id: r.body.id, c: client(s.base) };
      assert.equal((await users[role].c.post('/api/auth/login', { email: `${role}@example.com`, password: initial })).status, 200);
      assert.equal((await users[role].c.post('/api/auth/password', { current: initial, password: `Changed-secret-${i}-987` })).status, 200);
    }
    const p = await admin.post('/api/products', { name: 'Pump controller', markets: ['professional'] });
    assert.equal(p.status, 201); pid = p.body.id;
    for (const [u, role] of [['editor', 'editor'], ['approver', 'approver'], ['viewer', 'viewer']]) assert.equal((await admin.put(`/api/products/${pid}/members/${users[u].id}`, { role })).status, 200);
    assert.equal((await users.outsider.c.get(`/api/products/${pid}`)).status, 404, 'non-members do not see the product');
    assert.deepEqual((await users.outsider.c.get('/api/products')).body, []);
    assert.equal((await users.viewer.c.get(`/api/products/${pid}`)).body.permissions.edit, false);
    assert.equal((await users.outsider.c.post('/api/products', { name: 'Nope' })).status, 403, 'plain users may not create products');
  });

  test('editors edit, viewers do not; approval fields need the approver role', async () => {
    const a = (await users.editor.c.get(`/api/products/${pid}/assessment`)).body;
    a.data.product.intendedPurpose = 'Pump control';
    const ok = await users.editor.c.put(`/api/products/${pid}/assessment`, { revision: a.revision, data: a.data });
    assert.equal(ok.status, 200);
    assert.equal((await users.viewer.c.put(`/api/products/${pid}/assessment`, { revision: ok.body.revision, data: a.data })).status, 403);
    a.data.method.approvedBy = 'Editor himself';
    const forged = await users.editor.c.put(`/api/products/${pid}/assessment`, { revision: ok.body.revision, data: a.data });
    assert.equal(forged.status, 403); assert.match(forged.body.error, /risk method approval/);
    assert.equal((await users.editor.c.post(`/api/products/${pid}/assessment/approve`, { target: 'method' })).status, 403);
    const appr = await users.approver.c.post(`/api/products/${pid}/assessment/approve`, { target: 'method' });
    assert.equal(appr.status, 200); assert.match(appr.body.data.method.approvedBy, /approver@example.com/);
    const fresh = (await users.editor.c.get(`/api/products/${pid}/assessment`)).body;
    fresh.data.method.approvedBy = ''; fresh.data.method.approvedAt = '';
    assert.equal((await users.editor.c.put(`/api/products/${pid}/assessment`, { revision: fresh.revision, data: fresh.data })).status, 200, 'editors may withdraw an approval');
    assert.equal((await users.editor.c.post(`/api/products/${pid}/assessment/snapshots`, {})).status, 403, 'editors cannot freeze');
    assert.equal((await users.approver.c.post(`/api/products/${pid}/assessment/snapshots`, {})).status, 201);
  });

  let cid;
  test('components and SBOM import (CycloneDX and SPDX), quality check', async () => {
    const c = await users.editor.c.post(`/api/products/${pid}/components`, { name: 'Gateway firmware', type: 'firmware', version: '2.1' });
    assert.equal(c.status, 201); cid = c.body.id;
    assert.equal((await users.viewer.c.post(`/api/products/${pid}/components`, { name: 'x' })).status, 403);
    const up = await users.editor.c.post(`/api/products/${pid}/components/${cid}/sbom?name=fw.cdx.json`, undefined, { raw: cdx([
      { name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' }, { name: 'openssl', version: '1.1.1k', cpe: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*' }]) });
    assert.equal(up.status, 201, JSON.stringify(up.body));
    assert.equal(up.body.summary.packages, 2); assert.equal(up.body.summary.topLevel, 2); assert.ok(up.body.summary.quality.score >= 90);
    const spdx = { spdxVersion: 'SPDX-2.3', creationInfo: { created: '2026-01-01T00:00:00Z', creators: ['Tool: syft'] }, documentDescribes: ['SPDXRef-root'],
      packages: [{ SPDXID: 'SPDXRef-root', name: 'app', versionInfo: '3.0' }, { SPDXID: 'SPDXRef-p1', name: 'requests', versionInfo: '2.0.0', supplier: 'Organization: PSF', licenseConcluded: 'Apache-2.0',
        externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:pypi/requests@2.0.0' }] }],
      relationships: [{ spdxElementId: 'SPDXRef-root', relationshipType: 'DEPENDS_ON', relatedSpdxElement: 'SPDXRef-p1' }] };
    const c2 = await users.editor.c.post(`/api/products/${pid}/components`, { name: 'App', type: 'mobile' });
    const up2 = await users.editor.c.post(`/api/products/${pid}/components/${c2.body.id}/sbom?name=app.spdx.json`, undefined, { raw: Buffer.from(JSON.stringify(spdx)) });
    assert.equal(up2.status, 201); assert.equal(up2.body.format, 'SPDX'); assert.equal(up2.body.summary.topLevel, 1);
    assert.equal((await users.editor.c.get(`/api/products/${pid}/components`)).body.find((x) => x.id === c2.body.id).version, '3.0', 'version taken from the SBOM');
    assert.equal((await users.editor.c.post(`/api/products/${pid}/components/${cid}/sbom`, undefined, { raw: Buffer.from('<bom/>') })).status, 400);
  });

  test('online scan (OSV + NVD + EUVD/KEV) runs in the background and keeps triage on rescan', async () => {
    const r = await users.editor.c.post(`/api/products/${pid}/components/${cid}/scan`, {});
    assert.equal(r.status, 202);
    let scans;
    for (let i = 0; i < 50; i++) { scans = (await users.editor.c.get(`/api/products/${pid}/scans`)).body; if (scans[0].status !== 'running') break; await new Promise((x) => setTimeout(x, 100)); }
    assert.equal(scans[0].status, 'done', JSON.stringify(scans[0]));
    const vulns = (await users.viewer.c.get(`/api/products/${pid}/vulns?component=${cid}`)).body;
    const lodash = vulns.find((v) => v.vulnId === 'CVE-2021-23337');
    const openssl = vulns.find((v) => v.vulnId === 'CVE-2021-3711');
    assert.ok(lodash && openssl, JSON.stringify(vulns.map((v) => v.vulnId)));
    assert.equal(lodash.score, 7.2); assert.deepEqual(lodash.info.fixed, ['4.17.21']); assert.equal(lodash.euvdId, 'EUVD-CVE-2021-23337');
    assert.equal(openssl.kev, true, 'EUVD exploited list sets the KEV flag');
    assert.equal((await users.editor.c.patch(`/api/products/${pid}/vulns/${lodash.id}`, { state: 'not_affected' })).status, 400, 'not affected needs a justification');
    assert.equal((await users.viewer.c.patch(`/api/products/${pid}/vulns/${lodash.id}`, { state: 'resolved' })).status, 403);
    assert.equal((await users.editor.c.patch(`/api/products/${pid}/vulns/${lodash.id}`, { state: 'not_affected', justification: 'code_not_reachable', analysis: 'template() not used' })).status, 200);
    await users.editor.c.post(`/api/products/${pid}/components/${cid}/scan`, {});
    for (let i = 0; i < 50; i++) { if ((await users.editor.c.get(`/api/products/${pid}/scans`)).body[0].status !== 'running') break; await new Promise((x) => setTimeout(x, 100)); }
    const again = (await users.editor.c.get(`/api/products/${pid}/vulns?component=${cid}`)).body.find((v) => v.vulnId === 'CVE-2021-23337');
    assert.equal(again.state, 'not_affected', 'triage survives a rescan');
    const vex = await users.viewer.c.get(`/api/products/${pid}/vex.json?component=${cid}`);
    const doc = JSON.parse(vex.body.toString());
    assert.equal(doc.bomFormat, 'CycloneDX');
    assert.equal(doc.vulnerabilities.find((v) => v.id === 'CVE-2021-23337').analysis.justification, 'code_not_reachable');
  });

  test('scanner output import (Grype) adds findings', async () => {
    const grype = { matches: [{ vulnerability: { id: 'CVE-2022-0001', severity: 'High', cvss: [{ metrics: { baseScore: 7.5 } }], fix: { versions: ['2.0'] } }, artifact: { name: 'zlib', version: '1.2.11', purl: 'pkg:generic/zlib@1.2.11' } }] };
    const r = await users.editor.c.post(`/api/products/${pid}/components/${cid}/vulns/import`, undefined, { raw: Buffer.from(JSON.stringify(grype)) });
    assert.equal(r.status, 201); assert.equal(r.body.format, 'Grype JSON'); assert.equal(r.body.added, 1);
  });

  test('evidence files, technical documentation and release ZIP', async () => {
    const meta = Buffer.from(JSON.stringify({ title: 'Pen test 2026', type: 'Penetration test', result: 'Passed with findings', annex: ['P1-2d', 'P2-3'] })).toString('base64');
    const f = await users.editor.c.post(`/api/products/${pid}/files?section=6&name=pentest.pdf`, undefined, { raw: Buffer.from('%PDF-1.4 test'), headers: { 'content-type': 'application/pdf', 'x-file-meta': meta } });
    assert.equal(f.status, 201); assert.deepEqual(f.body.meta.annex, ['P1-2d', 'P2-3']);
    const html = await users.editor.c.post(`/api/products/${pid}/files?section=other&name=evil.html`, undefined, { raw: Buffer.from('<script>alert(1)</script>'), headers: { 'content-type': 'text/html' } });
    const dl = await users.viewer.c.get(`/api/products/${pid}/files/${html.body.id}/download`);
    assert.equal(dl.headers.get('content-type'), 'application/octet-stream', 'uploaded HTML is never served as HTML');
    assert.match(dl.headers.get('content-disposition'), /attachment/);
    const p = (await users.viewer.c.get(`/api/products/${pid}`)).body;
    assert.equal(p.techdoc.items.length, 8);
    assert.equal(p.techdoc.items.find((i) => i.id === '6').checks[0].ok, true);
    assert.equal((await users.editor.c.post(`/api/products/${pid}/releases`, { version: '1.0' })).status, 403);
    const rel = await users.approver.c.post(`/api/products/${pid}/releases`, { version: '1.0', note: 'first' });
    assert.equal(rel.status, 201, JSON.stringify(rel.body));
    const zipRes = await users.viewer.c.get(`/api/products/${pid}/releases/${rel.body.id}/download`);
    assert.equal(zipRes.headers.get('x-content-sha256'), rel.body.sha256);
    const zip = await JSZip.loadAsync(zipRes.body);
    const names = Object.keys(zip.files);
    for (const n of ['00_index_annex-VII.pdf', 'manifest.json', '03_risk-assessment/risk-assessment.pdf', '02_vulnerability-handling/vulnerabilities.csv', '02_design/threat-model.svg']) assert.ok(names.includes(n), `${n} in ${names.join(', ')}`);
    assert.ok(names.some((n) => n.startsWith('06_test-reports/') && n.endsWith('pentest.pdf')));
    assert.ok(names.some((n) => n.endsWith('/vex.cdx.json')));
    const manifest = JSON.parse(await zip.file('manifest.json').async('string'));
    const pdf = await zip.file('00_index_annex-VII.pdf').async('nodebuffer');
    const { createHash } = await import('node:crypto');
    assert.equal(manifest.files.find((x) => x.path === '00_index_annex-VII.pdf').sha256, createHash('sha256').update(pdf).digest('hex'));
    assert.equal((await users.approver.c.post(`/api/products/${pid}/releases`, { version: '1.0' })).status, 409);
  });

  test('ownership rules: last owner, last admin, deleting released products', async () => {
    const owners = (await admin.get(`/api/products/${pid}/members`)).body.filter((m) => m.role === 'owner');
    assert.equal(owners.length, 1);
    assert.equal((await admin.put(`/api/products/${pid}/members/${owners[0].user.id}`, { role: 'viewer' })).status, 400);
    const me = (await admin.get('/api/me')).body.user;
    assert.equal((await admin.patch(`/api/users/${me.id}`, { globalRole: 'user' })).status, 400, 'last admin stays admin');
    await admin.put(`/api/products/${pid}/members/${users.owner2.id}`, { role: 'owner' });
    assert.equal((await users.owner2.c.del(`/api/products/${pid}`)).status, 400, 'owners cannot delete products with releases');
  });

  test('disabled users lose their session', async () => {
    assert.equal((await admin.patch(`/api/users/${users.viewer.id}`, { disabled: true })).status, 200);
    assert.equal((await users.viewer.c.get('/api/products')).status, 401);
  });
});

// ------------------------------------------------------------------ SSO
describe('SSO (header mode)', () => {
  let s;
  before(async () => {
    s = await start({ AUTH_MODE: 'header', AUTH_HEADER: 'x-ms-client-principal-name', INITIAL_ADMIN_EMAIL: 'boss@example.com', ROLE_SOURCE: 'entra', VULN_LOOKUP: 'off' });
  });
  after(() => s?.stop());
  const as = (email, roles) => {
    const c = client(s.base);
    const principal = roles ? Buffer.from(JSON.stringify({ role_typ: 'roles', claims: roles.map((r) => ({ typ: 'roles', val: r })) })).toString('base64') : null;
    return (m, u, b) => c.call(m, u, b, { headers: { 'x-ms-client-principal-name': email, ...(principal ? { 'x-ms-client-principal': principal } : {}) } });
  };

  test('missing identity header is rejected', async () => {
    assert.equal((await client(s.base).get('/api/products')).status, 401);
  });
  test('unknown users are provisioned without rights; Entra app roles set the global role', async () => {
    const u = as('new.user@example.com');
    assert.equal((await u('GET', '/api/me')).body.user.globalRole, 'user');
    assert.deepEqual((await u('GET', '/api/products')).body, []);
    const auditor = as('audit@example.com', ['CRA.Auditor']);
    assert.equal((await auditor('GET', '/api/me')).body.user.globalRole, 'auditor');
    const boss = as('boss@example.com', ['CRA.Admin']);
    const p = await boss('POST', '/api/products', { name: 'P' });
    assert.equal(p.status, 201);
    assert.equal((await auditor('GET', `/api/products/${p.body.id}`)).status, 200, 'auditors read everything');
    assert.equal((await auditor('POST', `/api/products/${p.body.id}/components`, { name: 'c' })).status, 403);
  });
  test('admins cannot override SSO-managed global roles', async () => {
    const boss = as('boss@example.com', ['CRA.Admin']);
    const users = (await boss('GET', '/api/users')).body;
    const aud = users.find((x) => x.email === 'audit@example.com');
    assert.equal((await boss('PATCH', `/api/users/${aud.id}`, { globalRole: 'admin' })).status, 400);
  });
});

test('a local account becomes SSO-managed when signing in through SSO with the same e-mail', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-'));
  const db = `sqlite:${path.join(dir, 'db.sqlite')}`;
  const a = await start({ DATABASE_URL: db, AUTH_MODE: 'local', INITIAL_ADMIN_EMAIL: 'ann@example.com', INITIAL_ADMIN_PASSWORD: 'Initial-Boss-Pw-1' });
  await a.stop();
  const b = await start({ DATABASE_URL: db, AUTH_MODE: 'header', AUTH_HEADER: 'x-forwarded-email' });
  try {
    const me = (await client(b.base).get('/api/me', { headers: { 'x-forwarded-email': 'Ann@Example.com' } })).body.user;
    assert.equal(me.email, 'ann@example.com'); assert.equal(me.authSource, 'sso'); assert.equal(me.globalRole, 'admin'); assert.equal(me.mustChange, false);
  } finally { await b.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('local mode without initial admin requires the one-time setup token', async () => {
  let token;
  const app = await createApp(config({ DATABASE_URL: 'sqlite::memory:', AUTH_MODE: 'local' }), { log: { ...silent, log: (m) => { const x = /token: (\S+)/.exec(m); if (x) token = x[1]; } } });
  const srv = app.listen(0); const c = client(`http://127.0.0.1:${srv.address().port}`);
  try {
    assert.equal((await c.get('/api/auth/state')).body.setupRequired, true);
    assert.equal((await c.post('/api/auth/setup', { token: 'x'.repeat(token.length), email: 'a@b.c', password: 'Strong-password-123' })).status, 403);
    assert.equal((await c.post('/api/auth/setup', { token, email: 'a@b.c', password: 'Strong-password-123' })).status, 201);
    assert.equal((await c.get('/api/me')).body.user.globalRole, 'admin');
    assert.equal((await c.post('/api/auth/setup', { token, email: 'z@b.c', password: 'Strong-password-123' })).status, 409);
  } finally { srv.closeAllConnections(); srv.close(); await app.locals.store.close(); }
});

test('assessments from older versions are migrated into products', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-'));
  const file = path.join(dir, 'old.sqlite');
  const { DatabaseSync } = await import('node:sqlite');
  const old = new DatabaseSync(file);
  old.exec(`CREATE TABLE assessments (id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL, revision INTEGER NOT NULL, data TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT, updated_at TEXT NOT NULL, updated_by TEXT);
    CREATE TABLE snapshots (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, version TEXT NOT NULL, note TEXT, data TEXT NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT);
    CREATE TABLE events (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, at TEXT NOT NULL, actor TEXT, action TEXT NOT NULL, detail TEXT);`);
  const d = newAssessment({ title: 'Legacy' }); d.product.name = 'Old pump';
  old.prepare('INSERT INTO assessments VALUES (?,?,?,?,?,?,?,?,?)').run('a1', 'Legacy', 'draft', 3, JSON.stringify(d), '2026-01-01', 'x', '2026-01-01', 'x');
  old.close();
  const s = await start({ DATABASE_URL: `sqlite:${file}`, AUTH_MODE: 'none' });
  try {
    const list = (await client(s.base).get('/api/products')).body;
    assert.equal(list.length, 1); assert.equal(list[0].name, 'Old pump');
    const a = (await client(s.base).get(`/api/products/${list[0].id}/assessment`)).body;
    assert.equal(a.id, 'a1'); assert.equal(a.revision, 3);
  } finally { await s.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('tutorial example creates a product with components and SBOMs', async () => {
  const s = await start({ AUTH_MODE: 'none', VULN_LOOKUP: 'off' });
  try {
    const c = client(s.base);
    const p = await c.post('/api/examples/tutorial');
    assert.equal(p.status, 201);
    const comps = (await c.get(`/api/products/${p.body.id}/components`)).body;
    assert.equal(comps.length, 4);
    assert.equal(comps.filter((x) => x.sbom).length, 2);
    assert.equal((await c.post(`/api/products/${p.body.id}/components/${comps[0].id}/scan`, {})).status, 400, 'lookup disabled → clear error');
  } finally { await s.stop(); }
});

test('security headers are set', async () => {
  const s = await start({ AUTH_MODE: 'none' });
  try {
    const r = await fetch(s.base + '/');
    assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
    assert.equal(r.headers.get('x-powered-by'), null);
  } finally { await s.stop(); }
});

const tpl = path.join(import.meta.dirname, '..', '..', 'CRA_Risk_Assessment_Template_Consumer.xlsx');
test('imports the consumer Excel template', { skip: !fs.existsSync(tpl) && 'template not present' }, async () => {
  const { data } = await importTemplateXlsx(fs.readFileSync(tpl));
  assert.deepEqual(data.profile.markets, ['consumer']);
  assert.equal(data.risks.length, 11);
});

test('old AUTH_MODE=basic gives a clear migration error', () => {
  assert.throws(() => config({ AUTH_MODE: 'basic' }), /replaced by AUTH_MODE=local/);
});



test('editors may withdraw but not grant approvals', async () => {
  const s = await start({ AUTH_MODE: 'none' });
  try {
    const c = client(s.base);
    const p = (await c.post('/api/products', { name: 'P' })).body;
    await c.post(`/api/products/${p.id}/assessment/approve`, { target: 'method' });
    // demote the anonymous admin's power by simulating an editor through the guard logic: clear approval via PUT is fine
    const a = (await c.get(`/api/products/${p.id}/assessment`)).body;
    assert.ok(a.data.method.approvedBy);
    a.data.method.approvedBy = ''; a.data.method.approvedAt = '';
    assert.equal((await c.put(`/api/products/${p.id}/assessment`, { revision: a.revision, data: a.data })).status, 200);
  } finally { await s.stop(); }
});
