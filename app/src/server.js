import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { openStore, ConflictError } from './store.js';
import { catalog } from './shared/catalog.js';
import { newAssessment, normalize } from './shared/model.js';
import { tutorialAssessment, tutorialComponents, TUTORIAL_ID, TUTORIAL_TITLE } from './shared/tutorial.js';
import { normalizeProduct, evaluateTechDoc, FILE_SECTIONS, COMPONENT_TYPES, VEX_STATES, VEX_JUSTIFICATIONS, VEX_RESPONSES, TEST_TYPES, TEST_RESULTS } from './shared/techdoc.js';
import { can, permissions, canCreateProducts, canManageUsers, GLOBAL_ROLES, PRODUCT_ROLES } from './shared/roles.js';
import { authConfig, setupAuth, requireUser, hashPassword, passwordProblem, publicUser, validEmail } from './auth.js';
import { parseSbom, SbomError } from './sbom.js';
import { vulnConfig, scanPackages, parseVulnReport, enrich, toCycloneDxVex } from './vuln.js';
import { docControl, safeFilename, sha256 } from './export/common.js';
import { toXlsx } from './export/xlsx.js';
import { toPdf } from './export/pdf.js';
import { buildTechDocPackage } from './export/techdoc.js';
import { importTemplateXlsx } from './import/xlsx.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const APP_VERSION = JSON.parse(fs.readFileSync(path.join(here, '..', 'package.json'), 'utf8')).version;

export function config(env = process.env) {
  return {
    port: Number(env.PORT || 8080),
    databaseUrl: env.DATABASE_URL || 'sqlite:./data/cra.db',
    trustProxy: env.TRUST_PROXY || 'loopback, linklocal, uniquelocal',
    fileMaxMb: Number(env.FILE_MAX_MB || 25),
    auth: authConfig(env),
    vuln: vulnConfig(env),
  };
}

function securityHeaders(_req, res, next) {
  res.set({
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Cross-Origin-Opener-Policy': 'same-origin',
  });
  next();
}

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const validDoc = (d) => d && typeof d === 'object' && !Array.isArray(d) && d.meta && typeof d.meta === 'object' && d.profile && typeof d.profile === 'object';
const today = () => new Date().toISOString().slice(0, 10);
const str = (v, max = 500) => String(v ?? '').slice(0, max);
const SAFE_INLINE = new Set(['application/pdf', 'image/png', 'image/jpeg']);

function sendFile(res, buf, name, mime) {
  res.set({
    'Content-Type': SAFE_INLINE.has(mime) ? mime : 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${safeFilename(name)}"; filename*=UTF-8''${encodeURIComponent(name)}`,
    'Content-Security-Policy': "default-src 'none'; sandbox",
  });
  res.send(buf);
}

// Granting an approval needs the approver role (four-eyes principle). Withdrawing one – e.g. because the
// approved content was edited afterwards – is allowed for editors.
function approvalChanges(before, after) {
  const changes = [];
  const granted = (b, a) => !!String(a || '').trim() && a !== b;
  if (granted(before.method.approvedBy, after.method.approvedBy) || (after.method.approvedBy && before.method.approvedAt !== after.method.approvedAt)) changes.push('risk method approval');
  if (after.meta.status === 'approved' && before.meta.status !== 'approved') changes.push('assessment status "approved"');
  after.reviewLog.forEach((a, i) => {
    const b = before.reviewLog[i] || {};
    if (granted(b.approvedBy, a.approvedBy) || (a.approvedBy && (b.approvalDate || '') !== (a.approvalDate || ''))) changes.push(`approval of revision ${a.version || i + 1}`);
  });
  return changes;
}

export async function createApp(cfg = config(), { log = console } = {}) {
  const store = await openStore(cfg.databaseUrl);
  await migrateLegacyAssessments(store);
  await store.interruptStaleScans();
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', cfg.trustProxy);
  app.use(securityHeaders);
  app.get('/healthz', wrap(async (_req, res) => { await store.ping(); res.json({ ok: true }); }));
  await setupAuth(app, store, cfg.auth, log);

  const api = express.Router();
  api.use(requireUser(cfg.auth));
  api.use(express.json({ limit: '10mb' }));
  const raw = (mb) => express.raw({ type: () => true, limit: `${mb}mb` });
  const actor = (req) => req.user.email;

  // ---------------------------------------------------------------- access helpers
  async function access(req, res, productId, action) {
    const product = await store.getProduct(productId);
    if (!product) { res.status(404).json({ error: 'Product not found' }); return null; }
    const role = await store.roleOf(req.user.id, product.id);
    if (!can(req.user, role, 'read')) { res.status(404).json({ error: 'Product not found' }); return null; }   // do not reveal existence
    if (!can(req.user, role, action)) { res.status(403).json({ error: `Your role (${role || req.user.globalRole}) does not allow "${action}" on this product.` }); return null; }
    product.data = normalizeProduct(product.data);
    return { product, role, perms: permissions(req.user, role) };
  }

  async function componentView(c) {
    const sbom = await store.currentSbom(c.id);
    const findings = await store.listFindings(c.productId, c.id);
    const present = findings.filter((f) => f.present);
    const open = present.filter((f) => VEX_STATES.find((s) => s.id === f.state)?.open);
    const sev = (lvl) => open.filter((f) => f.severity === lvl).length;
    return { ...c, sbom, findings, vulns: {
      total: present.length, open: open.length, exploitable: open.filter((f) => f.state === 'exploitable').length,
      untriaged: open.filter((f) => f.state === 'in_triage').length, kevOpen: open.filter((f) => f.kev).length,
      critical: sev('critical'), high: sev('high'), medium: sev('medium'), low: sev('low'),
    } };
  }

  async function productContext(product) {
    const rec = await store.getAssessment(product.assessmentId);
    const components = await Promise.all((await store.listComponents(product.id)).map(componentView));
    const files = await store.listFiles(product.id);
    const snapshots = rec ? await store.listSnapshots(rec.id) : [];
    const assessment = rec ? normalize(rec.data) : null;
    return { rec, assessment, components, files, snapshots, techdoc: evaluateTechDoc({ product: product.data, assessment, components, files, snapshots }) };
  }
  const slimComponent = ({ findings, ...c }) => c;

  // ---------------------------------------------------------------- session / reference data
  api.get('/me', wrap(async (req, res) => {
    res.json({ user: publicUser(req.user, { roleFromIdp: !!req.user.roleFromIdp }), authMode: cfg.auth.mode, version: APP_VERSION,
      can: { createProducts: canCreateProducts(req.user), manageUsers: canManageUsers(req.user) },
      vulnLookup: cfg.vuln.enabled ? [...cfg.vuln.sources] : [] });
  }));
  api.get('/catalog', (_req, res) => res.json({ ...catalog(), GLOBAL_ROLES, PRODUCT_ROLES, COMPONENT_TYPES, FILE_SECTIONS, VEX_STATES, VEX_JUSTIFICATIONS, VEX_RESPONSES, TEST_TYPES, TEST_RESULTS }));

  // ---------------------------------------------------------------- users (administrators)
  const adminOnly = (req, res) => { if (!canManageUsers(req.user)) { res.status(403).json({ error: 'Administrators only.' }); return false; } return true; };
  api.get('/users', wrap(async (req, res) => { if (adminOnly(req, res)) res.json(await store.listUsers()); }));
  api.get('/directory', wrap(async (req, res) => {
    // minimal user list for picking product members (owners and admins only)
    const ownsSomething = (await store.membershipsOfUser(req.user.id)).some((m) => m.role === 'owner');
    if (!ownsSomething && !canManageUsers(req.user)) return res.status(403).json({ error: 'Not allowed.' });
    res.json((await store.listUsers()).filter((u) => !u.disabled && u.authSource !== 'none').map((u) => ({ id: u.id, email: u.email, name: u.name })));
  }));
  api.post('/users', wrap(async (req, res) => {
    if (!adminOnly(req, res)) return;
    const { email, name, globalRole = 'user', password } = req.body || {};
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid e-mail address.' });
    if (!GLOBAL_ROLES.some((r) => r.id === globalRole)) return res.status(400).json({ error: 'Unknown role.' });
    if (await store.getUserByEmail(email)) return res.status(409).json({ error: 'A user with this e-mail exists.' });
    const local = cfg.auth.mode === 'local';
    if (local) { const p = passwordProblem(password, email); if (p) return res.status(400).json({ error: `Initial password: ${p}` }); }
    const u = await store.createUser({ email, name: str(name, 200), globalRole, authSource: local ? 'local' : 'sso', passwordHash: local ? await hashPassword(password) : null, mustChange: local });
    await store.event(actor(req), 'user.create', `${u.email} (${globalRole})`);
    res.status(201).json(u);
  }));
  api.patch('/users/:id', wrap(async (req, res) => {
    if (!adminOnly(req, res)) return;
    const u = await store.getUser(req.params.id);
    if (!u) return res.status(404).json({ error: 'Not found' });
    const { name, globalRole, disabled, password } = req.body || {};
    const patch = {};
    if (name !== undefined) patch.name = str(name, 200);
    if (globalRole !== undefined) {
      if (!GLOBAL_ROLES.some((r) => r.id === globalRole)) return res.status(400).json({ error: 'Unknown role.' });
      if (cfg.auth.roleSource !== 'app' && u.authSource === 'sso') return res.status(400).json({ error: 'Global roles of SSO users come from the identity provider (ROLE_SOURCE).' });
      patch.globalRole = globalRole;
    }
    if (disabled !== undefined) patch.disabled = !!disabled;
    if ((patch.disabled || (patch.globalRole && patch.globalRole !== 'admin')) && u.globalRole === 'admin') {
      const admins = (await store.listUsers()).filter((x) => x.globalRole === 'admin' && !x.disabled);
      if (admins.length <= 1) return res.status(400).json({ error: 'The last active administrator cannot be demoted or disabled.' });
    }
    if (password !== undefined) {
      if (u.authSource !== 'local') return res.status(400).json({ error: 'This user signs in through single sign-on.' });
      const p = passwordProblem(password, u.email);
      if (p) return res.status(400).json({ error: p });
      patch.passwordHash = await hashPassword(password);
      patch.mustChange = true;
    }
    const updated = await store.updateUser(u.id, patch);
    if (patch.disabled || patch.passwordHash) await store.deleteUserSessions(u.id);
    await store.event(actor(req), 'user.update', `${u.email}: ${Object.keys(patch).filter((k) => k !== 'passwordHash').concat(patch.passwordHash ? ['password reset'] : []).join(', ')}`);
    res.json(updated);
  }));
  api.delete('/users/:id', wrap(async (req, res) => {
    if (!adminOnly(req, res)) return;
    const u = await store.getUser(req.params.id);
    if (!u) return res.status(404).end();
    if (u.id === req.user.id) return res.status(400).json({ error: 'You cannot delete your own account.' });
    for (const m of await store.membershipsOfUser(u.id)) {
      if (m.role === 'owner' && await store.countOwners(m.productId) <= 1) return res.status(400).json({ error: 'The user is the only owner of a product. Assign another owner first.' });
    }
    await store.deleteUser(u.id);
    await store.event(actor(req), 'user.delete', u.email);
    res.status(204).end();
  }));

  // ---------------------------------------------------------------- products
  api.get('/products', wrap(async (req, res) => {
    const mine = new Map((await store.membershipsOfUser(req.user.id)).map((m) => [m.productId, m.role]));
    const all = await store.listProducts();
    const visible = all.filter((p) => can(req.user, mine.get(p.id) || null, 'read'));
    res.json(await Promise.all(visible.map(async (p) => {
      p.data = normalizeProduct(p.data);
      const ctx = await productContext(p);
      return { id: p.id, name: p.name, role: mine.get(p.id) || null, updatedAt: p.updatedAt, updatedBy: p.updatedBy,
        placedOnMarket: p.data.placedOnMarket, components: ctx.components.length,
        vulns: ctx.components.reduce((t, c) => ({ open: t.open + c.vulns.open, kevOpen: t.kevOpen + c.vulns.kevOpen, exploitable: t.exploitable + c.vulns.exploitable }), { open: 0, kevOpen: 0, exploitable: 0 }),
        techdoc: { complete: ctx.techdoc.complete, total: ctx.techdoc.items.length, blockers: ctx.techdoc.blockers },
        assessment: ctx.assessment ? { status: ctx.assessment.meta.status, version: ctx.assessment.meta.version, blockers: ctx.techdoc.assessment.blockers } : null };
    })));
  }));

  async function createProductFrom(req, res, assessmentData, extra = {}) {
    if (!canCreateProducts(req.user)) return res.status(403).json({ error: 'Your role may not create products.' });
    const name = str(extra.name || assessmentData.product.name || assessmentData.meta.title, 200) || 'New product';
    if (!assessmentData.product.name) assessmentData.product.name = name;
    const p = await store.createProduct({ name, data: normalizeProduct({ name, ...(extra.data || {}) }), assessmentData }, actor(req), req.user.id);
    for (const c of extra.components || []) {
      const comp = await store.createComponent(p.id, c, actor(req));
      if (c.sbom) { try { await store.addSbom(comp.id, p.id, parseSbom(Buffer.from(JSON.stringify(c.sbom)), `${c.name}.cdx.json`), actor(req)); } catch (e) { log.warn(e.message); } }
    }
    res.status(201).json({ id: p.id, name: p.name, ...(extra.warnings ? { warnings: extra.warnings } : {}) });
  }

  api.post('/products', wrap(async (req, res) => {
    const b = req.body || {};
    if (b.import) {
      const imported = b.import.data && b.import.format === 'cra-risk-assessment' ? b.import.data : b.import;
      if (!validDoc(imported)) return res.status(400).json({ error: 'Not a CRA risk assessment JSON export.' });
      const data = normalize(structuredClone(imported));
      data.meta.status = 'draft';
      for (const l of data.reviewLog) { l.approvedBy = ''; l.approvalDate = ''; }
      data.method.approvedBy = ''; data.method.approvedAt = '';
      return createProductFrom(req, res, data);
    }
    const markets = Array.isArray(b.markets) ? b.markets.filter((m) => ['consumer', 'professional'].includes(m)) : [];
    const data = newAssessment({ title: str(b.name || 'New product', 200), markets: markets.length ? markets : ['professional'] });
    data.reviewLog[0].author = actor(req);
    return createProductFrom(req, res, data, { name: b.name });
  }));

  const exampleDir = path.join(here, '..', 'examples');
  api.get('/examples', (_req, res) => {
    const list = fs.existsSync(exampleDir) ? fs.readdirSync(exampleDir).filter((f) => f.endsWith('.json')) : [];
    res.json([{ id: TUTORIAL_ID, title: TUTORIAL_TITLE, markets: ['consumer'] }, ...list.map((f) => {
      const d = JSON.parse(fs.readFileSync(path.join(exampleDir, f), 'utf8'));
      return { id: f.replace(/\.json$/, ''), title: d.meta.title, markets: d.profile.markets };
    })]);
  });
  api.post('/examples/:id', wrap(async (req, res) => {
    if (req.params.id === TUTORIAL_ID) return createProductFrom(req, res, tutorialAssessment(), { name: 'Tutorial – Smart thermostat ST-1', components: tutorialComponents() });
    const f = path.join(exampleDir, path.basename(req.params.id) + '.json');
    if (!fs.existsSync(f)) return res.status(404).json({ error: 'Unknown example' });
    const data = normalize(JSON.parse(fs.readFileSync(f, 'utf8')));
    return createProductFrom(req, res, data, { name: data.meta.title });
  }));
  api.post('/import/xlsx', raw(20), wrap(async (req, res) => {
    if (!Buffer.isBuffer(req.body) || req.body.length < 4 || req.body.readUInt32LE(0) !== 0x04034b50) return res.status(400).json({ error: 'Upload an .xlsx file.' });
    let result;
    try { result = await importTemplateXlsx(req.body); } catch { return res.status(400).json({ error: 'The file could not be read as a risk-assessment workbook.' }); }
    return createProductFrom(req, res, result.data, { warnings: result.warnings });
  }));

  api.get('/products/:pid', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'read'); if (!x) return;
    const ctx = await productContext(x.product);
    const { assessment: ev, ...techdoc } = ctx.techdoc;
    res.json({ ...x.product, role: x.role, permissions: x.perms, assessment: ctx.rec ? { id: ctx.rec.id, version: ctx.assessment.meta.version, status: ctx.assessment.meta.status, title: ctx.assessment.meta.title,
      updatedAt: ctx.rec.updatedAt, updatedBy: ctx.rec.updatedBy, blockers: ev?.blockers ?? 0, warnings: ev?.warnings ?? 0 } : null,
      components: ctx.components.map(slimComponent), techdoc, files: ctx.files, releases: await store.listReleases(x.product.id), scans: await store.lastScans(x.product.id) });
  }));
  api.put('/products/:pid', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    const { revision, data } = req.body || {};
    if (!Number.isInteger(revision) || !data || typeof data !== 'object') return res.status(400).json({ error: 'Body must be { revision, data }.' });
    try {
      const p = await store.updateProduct(x.product.id, normalizeProduct({ ...data, name: str(data.name, 200) || x.product.name }), revision, actor(req));
      res.json({ id: p.id, revision: p.revision, updatedAt: p.updatedAt });
    } catch (e) {
      if (e instanceof ConflictError) return res.status(409).json({ error: `Changed by ${e.current.updatedBy} at ${e.current.updatedAt}. Reload to continue.` });
      throw e;
    }
  }));
  api.delete('/products/:pid', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'delete'); if (!x) return;
    if ((await store.listReleases(x.product.id)).length && !canManageUsers(req.user)) return res.status(400).json({ error: 'Products with frozen releases can only be deleted by an administrator (retention obligation, Art. 13(13)).' });
    await store.deleteProduct(x.product.id, actor(req));
    res.status(204).end();
  }));
  api.get('/products/:pid/events', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'read'); if (!x) return;
    res.json(await store.events({ productId: x.product.id }));
  }));

  // members
  api.get('/products/:pid/members', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'read'); if (!x) return;
    res.json((await store.memberships(x.product.id)).map((m) => ({ role: m.role, user: { id: m.user.id, email: m.user.email, name: m.user.name, disabled: m.user.disabled } })));
  }));
  api.put('/products/:pid/members/:uid', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'members'); if (!x) return;
    const role = req.body?.role || null;
    if (role && !PRODUCT_ROLES.some((r) => r.id === role)) return res.status(400).json({ error: 'Unknown role.' });
    const u = await store.getUser(req.params.uid);
    if (!u) return res.status(404).json({ error: 'User not found' });
    const current = await store.roleOf(u.id, x.product.id);
    if (current === 'owner' && role !== 'owner' && await store.countOwners(x.product.id) <= 1) return res.status(400).json({ error: 'A product needs at least one owner.' });
    await store.setMembership(x.product.id, u.id, role, actor(req));
    res.json({ ok: true });
  }));

  // ---------------------------------------------------------------- risk assessment of a product
  const loadAssessment = async (x) => { const r = await store.getAssessment(x.product.assessmentId); if (r) r.data = normalize(r.data); return r; };

  api.get('/products/:pid/assessment', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'read'); if (!x) return;
    const r = await loadAssessment(x);
    if (!r) return res.status(404).json({ error: 'Not found' });
    res.json({ ...r, product: { id: x.product.id, name: x.product.name }, role: x.role, permissions: x.perms,
      productComponents: (await store.listComponents(x.product.id)).map((c) => ({ id: c.id, name: c.name, type: c.type, version: c.version })) });
  }));
  api.put('/products/:pid/assessment', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    const { revision, data } = req.body || {};
    if (!Number.isInteger(revision) || !validDoc(data)) return res.status(400).json({ error: 'Body must be { revision, data }.' });
    const cur = await loadAssessment(x);
    const next = normalize(data);
    const changes = approvalChanges(cur.data, next);
    if (changes.length && !x.perms.approve) return res.status(403).json({ error: `Only approvers may change: ${changes.join(', ')}.` });
    try {
      const r = await store.updateAssessment(cur.id, next, revision, actor(req), x.product.id);
      res.json({ id: r.id, revision: r.revision, updatedAt: r.updatedAt, updatedBy: r.updatedBy });
    } catch (e) {
      if (e instanceof ConflictError) return res.status(409).json({ error: `Changed by ${e.current.updatedBy} at ${e.current.updatedAt}. Reload to continue.`, revision: e.current.revision });
      throw e;
    }
  }));
  // approvals are recorded with the signed-in user's identity
  api.post('/products/:pid/assessment/approve', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'approve'); if (!x) return;
    const cur = await loadAssessment(x);
    const d = cur.data;
    const who = req.user.name ? `${req.user.name} <${req.user.email}>` : req.user.email;
    const { target, index, revoke } = req.body || {};
    if (target === 'method') Object.assign(d.method, revoke ? { approvedBy: '', approvedAt: '' } : { approvedBy: who, approvedAt: today() });
    else if (target === 'revision' && d.reviewLog[index]) Object.assign(d.reviewLog[index], revoke ? { approvedBy: '', approvalDate: '' } : { approvedBy: who, approvalDate: today() });
    else if (target === 'status') d.meta.status = revoke ? 'in_review' : 'approved';
    else return res.status(400).json({ error: 'Unknown approval target.' });
    const r = await store.replaceAssessmentData(cur.id, d, actor(req), x.product.id);
    await store.event(actor(req), revoke ? 'approval.revoke' : 'approval', `${target}${index != null ? ` #${index}` : ''}`, { productId: x.product.id, assessmentId: cur.id });
    res.json({ revision: r.revision, data: r.data });
  }));
  api.get('/products/:pid/assessment/snapshots', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'read'); if (!x) return;
    res.json(await store.listSnapshots(x.product.assessmentId));
  }));
  api.post('/products/:pid/assessment/snapshots', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'release'); if (!x) return;
    const r = await loadAssessment(x);
    const version = String(r.data.meta.version || '').trim();
    if (!version) return res.status(400).json({ error: 'Set a version number before freezing.' });
    if ((await store.listSnapshots(r.id)).some((s) => s.version === version)) return res.status(409).json({ error: `Version ${version} is already frozen. Increase the version number first.` });
    const snap = await store.createSnapshot(r.id, { version, note: str(req.body?.note, 1000), data: r.data, sha256: sha256(r.data) }, actor(req), x.product.id);
    res.status(201).json({ id: snap.id, version: snap.version, sha256: snap.sha256, createdAt: snap.createdAt, createdBy: snap.createdBy });
  }));
  api.get('/products/:pid/assessment/export.:fmt', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'export'); if (!x) return;
    const r = await loadAssessment(x);
    let snap = null;
    if (req.query.snapshot) {
      snap = await store.getSnapshot(r.id, String(req.query.snapshot));
      if (!snap) return res.status(404).json({ error: 'Snapshot not found' });
      snap.data = normalize(snap.data);
    }
    const dc = docControl(r, snap);
    const base = `CRA-RA_${safeFilename(dc.data.product.name || dc.data.meta.title)}_v${safeFilename(dc.version)}${dc.frozen ? '' : '_DRAFT'}`;
    const send = (buf, type, ext) => { res.set({ 'Content-Type': type, 'Content-Disposition': `attachment; filename="${base}.${ext}"`, 'X-Content-SHA256': dc.sha256 }); res.send(buf); };
    switch (req.params.fmt) {
      case 'json': return send(Buffer.from(JSON.stringify({ format: 'cra-risk-assessment', schema: dc.data.schema, version: dc.version, frozen: dc.frozen, sha256: dc.sha256, exportedAt: dc.exportedAt, data: dc.data }, null, 2)), 'application/json', 'json');
      case 'xlsx': return send(await toXlsx(dc), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'xlsx');
      case 'pdf': return send(await toPdf(dc), 'application/pdf', 'pdf');
      default: return res.status(404).json({ error: 'Unknown export format' });
    }
  }));

  // ---------------------------------------------------------------- components, SBOMs, vulnerabilities
  const componentBody = (b) => ({ name: str(b.name, 200).trim(), type: COMPONENT_TYPES.some((t) => t.id === b.type) ? b.type : 'other', version: str(b.version, 100).trim(),
    data: { description: str(b.data?.description, 2000), repository: str(b.data?.repository, 500), owner: str(b.data?.owner, 200), assessmentRef: str(b.data?.assessmentRef, 20) } });
  const loadComponent = async (x, cid, res) => {
    const c = await store.getComponent(cid);
    if (!c || c.productId !== x.product.id) { res.status(404).json({ error: 'Component not found' }); return null; }
    return c;
  };

  api.get('/products/:pid/components', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'read'); if (!x) return;
    res.json(await Promise.all((await store.listComponents(x.product.id)).map(async (c) => slimComponent(await componentView(c)))));
  }));
  api.post('/products/:pid/components', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    const b = componentBody(req.body || {});
    if (!b.name) return res.status(400).json({ error: 'Name is required.' });
    res.status(201).json(await store.createComponent(x.product.id, b, actor(req)));
  }));
  api.put('/products/:pid/components/:cid', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    if (!await loadComponent(x, req.params.cid, res)) return;
    const b = componentBody(req.body || {});
    if (!b.name) return res.status(400).json({ error: 'Name is required.' });
    res.json(await store.updateComponent(req.params.cid, b, actor(req)));
  }));
  api.delete('/products/:pid/components/:cid', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    if (!await loadComponent(x, req.params.cid, res)) return;
    await store.deleteComponent(req.params.cid, actor(req));
    res.status(204).end();
  }));
  api.get('/products/:pid/components/:cid/sboms', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'read'); if (!x) return;
    if (!await loadComponent(x, req.params.cid, res)) return;
    const list = await store.listSboms(req.params.cid);
    const current = list.find((s) => s.isCurrent);
    res.json({ list, packages: current ? (await store.getSbom(current.id, true)).packages : [] });
  }));
  api.post('/products/:pid/components/:cid/sbom', raw(50), wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    const c = await loadComponent(x, req.params.cid, res); if (!c) return;
    if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'Empty upload.' });
    let parsed;
    try { parsed = parseSbom(req.body, str(req.query.name || 'sbom.json', 200)); } catch (e) { if (e instanceof SbomError) return res.status(400).json({ error: e.message }); throw e; }
    const s = await store.addSbom(c.id, x.product.id, parsed, actor(req));
    // align the component version with the SBOM's primary component if it was empty
    if (!c.version && parsed.meta.primary?.version) await store.updateComponent(c.id, { version: parsed.meta.primary.version }, actor(req));
    res.status(201).json(s);
  }));
  api.get('/products/:pid/sboms/:sid/download', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'export'); if (!x) return;
    const s = await store.getSbom(req.params.sid);
    if (!s || s.productId !== x.product.id) return res.status(404).json({ error: 'Not found' });
    const r = await store.getSbomRaw(s.id);
    sendFile(res, r.raw, r.filename || 'sbom.json', 'application/json');
  }));

  // scans run in the background; the UI polls /scans
  const running = new Set();
  async function runScan(scanId, product, component, packages, who) {
    running.add(component.id);
    try {
      const result = await scanPackages(packages, cfg.vuln, store);
      const merged = await store.mergeFindings(product.id, component.id, result.findings, { replace: true });
      await store.finishScan(scanId, 'done', { ...result.summary, added: merged.added });
      await store.event(who, 'vuln.scan', `${component.name}: ${result.summary.findings} finding(s), ${merged.added} new, ${result.summary.kev} actively exploited`, { productId: product.id });
    } catch (e) {
      await store.finishScan(scanId, 'failed', { error: e.message });
    } finally { running.delete(component.id); }
  }
  api.post('/products/:pid/components/:cid/scan', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    const c = await loadComponent(x, req.params.cid, res); if (!c) return;
    if (!cfg.vuln.enabled) return res.status(400).json({ error: 'Online vulnerability lookup is disabled on this server. Import scanner results instead.' });
    if (running.has(c.id)) return res.status(409).json({ error: 'A scan for this component is already running.' });
    const s = await store.currentSbom(c.id, true);
    if (!s) return res.status(400).json({ error: 'Import an SBOM for this component first.' });
    const scanId = await store.addScan(x.product.id, c.id, actor(req));
    runScan(scanId, x.product, c, s.packages, actor(req));
    res.status(202).json({ scanId });
  }));
  api.get('/products/:pid/scans', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'read'); if (!x) return;
    res.json(await store.lastScans(x.product.id));
  }));
  api.post('/products/:pid/components/:cid/vulns/import', raw(50), wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    const c = await loadComponent(x, req.params.cid, res); if (!c) return;
    let parsed;
    try { parsed = parseVulnReport(req.body); } catch (e) { return res.status(400).json({ error: e.message }); }
    const messages = [];
    if (cfg.vuln.enabled) { try { await enrich(parsed.findings, cfg.vuln, store, messages); } catch (e) { messages.push(e.message); } }
    const merged = await store.mergeFindings(x.product.id, c.id, parsed.findings, { replace: req.query.replace === 'true' });
    await store.event(actor(req), 'vuln.import', `${c.name}: ${parsed.format}, ${parsed.findings.length} finding(s), ${merged.added} new`, { productId: x.product.id });
    res.status(201).json({ format: parsed.format, findings: parsed.findings.length, added: merged.added, messages });
  }));
  api.get('/products/:pid/vulns', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'read'); if (!x) return;
    res.json(await store.listFindings(x.product.id, req.query.component ? String(req.query.component) : null));
  }));
  api.patch('/products/:pid/vulns/:fid', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    const f = await store.getFinding(req.params.fid);
    if (!f || f.productId !== x.product.id) return res.status(404).json({ error: 'Not found' });
    const { state, justification = '', response = '', analysis = '' } = req.body || {};
    if (!VEX_STATES.some((s) => s.id === state)) return res.status(400).json({ error: 'Unknown state.' });
    if (justification && !VEX_JUSTIFICATIONS.includes(justification)) return res.status(400).json({ error: 'Unknown justification.' });
    if (response && !VEX_RESPONSES.includes(response)) return res.status(400).json({ error: 'Unknown response.' });
    if (['not_affected', 'false_positive'].includes(state) && !justification && !str(analysis).trim()) return res.status(400).json({ error: 'Give a justification or an analysis for "not affected" / "false positive".' });
    res.json(await store.triageFinding(f.id, { state, justification, response, analysis: str(analysis, 4000) }, actor(req)));
  }));
  api.get('/products/:pid/vex.json', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'export'); if (!x) return;
    const cid = req.query.component ? String(req.query.component) : null;
    const component = cid ? await loadComponent(x, cid, res) : null;
    if (cid && !component) return;
    const findings = (await store.listFindings(x.product.id, cid)).filter((f) => f.present);
    const vex = toCycloneDxVex({ product: x.product, component, findings, serial: randomUUID() });
    sendFile(res, Buffer.from(JSON.stringify(vex, null, 2)), `VEX_${x.product.name}${component ? `_${component.name}` : ''}.cdx.json`, 'application/json');
  }));

  // ---------------------------------------------------------------- files (evidence for Annex VII)
  const fileMeta = (m = {}) => ({ title: str(m.title, 300), date: str(m.date, 20), type: str(m.type, 100), result: str(m.result, 50), summary: str(m.summary, 2000),
    annex: Array.isArray(m.annex) ? m.annex.map((a) => str(a, 10)).slice(0, 40) : [], components: Array.isArray(m.components) ? m.components.map((c) => str(c, 60)).slice(0, 40) : [] });
  api.get('/products/:pid/files', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'read'); if (!x) return;
    res.json(await store.listFiles(x.product.id));
  }));
  api.post('/products/:pid/files', raw(cfg.fileMaxMb), wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    const section = String(req.query.section || 'other');
    if (!FILE_SECTIONS.some((s) => s.id === section)) return res.status(400).json({ error: 'Unknown section.' });
    if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'Empty upload.' });
    const name = str(req.query.name || 'document', 200);
    let meta = {};
    try { meta = req.get('x-file-meta') ? JSON.parse(Buffer.from(req.get('x-file-meta'), 'base64').toString('utf8')) : {}; } catch { /* ignore */ }
    const f = await store.addFile(x.product.id, { section, name, mime: str(req.get('content-type') || 'application/octet-stream', 100), data: req.body,
      sha256: createHash('sha256').update(req.body).digest('hex'), meta: fileMeta({ title: name, ...meta }) }, actor(req));
    res.status(201).json(f);
  }));
  api.patch('/products/:pid/files/:fid', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    const f = await store.getFile(req.params.fid);
    if (!f || f.productId !== x.product.id) return res.status(404).json({ error: 'Not found' });
    const section = req.body?.section && FILE_SECTIONS.some((s) => s.id === req.body.section) ? req.body.section : null;
    res.json(await store.updateFileMeta(f.id, fileMeta(req.body?.meta || f.meta), section, actor(req)));
  }));
  api.delete('/products/:pid/files/:fid', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'edit'); if (!x) return;
    const f = await store.getFile(req.params.fid);
    if (!f || f.productId !== x.product.id) return res.status(404).json({ error: 'Not found' });
    await store.deleteFile(f.id, actor(req));
    res.status(204).end();
  }));
  api.get('/products/:pid/files/:fid/download', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'export'); if (!x) return;
    const f = await store.getFile(req.params.fid, true);
    if (!f || f.productId !== x.product.id) return res.status(404).json({ error: 'Not found' });
    sendFile(res, f.data, f.name, f.mime);
  }));

  // ---------------------------------------------------------------- technical documentation & releases
  async function packageInput(x, release) {
    const ctx = await productContext(x.product);
    const components = await Promise.all(ctx.components.map(async (c) => ({ ...c, sbomRaw: c.sbom ? await store.getSbomRaw(c.sbom.id) : null })));
    const files = await Promise.all(ctx.files.map((f) => store.getFile(f.id, true)));
    return { product: { ...x.product.data, id: x.product.id, name: x.product.name }, assessmentRecord: { id: ctx.rec.id, data: ctx.assessment }, components, files, snapshots: ctx.snapshots, release };
  }
  api.get('/products/:pid/techdoc/draft.zip', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'export'); if (!x) return;
    const pkg = await buildTechDocPackage(await packageInput(x, { version: 'draft', frozen: false, actor: actor(req), createdAt: new Date().toISOString() }));
    sendFile(res, pkg.zip, `TechDoc_${x.product.name}_DRAFT.zip`, 'application/zip');
  }));
  api.post('/products/:pid/releases', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'release'); if (!x) return;
    const version = str(req.body?.version, 50).trim();
    if (!version) return res.status(400).json({ error: 'Enter a version for this documentation release.' });
    if ((await store.listReleases(x.product.id)).some((r) => r.version === version)) return res.status(409).json({ error: `Release ${version} already exists.` });
    const release = { version, note: str(req.body?.note, 1000), frozen: true, actor: actor(req), createdAt: new Date().toISOString() };
    const pkg = await buildTechDocPackage(await packageInput(x, release));
    const r = await store.addRelease(x.product.id, { version, note: release.note, manifest: pkg.manifest, sha256: pkg.sha256, zip: pkg.zip }, actor(req));
    res.status(201).json(r);
  }));
  api.get('/products/:pid/releases', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'read'); if (!x) return;
    res.json(await store.listReleases(x.product.id));
  }));
  api.get('/products/:pid/releases/:rid/download', wrap(async (req, res) => {
    const x = await access(req, res, req.params.pid, 'export'); if (!x) return;
    const r = await store.getRelease(req.params.rid, true);
    if (!r || r.productId !== x.product.id) return res.status(404).json({ error: 'Not found' });
    res.set('X-Content-SHA256', r.sha256);
    sendFile(res, r.zip, `TechDoc_${x.product.name}_${r.version}.zip`, 'application/zip');
  }));

  app.use('/api', api);
  app.use('/shared', express.static(path.join(here, 'shared'), { fallthrough: false }));
  app.use(express.static(path.join(here, '..', 'public'), { index: 'index.html' }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Upload too large.' });
    if (err.status && err.status < 500) return res.status(err.status).json({ error: err.message });
    log.error(err);
    res.status(500).json({ error: 'Internal error' });
  });

  app.locals.store = store;
  app.locals.config = cfg;
  return app;
}

// Assessments created before v0.4 become products (visible to administrators until members are assigned).
async function migrateLegacyAssessments(store) {
  for (const a of await store.listOrphanAssessments()) {
    const d = normalize(a.data);
    const name = d.product.name || a.title || 'Migrated assessment';
    await store.attachProduct(a.id, name, normalizeProduct({ name }), 'migration');
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const cfg = config();
  const app = await createApp(cfg);
  const server = app.listen(cfg.port, () => console.log(`CRA Self Assessment Helper v${APP_VERSION} listening on :${cfg.port} (auth: ${cfg.auth.mode}, roles: ${cfg.auth.roleSource}, db: ${cfg.databaseUrl.split(':')[0]}, vulnerability lookup: ${cfg.vuln.enabled ? [...cfg.vuln.sources].join('+') : 'off'})`));
  const stop = () => server.close(async () => { await app.locals.store.close(); process.exit(0); });
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
