// Persistence: SQLite (default, single container) or PostgreSQL (DATABASE_URL=postgres://…).
// JSON documents (assessments, products, components) carry an optimistic-locking revision where
// several people may edit concurrently. Snapshots and releases are immutable.
// Transactions must only contain database calls (no network / file I/O) so that requests cannot interleave.
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export class ConflictError extends Error {
  constructor(current) { super('Revision conflict'); this.current = current; }
}

const now = () => new Date().toISOString();
const json = (v) => JSON.stringify(v ?? null);
const parse = (s, fallback = null) => { if (s == null) return fallback; try { return JSON.parse(s); } catch { return fallback; } };
const buf = (b) => (b == null ? null : Buffer.isBuffer(b) ? b : Buffer.from(b));

// ------------------------------------------------------------------ schema migrations
const MIGRATIONS = [
  // 1: original tables (v0.1 – v0.3)
  (d) => [
    `CREATE TABLE IF NOT EXISTS assessments (
       id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL, revision INTEGER NOT NULL,
       data TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT, updated_at TEXT NOT NULL, updated_by TEXT)`,
    `CREATE TABLE IF NOT EXISTS snapshots (
       id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
       version TEXT NOT NULL, note TEXT, data TEXT NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT)`,
    `CREATE TABLE IF NOT EXISTS events (
       id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, at TEXT NOT NULL, actor TEXT, action TEXT NOT NULL, detail TEXT)`,
    `CREATE INDEX IF NOT EXISTS snapshots_assessment ON snapshots(assessment_id)`,
    `CREATE INDEX IF NOT EXISTS events_assessment ON events(assessment_id)`,
  ],
  // 2: products, components, SBOMs, vulnerabilities, files, releases, users, RBAC
  (d) => [
    `CREATE TABLE IF NOT EXISTS users (
       id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, password_hash TEXT, auth_source TEXT NOT NULL,
       global_role TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, must_change INTEGER NOT NULL DEFAULT 0,
       created_at TEXT NOT NULL, last_login_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS sessions (
       id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
       created_at TEXT NOT NULL, expires_at TEXT NOT NULL, last_seen_at TEXT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS products (
       id TEXT PRIMARY KEY, name TEXT NOT NULL, data TEXT NOT NULL, revision INTEGER NOT NULL, assessment_id TEXT UNIQUE,
       created_at TEXT NOT NULL, created_by TEXT, updated_at TEXT NOT NULL, updated_by TEXT)`,
    `CREATE TABLE IF NOT EXISTS memberships (
       product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
       role TEXT NOT NULL, PRIMARY KEY (product_id, user_id))`,
    `CREATE TABLE IF NOT EXISTS components (
       id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
       name TEXT NOT NULL, type TEXT NOT NULL, version TEXT, data TEXT NOT NULL,
       created_at TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT)`,
    `CREATE TABLE IF NOT EXISTS sboms (
       id TEXT PRIMARY KEY, component_id TEXT NOT NULL REFERENCES components(id) ON DELETE CASCADE, product_id TEXT NOT NULL,
       format TEXT NOT NULL, spec_version TEXT, filename TEXT, sha256 TEXT NOT NULL, is_current INTEGER NOT NULL,
       summary TEXT NOT NULL, packages TEXT NOT NULL, raw ${d.blob} NOT NULL, uploaded_at TEXT NOT NULL, uploaded_by TEXT)`,
    `CREATE TABLE IF NOT EXISTS findings (
       id TEXT PRIMARY KEY, product_id TEXT NOT NULL, component_id TEXT NOT NULL REFERENCES components(id) ON DELETE CASCADE,
       vuln_id TEXT NOT NULL, pkg_key TEXT NOT NULL, pkg_name TEXT, pkg_version TEXT, purl TEXT, aliases TEXT,
       severity TEXT, score REAL, summary TEXT, info TEXT, kev INTEGER NOT NULL DEFAULT 0, euvd_id TEXT, epss REAL,
       sources TEXT, present INTEGER NOT NULL DEFAULT 1, state TEXT NOT NULL, justification TEXT, response TEXT, analysis TEXT,
       first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, updated_at TEXT, updated_by TEXT)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS findings_key ON findings(component_id, vuln_id, pkg_key)`,
    `CREATE INDEX IF NOT EXISTS findings_product ON findings(product_id)`,
    `CREATE TABLE IF NOT EXISTS scans (
       id TEXT PRIMARY KEY, product_id TEXT NOT NULL, component_id TEXT, started_at TEXT NOT NULL, finished_at TEXT,
       actor TEXT, status TEXT NOT NULL, summary TEXT)`,
    `CREATE TABLE IF NOT EXISTS files (
       id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE, section TEXT NOT NULL,
       name TEXT NOT NULL, mime TEXT, size INTEGER NOT NULL, sha256 TEXT NOT NULL, meta TEXT, data ${d.blob} NOT NULL,
       uploaded_at TEXT NOT NULL, uploaded_by TEXT)`,
    `CREATE INDEX IF NOT EXISTS files_product ON files(product_id)`,
    `CREATE TABLE IF NOT EXISTS releases (
       id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE, version TEXT NOT NULL,
       note TEXT, manifest TEXT NOT NULL, sha256 TEXT NOT NULL, zip ${d.blob} NOT NULL, created_at TEXT NOT NULL, created_by TEXT)`,
    `CREATE TABLE IF NOT EXISTS vuln_cache (key TEXT PRIMARY KEY, data TEXT NOT NULL, fetched_at TEXT NOT NULL)`,
    `ALTER TABLE events ADD COLUMN product_id TEXT`,
    `CREATE INDEX IF NOT EXISTS events_product ON events(product_id)`,
  ],
];

// ------------------------------------------------------------------ engine adapters (same SQL, ? placeholders)
class SqliteDb {
  constructor(DatabaseSync, file) {
    if (file !== ':memory:') fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
    this.db = new DatabaseSync(file);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
    this.dialect = { name: 'sqlite', blob: 'BLOB' };
  }
  async exec(sql) { this.db.exec(sql); }
  async all(sql, params = []) { return this.db.prepare(sql).all(...params); }
  async get(sql, params = []) { return this.db.prepare(sql).get(...params); }
  async run(sql, params = []) { return { changes: Number(this.db.prepare(sql).run(...params).changes) }; }
  async tx(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const r = await fn(this); this.db.exec('COMMIT'); return r; } catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  async close() { this.db.close(); }
}

class PgDb {
  constructor(pool, client) { this.pool = pool; this.client = client; this.dialect = { name: 'postgres', blob: 'BYTEA' }; }
  static conv(sql) { let i = 0; return sql.replace(/\?/g, () => '$' + ++i); }
  q() { return this.client || this.pool; }
  async exec(sql) { await this.q().query(sql); }
  async all(sql, params = []) { return (await this.q().query(PgDb.conv(sql), params)).rows; }
  async get(sql, params = []) { return (await this.all(sql, params))[0]; }
  async run(sql, params = []) { return { changes: (await this.q().query(PgDb.conv(sql), params)).rowCount }; }
  async tx(fn) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const r = await fn(new PgDb(this.pool, client));
      await client.query('COMMIT');
      return r;
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  }
  async close() { await this.pool.end(); }
}

export async function openStore(databaseUrl) {
  let db;
  if (/^postgres(ql)?:\/\//.test(databaseUrl || '')) {
    const { default: pg } = await import('pg');
    const ssl = process.env.PGSSLMODE === 'disable' ? false : (process.env.PGSSLMODE ? { rejectUnauthorized: process.env.PGSSLMODE === 'verify-full' } : undefined);
    db = new PgDb(new pg.Pool({ connectionString: databaseUrl, ssl, max: 10 }));
  } else {
    const { DatabaseSync } = await import('node:sqlite');
    const file = (databaseUrl || 'sqlite:./data/cra.db').replace(/^sqlite:(\/\/)?/, '');
    db = new SqliteDb(DatabaseSync, file);
  }
  await migrate(db);
  return new Store(db);
}

async function migrate(db) {
  await db.exec('CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
  const row = await db.get("SELECT value FROM schema_meta WHERE key = 'version'");
  let version = row ? Number(row.value) : 0;
  if (!row) {
    // databases from v0.1–v0.3 have the tables of migration 1 but no schema_meta
    const legacy = await db.get(db.dialect.name === 'sqlite'
      ? "SELECT name FROM sqlite_master WHERE type='table' AND name='assessments'"
      : "SELECT table_name AS name FROM information_schema.tables WHERE table_name='assessments'");
    version = legacy ? 1 : 0;
    await db.run("INSERT INTO schema_meta (key, value) VALUES ('version', ?)", [String(version)]);
  }
  for (let v = version; v < MIGRATIONS.length; v++) {
    await db.tx(async (t) => {
      for (const sql of MIGRATIONS[v](db.dialect)) await t.exec(sql);
      await t.run("UPDATE schema_meta SET value = ? WHERE key = 'version'", [String(v + 1)]);
    });
  }
}

// ------------------------------------------------------------------ row mappers
const toAssessment = (r) => r && ({
  id: r.id, title: r.title, status: r.status, revision: Number(r.revision), data: parse(r.data),
  createdAt: r.created_at, createdBy: r.created_by, updatedAt: r.updated_at, updatedBy: r.updated_by,
});
const toUser = (r) => r && ({
  id: r.id, email: r.email, name: r.name || '', authSource: r.auth_source, globalRole: r.global_role,
  disabled: !!Number(r.disabled), mustChange: !!Number(r.must_change), hasPassword: !!r.password_hash,
  createdAt: r.created_at, lastLoginAt: r.last_login_at,
});
const toProduct = (r) => r && ({
  id: r.id, name: r.name, data: parse(r.data, {}), revision: Number(r.revision), assessmentId: r.assessment_id,
  createdAt: r.created_at, createdBy: r.created_by, updatedAt: r.updated_at, updatedBy: r.updated_by,
});
const toComponent = (r) => r && ({
  id: r.id, productId: r.product_id, name: r.name, type: r.type, version: r.version || '', data: parse(r.data, {}),
  createdAt: r.created_at, updatedAt: r.updated_at, updatedBy: r.updated_by,
});
const toSbom = (r, withPackages = false) => r && ({
  id: r.id, componentId: r.component_id, productId: r.product_id, format: r.format, specVersion: r.spec_version, filename: r.filename,
  sha256: r.sha256, isCurrent: !!Number(r.is_current), summary: parse(r.summary, {}), uploadedAt: r.uploaded_at, uploadedBy: r.uploaded_by,
  ...(withPackages ? { packages: parse(r.packages, []) } : {}),
});
const toFinding = (r) => r && ({
  id: r.id, productId: r.product_id, componentId: r.component_id, vulnId: r.vuln_id, pkgKey: r.pkg_key, pkgName: r.pkg_name,
  pkgVersion: r.pkg_version, purl: r.purl, aliases: parse(r.aliases, []), severity: r.severity, score: r.score == null ? null : Number(r.score),
  summary: r.summary, info: parse(r.info, {}), kev: !!Number(r.kev), euvdId: r.euvd_id, epss: r.epss == null ? null : Number(r.epss),
  sources: parse(r.sources, []), present: !!Number(r.present), state: r.state, justification: r.justification || '', response: r.response || '',
  analysis: r.analysis || '', firstSeen: r.first_seen, lastSeen: r.last_seen, updatedAt: r.updated_at, updatedBy: r.updated_by,
});
const toFile = (r, withData = false) => r && ({
  id: r.id, productId: r.product_id, section: r.section, name: r.name, mime: r.mime, size: Number(r.size), sha256: r.sha256,
  meta: parse(r.meta, {}), uploadedAt: r.uploaded_at, uploadedBy: r.uploaded_by, ...(withData ? { data: buf(r.data) } : {}),
});
const toRelease = (r, withZip = false) => r && ({
  id: r.id, productId: r.product_id, version: r.version, note: r.note, manifest: parse(r.manifest, {}), sha256: r.sha256,
  createdAt: r.created_at, createdBy: r.created_by, ...(withZip ? { zip: buf(r.zip) } : {}),
});

export class Store {
  constructor(db) { this.db = db; }
  get dialect() { return this.db.dialect.name; }
  async ping() { await this.db.get('SELECT 1 AS ok'); return true; }
  async close() { await this.db.close(); }

  // ---------------------------------------------------------------- events (audit trail)
  async event(actor, action, detail = '', { assessmentId = '', productId = null } = {}, db = this.db) {
    await db.run('INSERT INTO events (id, assessment_id, product_id, at, actor, action, detail) VALUES (?,?,?,?,?,?,?)',
      [randomUUID(), assessmentId || '', productId, now(), actor, action, String(detail).slice(0, 2000)]);
  }
  async events({ assessmentId, productId }) {
    if (productId) return this.db.all('SELECT at, actor, action, detail FROM events WHERE product_id = ? OR (assessment_id <> \'\' AND assessment_id = (SELECT assessment_id FROM products WHERE id = ?)) ORDER BY at DESC LIMIT 500', [productId, productId]);
    return this.db.all('SELECT at, actor, action, detail FROM events WHERE assessment_id = ? ORDER BY at DESC LIMIT 200', [assessmentId]);
  }

  // ---------------------------------------------------------------- users & sessions
  async countUsers() { return Number((await this.db.get('SELECT COUNT(*) AS n FROM users')).n); }
  async listUsers() { return (await this.db.all('SELECT * FROM users ORDER BY email')).map(toUser); }
  async getUser(id) { return toUser(await this.db.get('SELECT * FROM users WHERE id = ?', [id])); }
  async getUserByEmail(email) { return toUser(await this.db.get('SELECT * FROM users WHERE email = ?', [String(email).toLowerCase()])); }
  async getPasswordHash(id) { return (await this.db.get('SELECT password_hash FROM users WHERE id = ?', [id]))?.password_hash || null; }
  async createUser({ email, name = '', passwordHash = null, authSource = 'local', globalRole = 'user', mustChange = false }) {
    const id = randomUUID();
    await this.db.run('INSERT INTO users (id, email, name, password_hash, auth_source, global_role, disabled, must_change, created_at) VALUES (?,?,?,?,?,?,0,?,?)',
      [id, String(email).toLowerCase(), name, passwordHash, authSource, globalRole, mustChange ? 1 : 0, now()]);
    return this.getUser(id);
  }
  async updateUser(id, fields) {
    const map = { name: 'name', globalRole: 'global_role', disabled: 'disabled', mustChange: 'must_change', passwordHash: 'password_hash', authSource: 'auth_source', lastLoginAt: 'last_login_at' };
    const sets = [], vals = [];
    for (const [k, col] of Object.entries(map)) if (k in fields) {
      sets.push(`${col} = ?`);
      vals.push(typeof fields[k] === 'boolean' ? (fields[k] ? 1 : 0) : fields[k]);
    }
    if (sets.length) await this.db.run(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, [...vals, id]);
    return this.getUser(id);
  }
  async deleteUser(id) { await this.db.run('DELETE FROM users WHERE id = ?', [id]); }
  async createSession(id, userId, ttlMs) {
    const t = now();
    await this.db.run('INSERT INTO sessions (id, user_id, created_at, expires_at, last_seen_at) VALUES (?,?,?,?,?)', [id, userId, t, new Date(Date.now() + ttlMs).toISOString(), t]);
  }
  async getSession(id) { return this.db.get('SELECT * FROM sessions WHERE id = ?', [id]); }
  async touchSession(id, idleTtlMs, absoluteExpiry) {
    const exp = new Date(Math.min(Date.now() + idleTtlMs, new Date(absoluteExpiry).getTime())).toISOString();
    await this.db.run('UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?', [now(), exp, id]);
  }
  async deleteSession(id) { await this.db.run('DELETE FROM sessions WHERE id = ?', [id]); }
  async deleteUserSessions(userId) { await this.db.run('DELETE FROM sessions WHERE user_id = ?', [userId]); }
  async purgeSessions() { await this.db.run('DELETE FROM sessions WHERE expires_at < ?', [now()]); }

  // ---------------------------------------------------------------- products & memberships
  async listProducts() { return (await this.db.all('SELECT * FROM products ORDER BY name')).map(toProduct); }
  async getProduct(id) { return toProduct(await this.db.get('SELECT * FROM products WHERE id = ?', [id])); }
  async getProductByAssessment(assessmentId) { return toProduct(await this.db.get('SELECT * FROM products WHERE assessment_id = ?', [assessmentId])); }
  async createProduct({ name, data, assessmentData }, actor, ownerUserId = null) {
    const id = randomUUID(), aid = randomUUID(), t = now();
    await this.db.tx(async (db) => {
      await db.run('INSERT INTO assessments (id, title, status, revision, data, created_at, created_by, updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?,?)',
        [aid, assessmentData.meta.title, assessmentData.meta.status, 1, json(assessmentData), t, actor, t, actor]);
      await db.run('INSERT INTO products (id, name, data, revision, assessment_id, created_at, created_by, updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?,?)',
        [id, name, json(data), 1, aid, t, actor, t, actor]);
      if (ownerUserId) await db.run('INSERT INTO memberships (product_id, user_id, role) VALUES (?,?,?)', [id, ownerUserId, 'owner']);
      await this.event(actor, 'product.create', name, { productId: id, assessmentId: aid }, db);
    });
    return this.getProduct(id);
  }
  async updateProduct(id, data, revision, actor) {
    return this.db.tx(async (db) => {
      const res = await db.run('UPDATE products SET name = ?, data = ?, revision = revision + 1, updated_at = ?, updated_by = ? WHERE id = ? AND revision = ?',
        [data.name || 'Unnamed product', json(data), now(), actor, id, revision]);
      if (res.changes !== 1) {
        const cur = toProduct(await db.get('SELECT * FROM products WHERE id = ?', [id]));
        if (!cur) return null;
        throw new ConflictError(cur);
      }
      await this.event(actor, 'product.update', `revision ${revision + 1}`, { productId: id }, db);
      return toProduct(await db.get('SELECT * FROM products WHERE id = ?', [id]));
    });
  }
  async deleteProduct(id, actor) {
    return this.db.tx(async (db) => {
      const p = toProduct(await db.get('SELECT * FROM products WHERE id = ?', [id]));
      if (!p) return false;
      // explicit deletes keep SQLite and PostgreSQL behaviour identical
      for (const t of ['findings', 'scans', 'sboms', 'files', 'releases', 'memberships']) await db.run(`DELETE FROM ${t} WHERE product_id = ?`, [id]);
      await db.run('DELETE FROM components WHERE product_id = ?', [id]);
      await db.run('DELETE FROM products WHERE id = ?', [id]);
      if (p.assessmentId) {
        await db.run('DELETE FROM snapshots WHERE assessment_id = ?', [p.assessmentId]);
        await db.run('DELETE FROM assessments WHERE id = ?', [p.assessmentId]);
      }
      await this.event(actor, 'product.delete', p.name, { productId: id }, db);
      return true;
    });
  }
  async memberships(productId) {
    return (await this.db.all('SELECT m.role, u.* FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.product_id = ? ORDER BY u.email', [productId]))
      .map((r) => ({ role: r.role, user: toUser(r) }));
  }
  async membershipsOfUser(userId) {
    return this.db.all('SELECT product_id AS "productId", role FROM memberships WHERE user_id = ?', [userId]);
  }
  async roleOf(userId, productId) {
    return (await this.db.get('SELECT role FROM memberships WHERE user_id = ? AND product_id = ?', [userId, productId]))?.role || null;
  }
  async setMembership(productId, userId, role, actor) {
    await this.db.tx(async (db) => {
      await db.run('DELETE FROM memberships WHERE product_id = ? AND user_id = ?', [productId, userId]);
      if (role) await db.run('INSERT INTO memberships (product_id, user_id, role) VALUES (?,?,?)', [productId, userId, role]);
      await this.event(actor, 'member.set', `${userId}: ${role || 'removed'}`, { productId }, db);
    });
  }
  async countOwners(productId) { return Number((await this.db.get("SELECT COUNT(*) AS n FROM memberships WHERE product_id = ? AND role = 'owner'", [productId])).n); }

  // ---------------------------------------------------------------- assessments
  async listOrphanAssessments() {
    return (await this.db.all('SELECT a.* FROM assessments a LEFT JOIN products p ON p.assessment_id = a.id WHERE p.id IS NULL')).map(toAssessment);
  }
  async attachProduct(assessmentId, name, data, actor) {
    const id = randomUUID(), t = now();
    await this.db.run('INSERT INTO products (id, name, data, revision, assessment_id, created_at, created_by, updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?,?)',
      [id, name, json(data), 1, assessmentId, t, actor, t, actor]);
    return this.getProduct(id);
  }
  async getAssessment(id) { return toAssessment(await this.db.get('SELECT * FROM assessments WHERE id = ?', [id])); }
  async updateAssessment(id, data, revision, actor, productId = null) {
    return this.db.tx(async (db) => {
      const res = await db.run('UPDATE assessments SET title = ?, status = ?, revision = revision + 1, data = ?, updated_at = ?, updated_by = ? WHERE id = ? AND revision = ?',
        [data.meta.title, data.meta.status, json(data), now(), actor, id, revision]);
      if (res.changes !== 1) {
        const cur = toAssessment(await db.get('SELECT * FROM assessments WHERE id = ?', [id]));
        if (!cur) return null;
        throw new ConflictError(cur);
      }
      await this.event(actor, 'update', `revision ${revision + 1}`, { assessmentId: id, productId }, db);
      return toAssessment(await db.get('SELECT * FROM assessments WHERE id = ?', [id]));
    });
  }
  async replaceAssessmentData(id, data, actor, productId) {
    return this.db.tx(async (db) => {
      await db.run('UPDATE assessments SET title = ?, status = ?, revision = revision + 1, data = ?, updated_at = ?, updated_by = ? WHERE id = ?',
        [data.meta.title, data.meta.status, json(data), now(), actor, id]);
      await this.event(actor, 'assessment.replace', data.meta.title, { assessmentId: id, productId }, db);
      return toAssessment(await db.get('SELECT * FROM assessments WHERE id = ?', [id]));
    });
  }
  async createSnapshot(assessmentId, { version, note, data, sha256 }, actor, productId = null) {
    const id = randomUUID();
    await this.db.tx(async (db) => {
      await db.run('INSERT INTO snapshots (id, assessment_id, version, note, data, sha256, created_at, created_by) VALUES (?,?,?,?,?,?,?,?)',
        [id, assessmentId, version, note || '', json(data), sha256, now(), actor]);
      await this.event(actor, 'snapshot', `version ${version} ${sha256}`, { assessmentId, productId }, db);
    });
    return this.getSnapshot(assessmentId, id);
  }
  async listSnapshots(assessmentId) {
    const rows = await this.db.all('SELECT id, version, note, sha256, created_at, created_by FROM snapshots WHERE assessment_id = ? ORDER BY created_at DESC', [assessmentId]);
    return rows.map((r) => ({ id: r.id, version: r.version, note: r.note, sha256: r.sha256, createdAt: r.created_at, createdBy: r.created_by }));
  }
  async getSnapshot(assessmentId, id) {
    const r = await this.db.get('SELECT * FROM snapshots WHERE assessment_id = ? AND id = ?', [assessmentId, id]);
    return r && { id: r.id, version: r.version, note: r.note, sha256: r.sha256, createdAt: r.created_at, createdBy: r.created_by, data: parse(r.data) };
  }

  // ---------------------------------------------------------------- components & SBOMs
  async listComponents(productId) { return (await this.db.all('SELECT * FROM components WHERE product_id = ? ORDER BY name', [productId])).map(toComponent); }
  async getComponent(id) { return toComponent(await this.db.get('SELECT * FROM components WHERE id = ?', [id])); }
  async createComponent(productId, { name, type, version, data }, actor) {
    const id = randomUUID(), t = now();
    await this.db.run('INSERT INTO components (id, product_id, name, type, version, data, created_at, updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?,?)',
      [id, productId, name, type, version || '', json(data || {}), t, t, actor]);
    await this.event(actor, 'component.create', `${name} ${version || ''}`, { productId });
    return this.getComponent(id);
  }
  async updateComponent(id, { name, type, version, data }, actor) {
    const c = await this.getComponent(id);
    await this.db.run('UPDATE components SET name = ?, type = ?, version = ?, data = ?, updated_at = ?, updated_by = ? WHERE id = ?',
      [name ?? c.name, type ?? c.type, version ?? c.version, json(data ?? c.data), now(), actor, id]);
    await this.event(actor, 'component.update', `${name ?? c.name} ${version ?? c.version}`, { productId: c.productId });
    return this.getComponent(id);
  }
  async deleteComponent(id, actor) {
    const c = await this.getComponent(id);
    if (!c) return false;
    await this.db.tx(async (db) => {
      for (const t of ['findings', 'sboms']) await db.run(`DELETE FROM ${t} WHERE component_id = ?`, [id]);
      await db.run('DELETE FROM components WHERE id = ?', [id]);
      await this.event(actor, 'component.delete', c.name, { productId: c.productId }, db);
    });
    return true;
  }
  async addSbom(componentId, productId, sbom, actor) {
    const id = randomUUID();
    await this.db.tx(async (db) => {
      await db.run('UPDATE sboms SET is_current = 0 WHERE component_id = ?', [componentId]);
      await db.run('INSERT INTO sboms (id, component_id, product_id, format, spec_version, filename, sha256, is_current, summary, packages, raw, uploaded_at, uploaded_by) VALUES (?,?,?,?,?,?,?,1,?,?,?,?,?)',
        [id, componentId, productId, sbom.format, sbom.specVersion, sbom.filename, sbom.sha256, json(sbom.summary), json(sbom.packages), sbom.raw, now(), actor]);
      await this.event(actor, 'sbom.import', `${sbom.filename} (${sbom.packages.length} packages, ${sbom.format} ${sbom.specVersion})`, { productId }, db);
    });
    return this.getSbom(id);
  }
  async getSbom(id, withPackages = false) { return toSbom(await this.db.get('SELECT * FROM sboms WHERE id = ?', [id]), withPackages); }
  async getSbomRaw(id) { const r = await this.db.get('SELECT raw, filename, format FROM sboms WHERE id = ?', [id]); return r && { raw: buf(r.raw), filename: r.filename, format: r.format }; }
  async currentSbom(componentId, withPackages = false) { return toSbom(await this.db.get('SELECT * FROM sboms WHERE component_id = ? AND is_current = 1', [componentId]), withPackages); }
  async listSboms(componentId) {
    return (await this.db.all('SELECT id, component_id, product_id, format, spec_version, filename, sha256, is_current, summary, uploaded_at, uploaded_by FROM sboms WHERE component_id = ? ORDER BY uploaded_at DESC', [componentId])).map((r) => toSbom(r));
  }

  // ---------------------------------------------------------------- vulnerability findings
  async listFindings(productId, componentId = null) {
    const rows = componentId
      ? await this.db.all('SELECT * FROM findings WHERE component_id = ? ORDER BY score DESC, vuln_id', [componentId])
      : await this.db.all('SELECT * FROM findings WHERE product_id = ? ORDER BY score DESC, vuln_id', [productId]);
    return rows.map(toFinding);
  }
  async getFinding(id) { return toFinding(await this.db.get('SELECT * FROM findings WHERE id = ?', [id])); }
  /** Upsert findings of one component scan. Existing triage decisions are kept; findings no longer reported are marked not present. */
  async mergeFindings(productId, componentId, found, { replace = true } = {}) {
    const t = now();
    let added = 0;
    await this.db.tx(async (db) => {
      if (replace) await db.run('UPDATE findings SET present = 0 WHERE component_id = ?', [componentId]);
      for (const f of found) {
        const existing = await db.get('SELECT id, state FROM findings WHERE component_id = ? AND vuln_id = ? AND pkg_key = ?', [componentId, f.vulnId, f.pkgKey]);
        if (existing) {
          await db.run(`UPDATE findings SET present = 1, last_seen = ?, aliases = ?, severity = ?, score = ?, summary = ?, info = ?, kev = ?, euvd_id = COALESCE(?, euvd_id),
                        epss = COALESCE(?, epss), sources = ?, pkg_name = ?, pkg_version = ?, purl = ? WHERE id = ?`,
          [t, json(f.aliases), f.severity, f.score, f.summary, json(f.info), f.kev ? 1 : 0, f.euvdId || null, f.epss ?? null, json(f.sources), f.pkgName, f.pkgVersion, f.purl, existing.id]);
          // an imported analysis (e.g. from a VEX document) may set the state if nobody triaged yet
          if (f.state && existing.state === 'in_triage') await db.run('UPDATE findings SET state = ?, justification = ?, response = ?, analysis = ? WHERE id = ?', [f.state, f.justification || '', f.response || '', f.analysis || '', existing.id]);
        } else {
          added++;
          await db.run(`INSERT INTO findings (id, product_id, component_id, vuln_id, pkg_key, pkg_name, pkg_version, purl, aliases, severity, score, summary, info, kev, euvd_id, epss,
                        sources, present, state, justification, response, analysis, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?,?)`,
          [randomUUID(), productId, componentId, f.vulnId, f.pkgKey, f.pkgName, f.pkgVersion, f.purl, json(f.aliases), f.severity, f.score, f.summary, json(f.info),
            f.kev ? 1 : 0, f.euvdId || null, f.epss ?? null, json(f.sources), f.state || 'in_triage', f.justification || '', f.response || '', f.analysis || '', t, t]);
        }
      }
    });
    return { added, total: found.length };
  }
  async updateFindingEnrichment(id, { kev, euvdId, epss }) {
    await this.db.run('UPDATE findings SET kev = ?, euvd_id = COALESCE(?, euvd_id), epss = COALESCE(?, epss) WHERE id = ?', [kev ? 1 : 0, euvdId || null, epss ?? null, id]);
  }
  async triageFinding(id, { state, justification, response, analysis }, actor) {
    const f = await this.getFinding(id);
    await this.db.run('UPDATE findings SET state = ?, justification = ?, response = ?, analysis = ?, updated_at = ?, updated_by = ? WHERE id = ?',
      [state, justification || '', response || '', analysis || '', now(), actor, id]);
    await this.event(actor, 'vuln.triage', `${f.vulnId} in ${f.pkgName}@${f.pkgVersion}: ${state}${justification ? ` (${justification})` : ''}`, { productId: f.productId });
    return this.getFinding(id);
  }
  async addScan(productId, componentId, actor) {
    const id = randomUUID();
    await this.db.run('INSERT INTO scans (id, product_id, component_id, started_at, actor, status) VALUES (?,?,?,?,?,?)', [id, productId, componentId, now(), actor, 'running']);
    return id;
  }
  async finishScan(id, status, summary) {
    await this.db.run('UPDATE scans SET finished_at = ?, status = ?, summary = ? WHERE id = ?', [now(), status, json(summary), id]);
  }
  async interruptStaleScans() {
    await this.db.run("UPDATE scans SET status = 'interrupted', finished_at = ? WHERE status = 'running' AND started_at < ?", [now(), new Date(Date.now() - 30 * 60_000).toISOString()]);
  }
  async lastScans(productId) {
    const rows = await this.db.all('SELECT * FROM scans WHERE product_id = ? ORDER BY started_at DESC LIMIT 50', [productId]);
    return rows.map((r) => ({ id: r.id, componentId: r.component_id, startedAt: r.started_at, finishedAt: r.finished_at, actor: r.actor, status: r.status, summary: parse(r.summary, {}) }));
  }

  // ---------------------------------------------------------------- files
  async listFiles(productId) {
    return (await this.db.all('SELECT id, product_id, section, name, mime, size, sha256, meta, uploaded_at, uploaded_by FROM files WHERE product_id = ? ORDER BY section, uploaded_at', [productId])).map((r) => toFile(r));
  }
  async getFile(id, withData = false) { return toFile(await this.db.get(`SELECT ${withData ? '*' : 'id, product_id, section, name, mime, size, sha256, meta, uploaded_at, uploaded_by'} FROM files WHERE id = ?`, [id]), withData); }
  async addFile(productId, { section, name, mime, data, sha256, meta }, actor) {
    const id = randomUUID();
    await this.db.run('INSERT INTO files (id, product_id, section, name, mime, size, sha256, meta, data, uploaded_at, uploaded_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      [id, productId, section, name, mime, data.length, sha256, json(meta || {}), data, now(), actor]);
    await this.event(actor, 'file.add', `${section}: ${name} (${sha256.slice(0, 12)})`, { productId });
    return this.getFile(id);
  }
  async updateFileMeta(id, meta, section, actor) {
    const f = await this.getFile(id);
    await this.db.run('UPDATE files SET meta = ?, section = ? WHERE id = ?', [json(meta), section || f.section, id]);
    await this.event(actor, 'file.update', f.name, { productId: f.productId });
    return this.getFile(id);
  }
  async deleteFile(id, actor) {
    const f = await this.getFile(id);
    if (!f) return false;
    await this.db.run('DELETE FROM files WHERE id = ?', [id]);
    await this.event(actor, 'file.delete', `${f.section}: ${f.name}`, { productId: f.productId });
    return true;
  }

  // ---------------------------------------------------------------- releases (frozen technical documentation)
  async addRelease(productId, { version, note, manifest, sha256, zip }, actor) {
    const id = randomUUID();
    await this.db.tx(async (db) => {
      await db.run('INSERT INTO releases (id, product_id, version, note, manifest, sha256, zip, created_at, created_by) VALUES (?,?,?,?,?,?,?,?,?)',
        [id, productId, version, note || '', json(manifest), sha256, zip, now(), actor]);
      await this.event(actor, 'release.freeze', `technical documentation ${version} ${sha256}`, { productId }, db);
    });
    return this.getRelease(id);
  }
  async listReleases(productId) {
    return (await this.db.all('SELECT id, product_id, version, note, manifest, sha256, created_at, created_by FROM releases WHERE product_id = ? ORDER BY created_at DESC', [productId])).map((r) => toRelease(r));
  }
  async getRelease(id, withZip = false) { return toRelease(await this.db.get(`SELECT ${withZip ? '*' : 'id, product_id, version, note, manifest, sha256, created_at, created_by'} FROM releases WHERE id = ?`, [id]), withZip); }

  // ---------------------------------------------------------------- vulnerability database cache
  async cacheGet(key, maxAgeMs) {
    const r = await this.db.get('SELECT data, fetched_at FROM vuln_cache WHERE key = ?', [key]);
    if (!r || Date.now() - new Date(r.fetched_at).getTime() > maxAgeMs) return null;
    return parse(r.data);
  }
  async cacheSet(key, data) {
    await this.db.run('INSERT INTO vuln_cache (key, data, fetched_at) VALUES (?,?,?) ON CONFLICT (key) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at', [key, json(data), now()]);
  }
}
