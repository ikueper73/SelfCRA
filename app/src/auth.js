// Authentication: local accounts (AUTH_MODE=local) or SSO through an authenticating proxy (AUTH_MODE=header).
// Users are identified by e-mail. When SSO is switched on, an existing local user with the same e-mail is
// converted to an SSO user on first sign-in (password removed). Global roles can optionally come from the
// identity provider (Entra app roles via X-MS-CLIENT-PRINCIPAL, or a groups/roles header).
import { randomBytes, scrypt as scryptCb, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import express from 'express';
import { GLOBAL_ROLES } from './shared/roles.js';

const scrypt = promisify(scryptCb);
const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const COOKIE = 'cra_session';

export function authConfig(env = process.env) {
  const mode = (env.AUTH_MODE || 'local').toLowerCase();
  if (mode === 'basic') throw new Error('AUTH_MODE=basic was replaced by AUTH_MODE=local (in-app accounts). Set INITIAL_ADMIN_EMAIL / INITIAL_ADMIN_PASSWORD to create the first administrator.');
  if (!['local', 'header', 'none'].includes(mode)) throw new Error(`Unknown AUTH_MODE "${mode}" (use local, header or none)`);
  const roleMap = Object.fromEntries(String(env.ROLE_MAP || 'CRA.Admin=admin,CRA.Auditor=auditor,CRA.Creator=creator')
    .split(',').map((x) => x.split('=').map((s) => s.trim())).filter(([k, v]) => k && GLOBAL_ROLES.some((r) => r.id === v)));
  return {
    mode,
    header: (env.AUTH_HEADER || 'x-forwarded-user').toLowerCase(),
    nameHeader: (env.AUTH_NAME_HEADER || '').toLowerCase(),
    autoProvision: (env.SSO_AUTO_PROVISION || 'true') !== 'false',
    roleSource: (env.ROLE_SOURCE || 'app').toLowerCase(), // app | entra | header
    rolesHeader: (env.AUTH_ROLES_HEADER || 'x-forwarded-groups').toLowerCase(),
    roleMap,
    initialAdminEmail: (env.INITIAL_ADMIN_EMAIL || '').trim().toLowerCase(),
    initialAdminPassword: env.INITIAL_ADMIN_PASSWORD || '',
    idleMs: Number(env.SESSION_IDLE_MINUTES || 120) * 60_000,
    maxMs: Number(env.SESSION_MAX_HOURS || 12) * 3_600_000,
    cookieSecure: (env.COOKIE_SECURE || 'auto').toLowerCase(), // auto | true | false
  };
}

// ------------------------------------------------------------------ passwords
export async function hashPassword(pw) {
  const salt = randomBytes(16);
  const key = await scrypt(pw, salt, 64, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}
export async function verifyPassword(pw, stored) {
  const [alg, N, r, p, salt, hash] = String(stored || '').split('$');
  if (alg !== 'scrypt') return false;
  const expected = Buffer.from(hash, 'base64');
  const key = await scrypt(String(pw), Buffer.from(salt, 'base64'), expected.length, { N: Number(N), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem });
  return timingSafeEqual(key, expected);
}
export function passwordProblem(pw, email = '') {
  if (typeof pw !== 'string' || pw.length < 12) return 'Password must have at least 12 characters.';
  if (pw.length > 200) return 'Password is too long.';
  const local = String(email || '').split('@')[0].toLowerCase();
  if (local.length >= 4 && pw.toLowerCase().includes(local)) return 'Password must not contain the e-mail name.';
  if (new Set(pw).size < 5) return 'Password is too simple.';
  return null;
}
const validEmail = (e) => /^[^\s@]+@[^\s@]+$/.test(String(e || '')) && String(e).length <= 254;
const tokenHash = (t) => createHash('sha256').update(t).digest('hex');

// ------------------------------------------------------------------ brute-force protection (per process)
const failures = new Map();
function tooMany(key) {
  const f = failures.get(key);
  return f && f.count >= 8 && Date.now() - f.first < 15 * 60_000;
}
function fail(key) {
  const f = failures.get(key);
  if (!f || Date.now() - f.first > 15 * 60_000) failures.set(key, { count: 1, first: Date.now() });
  else f.count++;
}

// ------------------------------------------------------------------ identity-provider roles
function idpRoles(req, cfg) {
  if (cfg.roleSource === 'entra') {
    const raw = req.get('x-ms-client-principal');
    if (!raw) return null;
    try {
      const p = JSON.parse(Buffer.from(raw, 'base64').toString('utf8'));
      const typ = p.role_typ || 'roles';
      return (p.claims || []).filter((c) => c.typ === typ || c.typ === 'roles').map((c) => c.val);
    } catch { return null; }
  }
  if (cfg.roleSource === 'header') {
    const v = req.get(cfg.rolesHeader);
    return v == null ? null : v.split(/[,;\s]+/).filter(Boolean);
  }
  return null;
}
function mapGlobalRole(values, cfg) {
  const order = ['admin', 'auditor', 'creator'];
  const got = new Set((values || []).map((v) => cfg.roleMap[v]).filter(Boolean));
  return order.find((r) => got.has(r)) || 'user';
}

const publicUser = (u, extra = {}) => u && ({ id: u.id, email: u.email, name: u.name, globalRole: u.globalRole, authSource: u.authSource, mustChange: u.mustChange, ...extra });

// ------------------------------------------------------------------ middleware & routes
export async function setupAuth(app, store, cfg, log = console) {
  let setupToken = null;

  // bootstrap the first administrator
  if (await store.countUsers() === 0) {
    if (cfg.mode === 'local' && cfg.initialAdminEmail) {
      const problem = cfg.initialAdminPassword ? passwordProblem(cfg.initialAdminPassword, cfg.initialAdminEmail) : 'INITIAL_ADMIN_PASSWORD is not set.';
      if (problem) throw new Error(`INITIAL_ADMIN_PASSWORD rejected: ${problem}`);
      await store.createUser({ email: cfg.initialAdminEmail, name: 'Administrator', passwordHash: await hashPassword(cfg.initialAdminPassword), authSource: 'local', globalRole: 'admin', mustChange: true });
      log.log(`Created initial administrator ${cfg.initialAdminEmail} (password change required at first sign-in).`);
    } else if (cfg.mode === 'local') {
      setupToken = randomBytes(18).toString('base64url');
      log.log(`No users exist. Open the application and complete the setup with this one-time token: ${setupToken}`);
    } else if (cfg.mode === 'header' && cfg.initialAdminEmail) {
      await store.createUser({ email: cfg.initialAdminEmail, name: '', authSource: 'sso', globalRole: 'admin' });
      log.log(`Pre-registered SSO administrator ${cfg.initialAdminEmail}.`);
    } else if (cfg.mode === 'header') {
      log.warn('No users exist and INITIAL_ADMIN_EMAIL is not set: SSO users are provisioned without rights until an administrator exists.');
    }
  }
  if (cfg.mode === 'none') log.warn('AUTH_MODE=none: every visitor is an administrator. Use only for local development.');

  const secureCookie = (req) => cfg.cookieSecure === 'true' || (cfg.cookieSecure === 'auto' && req.secure);
  const setCookie = (req, res, token) => res.cookie(COOKIE, token, { httpOnly: true, sameSite: 'strict', secure: secureCookie(req), path: '/', maxAge: cfg.maxMs });
  const readCookie = (req) => {
    const m = /(?:^|;\s*)cra_session=([^;]+)/.exec(req.get('cookie') || '');
    return m ? decodeURIComponent(m[1]) : null;
  };
  const newSession = async (req, res, user) => {
    const token = randomBytes(32).toString('base64url');
    await store.createSession(tokenHash(token), user.id, cfg.maxMs);
    await store.updateUser(user.id, { lastLoginAt: new Date().toISOString() });
    setCookie(req, res, token);
  };

  // resolve the current user for every request
  app.use(async (req, _res, next) => {
    try {
      req.user = null;
      if (cfg.mode === 'none') {
        req.user = (await store.getUserByEmail('anonymous@localhost')) || await store.createUser({ email: 'anonymous@localhost', name: 'Anonymous (AUTH_MODE=none)', authSource: 'none', globalRole: 'admin' });
      } else if (cfg.mode === 'header') {
        const ident = String(req.get(cfg.header) || '').trim().toLowerCase();
        if (ident) {
          let u = await store.getUserByEmail(ident);
          const roles = idpRoles(req, cfg);
          const name = cfg.nameHeader ? String(req.get(cfg.nameHeader) || '').slice(0, 200) : '';
          if (!u && cfg.autoProvision) {
            const first = await store.countUsers() === 0;
            u = await store.createUser({ email: ident, name, authSource: 'sso', globalRole: first ? 'admin' : 'user' });
            await store.event(ident, 'user.provision', `SSO user created${first ? ' (first user → admin)' : ''}`);
          }
          if (u) {
            const patch = {};
            if (u.authSource !== 'sso') { patch.authSource = 'sso'; patch.passwordHash = null; patch.mustChange = false; }   // local → SSO-managed
            if (roles) { const g = mapGlobalRole(roles, cfg); if (g !== u.globalRole) patch.globalRole = g; }
            if (name && !u.name) patch.name = name;
            if (Object.keys(patch).length) {
              u = await store.updateUser(u.id, patch);
              await store.event(ident, 'user.sync', Object.keys(patch).join(', '));
            }
            req.user = u.disabled ? null : { ...u, roleFromIdp: !!roles };
          }
          req.identity = ident;
        }
      } else {
        const token = readCookie(req);
        if (token) {
          const s = await store.getSession(tokenHash(token));
          if (s && new Date(s.expires_at) > new Date()) {
            const u = await store.getUser(s.user_id);
            if (u && !u.disabled && u.authSource === 'local') {
              req.user = u;
              req.sessionId = s.id;
              if (Date.now() - new Date(s.last_seen_at).getTime() > 60_000) {
                await store.touchSession(s.id, cfg.idleMs, new Date(new Date(s.created_at).getTime() + cfg.maxMs).toISOString());
              }
            }
          }
        }
      }
      next();
    } catch (e) { next(e); }
  });

  const r = express.Router();
  r.use(express.json({ limit: '64kb' }));

  r.get('/state', async (req, res) => {
    res.json({
      mode: cfg.mode,
      user: publicUser(req.user, { roleFromIdp: !!req.user?.roleFromIdp }),
      setupRequired: !!setupToken && await store.countUsers() === 0,
      identity: cfg.mode === 'header' ? req.identity || null : undefined,
    });
  });

  r.post('/setup', async (req, res) => {
    const { token, email, name, password } = req.body || {};
    if (!setupToken || await store.countUsers() > 0) return res.status(409).json({ error: 'Setup already completed.' });
    if (typeof token !== 'string' || token.length !== setupToken.length || !timingSafeEqual(Buffer.from(token), Buffer.from(setupToken))) return res.status(403).json({ error: 'Invalid setup token (see the server log).' });
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid e-mail address.' });
    const p = passwordProblem(password, email);
    if (p) return res.status(400).json({ error: p });
    const u = await store.createUser({ email, name: String(name || '').slice(0, 200), passwordHash: await hashPassword(password), authSource: 'local', globalRole: 'admin' });
    setupToken = null;
    await store.event(u.email, 'user.setup', 'initial administrator created');
    await newSession(req, res, u);
    res.status(201).json({ user: publicUser(u) });
  });

  r.post('/login', async (req, res) => {
    if (cfg.mode !== 'local') return res.status(400).json({ error: 'Sign-in is handled by the single sign-on provider.' });
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const key = `${req.ip}|${email}`;
    if (tooMany(key) || tooMany(req.ip)) return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
    const u = await store.getUserByEmail(email);
    const hash = u ? await store.getPasswordHash(u.id) : null;
    // always run a scrypt so response time does not reveal whether the account exists
    const ok = await verifyPassword(password, hash || 'scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAA');
    if (!u || !hash || !ok || u.disabled || u.authSource !== 'local') {
      fail(key); fail(req.ip);
      if (u?.authSource === 'sso') return res.status(400).json({ error: 'This account signs in through single sign-on.' });
      return res.status(401).json({ error: 'E-mail or password is wrong, or the account is disabled.' });
    }
    failures.delete(key);
    await newSession(req, res, u);
    await store.event(u.email, 'user.login', req.ip);
    res.json({ user: publicUser(u) });
  });

  r.post('/logout', async (req, res) => {
    if (req.sessionId) await store.deleteSession(req.sessionId);
    res.clearCookie(COOKIE, { path: '/' });
    res.json({ ok: true, ssoLogout: cfg.mode === 'header' });
  });

  r.post('/password', async (req, res) => {
    if (!req.user || cfg.mode !== 'local') return res.status(400).json({ error: 'Not available.' });
    const { current, password } = req.body || {};
    if (!(await verifyPassword(String(current || ''), await store.getPasswordHash(req.user.id)))) return res.status(403).json({ error: 'Current password is wrong.' });
    const p = passwordProblem(password, req.user.email);
    if (p) return res.status(400).json({ error: p });
    if (password === current) return res.status(400).json({ error: 'Choose a new password.' });
    await store.updateUser(req.user.id, { passwordHash: await hashPassword(password), mustChange: false });
    await store.deleteUserSessions(req.user.id);
    await newSession(req, res, req.user);
    await store.event(req.user.email, 'user.password', 'changed');
    res.json({ ok: true });
  });

  app.use('/api/auth', r);
  setInterval(() => store.purgeSessions().catch(() => {}), 3_600_000).unref();
}

// Rejects unauthenticated API calls (except the auth endpoints) and cross-site state changes.
export function requireUser(cfg) {
  return (req, res, next) => {
    if (req.path.startsWith('/auth/')) return next();
    // CSRF: browsers cannot send this header cross-site without a CORS preflight (which we never allow)
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.get('x-requested-with') !== 'XMLHttpRequest') {
      return res.status(403).json({ error: 'Missing X-Requested-With header.' });
    }
    if (!req.user) {
      if (cfg.mode === 'header' && !req.identity) return res.status(401).json({ error: `Missing identity header ${cfg.header} – the app must run behind an authenticating proxy.` });
      if (cfg.mode === 'header') return res.status(403).json({ error: 'Your account is not registered or has been disabled. Ask an administrator for access.' });
      return res.status(401).json({ error: 'Sign-in required.' });
    }
    if (req.user.mustChange && !(req.method === 'GET' && (req.path === '/me' || req.path === '/catalog'))) return res.status(403).json({ error: 'Password change required.', code: 'must_change' });
    next();
  };
}

export const userLabel = (u) => (u ? u.email : 'anonymous');
export { publicUser, validEmail };
