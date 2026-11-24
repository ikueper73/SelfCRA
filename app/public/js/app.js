import { h, clear, toast, modal, badge } from './ui.js';
import { api } from './api.js';
import { state } from './state.js';
import { evaluate, visibleSteps, normalize } from '../shared/model.js';
import { renderStep } from './steps.js';
import { icon } from './icons.js';
import { productsPage, productPage } from './product.js';
import { usersPage, accountPage } from './admin.js';

const root = document.getElementById('root');
const saveState = document.getElementById('save-state');
const crumb = document.getElementById('crumb');
let ctx = null; // current assessment editor context
let roObserver = null;

// ---------------------------------------------------------------- boot & auth
window.addEventListener('hashchange', route);
window.addEventListener('beforeunload', (e) => { if (ctx?.dirty) e.preventDefault(); });
window.addEventListener('cra-auth', (e) => {
  if (e.detail.code === 'must_change') { state.mustChange = true; route(); return; }
  if (e.detail.status === 401 && !ctx?.dirty && state.authMode === 'local') boot();
});

async function boot() {
  try {
    const st = await api.authState();
    state.authMode = st.mode;
    if (!st.user) return authPage(st);
    const [me, cat] = await Promise.all([api.me().catch((e) => (e.data?.code === 'must_change' ? { user: st.user, mustChange: true } : Promise.reject(e))), api.catalog().catch(() => null)]);
    state.me = me;
    state.catalog = cat || state.catalog;
    renderUserMenu();
    state.mustChange = !!st.user.mustChange;
    if (state.mustChange) return accountPage(root, { crumb, forced: true, onDone: () => { state.mustChange = false; boot(); } });
    await route();
  } catch (e) {
    clear(root, h('p', { class: 'pad error' }, `Could not load the application: ${e.message}`));
  }
}

const initials = (u) => ((u.name || u.email).split(/[\s@._-]+/).filter(Boolean).slice(0, 2).map((x) => x[0].toUpperCase()).join('') || '?');
function renderUserMenu() {
  const u = state.me?.user;
  const menu = document.getElementById('user');
  if (!u) return clear(menu);
  clear(menu,
    state.me.can?.manageUsers ? h('a', { href: '#/admin/users', title: 'User administration' }, icon('people-settings'), 'Users') : null,
    h('a', { href: '#/account', title: `Signed in as ${u.email}` }, h('span', { class: 'avatar', 'aria-hidden': 'true' }, initials(u)), u.name || u.email),
    state.authMode === 'local' ? h('button', { type: 'button', class: 'link-btn', title: 'Sign out', onclick: async () => { await flush(); await api.logout(); ctx = null; state.me = null; location.hash = '#/'; boot(); } }, icon('sign-out'), 'Sign out') : null);
  document.getElementById('version').textContent = state.me.version ? `v${state.me.version}` : '';
}

function authPage(st) {
  crumb.textContent = '';
  clear(document.getElementById('user'));
  if (st.mode === 'header') {
    return clear(root, h('div', { class: 'auth-box card' }, h('h1', {}, 'No access'),
      h('p', {}, st.identity ? `You are signed in as ${st.identity}, but this account is not registered or has been disabled.` : 'The application could not identify you. It must be reached through the single sign-on proxy.'),
      h('p', { class: 'muted' }, 'Ask an administrator to give you access.')));
  }
  if (st.setupRequired) {
    const f = { token: '', email: '', name: '', password: '' };
    const inp = (k, label, type = 'text', help) => h('div', { class: 'field' }, h('label', {}, label), (() => { const i = h('input', { type, autocomplete: type === 'password' ? 'new-password' : 'off' }); i.addEventListener('input', () => { f[k] = i.value; }); return i; })(), help && h('div', { class: 'help' }, help));
    return clear(root, h('form', { class: 'auth-box card', onsubmit: async (e) => {
      e.preventDefault();
      try { await api.setup(f); toast('Administrator created.'); boot(); } catch (err) { toast(err.message, 'error'); }
    } }, h('h1', {}, 'First-time setup'),
    h('p', { class: 'muted' }, 'Create the first administrator. The one-time setup token is printed in the server log.'),
    inp('token', 'Setup token', 'password'), inp('email', 'E-mail', 'email'), inp('name', 'Name'), inp('password', 'Password', 'password', 'At least 12 characters.'),
    h('button', { class: 'btn primary', type: 'submit' }, 'Create administrator')));
  }
  const email = h('input', { type: 'email', autocomplete: 'username', required: true });
  const pw = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  clear(root, h('form', { class: 'auth-box card', onsubmit: async (e) => {
    e.preventDefault();
    try { await api.login(email.value, pw.value); boot(); } catch (err) { toast(err.message, 'error'); pw.value = ''; pw.focus(); }
  } }, h('h1', {}, 'Sign in'),
  h('div', { class: 'field' }, h('label', {}, 'E-mail'), email),
  h('div', { class: 'field' }, h('label', {}, 'Password'), pw),
  h('button', { class: 'btn primary', type: 'submit' }, 'Sign in'),
  h('p', { class: 'muted small' }, 'Forgot your password? An administrator can set a new one.')));
  email.focus();
}

// ---------------------------------------------------------------- routing
async function route() {
  if (!state.me) return;
  if (state.mustChange) return accountPage(root, { crumb, forced: true, onDone: () => { state.mustChange = false; boot(); } });
  const parts = location.hash.replace(/^#\/?/, '').split('/');
  const [view, id, sub, step] = parts;
  const editorRoute = view === 'p' && sub === 'a';
  if (ctx && (!editorRoute || id !== ctx.pid)) { await flush(); leaveEditor(); }
  saveState.textContent = '';
  try {
    if (editorRoute) return openEditor(id, step);
    if (view === 'p' && id) return productPage(root, id, parts.slice(2), { crumb });
    if (view === 'admin' && id === 'users') return usersPage(root, { crumb });
    if (view === 'account') return accountPage(root, { crumb, onDone: boot });
    return productsPage(root, { crumb });
  } catch (e) {
    clear(root, h('p', { class: 'pad error' }, e.message));
  }
}

// ---------------------------------------------------------------- risk-assessment editor (per product)
function leaveEditor() {
  ctx = null;
  roObserver?.disconnect();
  roObserver = null;
  document.body.classList.remove('readonly-mode');
}

async function openEditor(pid, stepId) {
  if (!ctx || ctx.pid !== pid) {
    const rec = await api.assessment(pid).catch((e) => { toast(e.message, 'error'); return null; });
    if (!rec) { location.hash = `#/p/${pid}`; return; }
    ctx = { pid, id: rec.id, revision: rec.revision, a: normalize(rec.data), catalog: state.catalog, perms: rec.permissions, product: rec.product,
      productComponents: rec.productComponents || [], dirty: false, saving: false, timer: null, hooks: [] };
    ctx.changed = changed;
    ctx.refresh = refresh;
    ctx.flush = flush;
    ctx.go = (s) => { location.hash = `#/p/${pid}/a/${s}`; };
    ctx.applyApproval = (r) => { ctx.revision = r.revision; ctx.a = normalize(r.data); openEditor(pid, ctx.step); };
    setReadOnly(!ctx.perms.edit);
  }
  const steps = visibleSteps(ctx.a);
  const step = steps.find((s) => s.id === stepId) || steps[0];
  ctx.step = step.id;
  ctx.hooks = [];
  ctx.ev = evaluate(ctx.a);

  const nav = h('nav', { class: 'steps', 'aria-label': 'Assessment steps' });
  const body = h('section', { class: 'step-body' });
  const idx = steps.indexOf(step);
  clear(root, h('div', { class: 'editor' }, nav, body));
  clear(body,
    !ctx.perms.edit ? h('div', { class: 'readonly-banner' }, `Read-only: your role on this product does not allow editing the risk assessment${ctx.perms.approve ? ' (you can approve and freeze)' : ''}.`) : null,
    h('div', { class: 'step-head' },
      h('div', {}, h('div', { class: 'eyebrow' }, `Risk assessment · Step ${idx + 1} of ${steps.length} · ${step.cra}`), h('h1', {}, step.label))),
    renderStep(ctx, step.id),
    h('div', { class: 'step-findings', id: 'step-findings' }),
    h('div', { class: 'step-nav' },
      idx > 0 ? h('a', { class: 'btn', href: `#/p/${pid}/a/${steps[idx - 1].id}` }, `← ${steps[idx - 1].label}`) : h('span'),
      idx < steps.length - 1 ? h('a', { class: 'btn primary', href: `#/p/${pid}/a/${steps[idx + 1].id}` }, `${steps[idx + 1].label} →`) : h('span')));
  ctx.nav = nav;
  refresh();
  window.scrollTo(0, 0);
}

// Viewers / approvers see the editor read-only: every control is disabled except those marked .ro-ok.
function setReadOnly(on) {
  document.body.classList.toggle('readonly-mode', on);
  roObserver?.disconnect();
  if (!on) return;
  const lock = (node) => {
    if (!(node instanceof Element)) return;
    for (const el of [node, ...node.querySelectorAll('input, select, textarea, button')]) {
      if (!el.matches?.('input, select, textarea, button') || el.closest('.ro-ok') || el.closest('nav') || el.closest('.modal header') || el.closest('.modal footer')) continue;
      el.disabled = true;
    }
  };
  roObserver = new MutationObserver((muts) => muts.forEach((m) => m.addedNodes.forEach(lock)));
  roObserver.observe(document.body, { childList: true, subtree: true });
  lock(document.body.querySelector('main'));
}

function refresh() {
  if (!ctx) return;
  ctx.ev = evaluate(ctx.a);
  crumb.replaceChildren(' › ', h('a', { href: `#/p/${ctx.pid}` }, ctx.product.name), ' › Risk assessment');
  const steps = visibleSteps(ctx.a);
  clear(ctx.nav, h('a', { href: `#/p/${ctx.pid}`, class: 'back' }, icon('arrow-left'), ctx.product.name), h('ol', {}, steps.map((s, i) => {
    const c = ctx.ev.byStep[s.id];
    const mark = c.blocker ? badge('blocker', c.blocker) : c.warning ? badge('warning', c.warning) : badge('ok', '✓');
    return h('li', { class: s.id === ctx.step ? 'active' : '' }, h('a', { href: `#/p/${ctx.pid}/a/${s.id}` }, h('span', { class: 'num' }, i + 1), h('span', { class: 'lbl' }, s.label), mark));
  })), h('div', { class: 'nav-summary' },
    ctx.ev.blockers ? badge('blocker', `${ctx.ev.blockers} blocking`) : badge('ok', 'No blocking findings'),
    ' ', badge('warning', `${ctx.ev.warnings} warnings`)));
  const box = document.getElementById('step-findings');
  if (box && ctx.step !== 'summary') {
    const f = ctx.ev.findings.filter((x) => x.step === ctx.step);
    clear(box, f.length ? [h('h3', {}, 'Checks for this step'), h('ul', { class: 'findings' }, f.map((x) => h('li', { class: x.level }, badge(x.level, x.level), ' ', x.message)))] : h('p', { class: 'ok-line' }, '✓ No open checks for this step.'));
  }
  for (const fn of ctx.hooks) fn(ctx.ev);
}

function changed({ rerender = false } = {}) {
  if (!ctx) return;
  if (!ctx.perms.edit) { if (rerender) openEditor(ctx.pid, ctx.step); else refresh(); return; }
  ctx.dirty = true;
  saveState.textContent = 'Unsaved changes…';
  saveState.className = 'save-state pending';
  clearTimeout(ctx.timer);
  ctx.timer = setTimeout(save, 800);
  if (rerender) openEditor(ctx.pid, ctx.step); else refresh();
}

async function save() {
  if (!ctx || !ctx.dirty) return;
  if (ctx.saving) { clearTimeout(ctx.timer); ctx.timer = setTimeout(save, 400); return; }
  const c = ctx;
  c.saving = true; c.dirty = false;
  saveState.textContent = 'Saving…';
  try {
    const r = await api.save(c.pid, c.revision, c.a);
    c.revision = r.revision;
    if (ctx === c && !c.dirty) { saveState.textContent = `Saved ${new Date(r.updatedAt).toLocaleTimeString()}`; saveState.className = 'save-state ok'; }
  } catch (e) {
    c.dirty = true;
    saveState.className = 'save-state error';
    if (e.status === 401) {
      // Sign-in session expired (proxy or in-app): keep the edits in memory, let the user sign in again.
      saveState.textContent = 'Sign-in expired';
      if (!document.querySelector('dialog.session')) {
        const dlg = modal('Sign-in session expired', h('div', {},
          h('p', {}, 'Your changes are kept in this window but are not saved yet.'),
          h('ol', {}, h('li', {}, 'Open the application in a new tab (button below) and sign in.'), h('li', {}, 'Come back to this tab and click “Save now”.'))),
        [h('a', { class: 'btn', href: './', target: '_blank', rel: 'noopener' }, 'Sign in again (new tab)'),
          h('button', { class: 'btn primary', onclick: () => { dlg.close(); save(); } }, 'Save now')]);
        dlg.classList.add('session');
      }
    } else if (e.status === 409) {
      saveState.textContent = 'Conflict';
      modal('Changed elsewhere', h('p', {}, `${e.message} Your latest edits on this page are not saved. Reload to get the current version (copy any text you need first).`),
        [h('button', { class: 'btn primary', onclick: () => { ctx = null; location.reload(); } }, 'Reload')]);
    } else if (e.status === 403) {
      saveState.textContent = 'Not saved';
      c.dirty = false;
      modal('Change not allowed', h('p', {}, e.message), [h('button', { class: 'btn primary', onclick: () => { ctx = null; location.reload(); } }, 'Reload')]);
    } else {
      saveState.textContent = 'Save failed – retrying';
      toast(`Save failed: ${e.message}`, 'error');
      c.timer = setTimeout(save, 5000);
    }
  } finally { c.saving = false; }
}

async function flush() {
  if (ctx?.dirty) { clearTimeout(ctx.timer); await save(); }
}

document.querySelector('.topbar .brand')?.prepend(icon('shield-checkmark', 24));
boot();
