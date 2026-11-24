// Product pages: list, overview (Annex VII status), components & SBOMs, vulnerabilities, technical
// documentation & evidence, releases, members, activity.
import { h, clear, toast, modal, badge, field, chips } from './ui.js';
import { api } from './api.js';
import { state, roleLabel, fmtDate, fmtDay, bytes } from './state.js';
import { normalizeProduct } from '../shared/techdoc.js';
import { icon } from './icons.js';

const cat = () => state.catalog;
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'none', 'unknown'];
const sevBadge = (sev, score) => h('span', { class: `sev sev-${sev || 'unknown'}` }, `${sev || 'unknown'}${score != null ? ` ${score}` : ''}`);
const stateLabel = (id) => cat().VEX_STATES.find((s) => s.id === id)?.label || id;
const typeLabel = (id) => cat().COMPONENT_TYPES.find((t) => t.id === id)?.label || id;
const statusBadge = (st) => badge(st === 'complete' ? 'ok' : st === 'partial' ? 'warning' : 'blocker', st);
const pickFile = (accept) => new Promise((resolve) => {
  const i = h('input', { type: 'file', accept, class: 'hidden' });
  i.addEventListener('change', () => resolve(i.files[0] || null));
  document.body.append(i); i.click(); setTimeout(() => i.remove(), 60_000);
});
const section = (title, ...body) => h('section', { class: 'card' }, title && h('h2', {}, title), body);

// ======================================================================== product list
export async function productsPage(root, { crumb }) {
  crumb.textContent = '';
  const [items, examples] = await Promise.all([api.products(), api.examples().catch(() => [])]);
  const canCreate = state.me.can.createProducts;
  const name = h('input', { type: 'text', placeholder: 'e.g. Smart pool controller PC-200', 'aria-label': 'Product name' });
  const mk = { consumer: h('input', { type: 'checkbox' }), professional: h('input', { type: 'checkbox', checked: true }) };
  const goto = (r) => { location.hash = `#/p/${r.id}`; if (r.warnings?.length) toast(r.warnings.join(' ')); };
  const fileJson = async () => { const f = await pickFile('.json,application/json'); if (!f) return; try { goto(await api.importJson(JSON.parse(await f.text()))); } catch (e) { toast(`Import failed: ${e.message}`, 'error'); } };
  const fileXlsx = async () => { const f = await pickFile('.xlsx'); if (!f) return; try { goto(await api.importXlsx(await f.arrayBuffer())); } catch (e) { toast(`Import failed: ${e.message}`, 'error'); } };

  clear(root, h('div', { class: 'page' },
    canCreate ? h('section', { class: 'card new' },
      h('h1', {}, 'New product'),
      h('p', { class: 'muted' }, 'Each product gets its components (firmware, backend, apps …), SBOMs and vulnerability tracking, a cybersecurity risk assessment (Art. 13) and the technical documentation per Annex VII.'),
      h('div', { class: 'row' },
        h('div', { class: 'field grow' }, h('label', {}, 'Product name'), name),
        h('fieldset', { class: 'markets' }, h('legend', {}, 'Placed on the market for'),
          h('label', { class: 'check' }, mk.consumer, ' Consumers'), h('label', { class: 'check' }, mk.professional, ' Commercial / industrial users')),
        h('button', { class: 'btn primary', onclick: async () => {
          const m = Object.entries(mk).filter(([, c]) => c.checked).map(([k]) => k);
          if (!m.length) return toast('Select at least one market.', 'error');
          goto(await api.createProduct(name.value.trim() || 'New product', m));
        } }, icon('add'), 'Create product')),
      h('div', { class: 'row small-gap' }, h('span', { class: 'muted' }, 'Or:'),
        h('button', { class: 'btn small', onclick: fileXlsx }, 'Import Excel risk assessment (.xlsx)'),
        h('button', { class: 'btn small', onclick: fileJson }, 'Import risk assessment JSON'),
        examples.map((x) => h('button', { class: 'btn small ghost', onclick: async () => goto(await api.fromExample(x.id)) }, `Load ${x.title}`))))
      : null,
    section('Products', items.length ? h('table', { class: 'list' },
      h('thead', {}, h('tr', {}, ['Product', 'Your role', 'Components', 'Open vulnerabilities', 'Risk assessment', 'Annex VII', 'Last change'].map((t) => h('th', {}, t)))),
      h('tbody', {}, items.map((p) => h('tr', {},
        h('td', {}, h('a', { href: `#/p/${p.id}` }, p.name)),
        h('td', {}, p.role ? roleLabel(p.role) : h('span', { class: 'muted' }, roleLabel(state.me.user.globalRole))),
        h('td', {}, p.components),
        h('td', {}, p.vulns.open ? [badge(p.vulns.kevOpen ? 'blocker' : 'warning', p.vulns.open), p.vulns.kevOpen ? [' ', badge('blocker', `${p.vulns.kevOpen} actively exploited`)] : null] : badge('ok', '0')),
        h('td', {}, p.assessment ? [p.assessment.status.replace('_', ' '), ' ', p.assessment.blockers ? badge('blocker', `${p.assessment.blockers} blocking`) : badge('ok', '✓')] : '—'),
        h('td', {}, badge(p.techdoc.complete === p.techdoc.total ? 'ok' : 'warning', `${p.techdoc.complete}/${p.techdoc.total} complete`)),
        h('td', { class: 'muted small' }, `${fmtDate(p.updatedAt)} · ${p.updatedBy || ''}`))))) : h('p', { class: 'muted' }, canCreate ? 'No products yet.' : 'You have not been added to a product yet. Ask a product owner or an administrator.'))));
}

// ======================================================================== product shell
const NAV = [
  ['', 'Overview', 'home'], ['a', 'Risk assessment', 'shield-checkmark'], ['components', 'Components & SBOMs', 'cube'], ['vulns', 'Vulnerabilities', 'bug'],
  ['docs', 'Technical documentation', 'document-text'], ['releases', 'Releases', 'archive'], ['members', 'Members', 'people'], ['activity', 'Activity', 'history'],
];

export async function productPage(root, pid, rest, { crumb }) {
  const p = await api.product(pid).catch((e) => { toast(e.message, 'error'); location.hash = '#/'; return null; });
  if (!p) return;
  p.data = normalizeProduct(p.data);
  const [rawSub = '', id] = rest;
  const sub = rawSub.split('?')[0];
  crumb.replaceChildren(' › ', h('a', { href: `#/p/${pid}` }, p.name));
  const body = h('section', { class: 'step-body' });
  const vulnOpen = p.components.reduce((n, c) => n + c.vulns.open, 0);
  const nav = h('nav', { class: 'steps', 'aria-label': 'Product sections' },
    h('a', { href: '#/', class: 'back' }, icon('arrow-left'), 'All products'),
    h('div', { class: 'nav-title' }, p.name, h('div', { class: 'small muted' }, `Your role: ${roleLabel(p.role || state.me.user.globalRole)}`)),
    h('ol', {}, NAV.map(([k, label, ic]) => {
      const mark = k === 'vulns' && vulnOpen ? badge('warning', vulnOpen) : k === 'docs' ? badge(p.techdoc.complete === 8 ? 'ok' : 'warning', `${p.techdoc.complete}/8`)
        : k === 'a' && p.assessment?.blockers ? badge('blocker', p.assessment.blockers) : null;
      return h('li', { class: (sub === k || (k === 'components' && sub === 'component')) ? 'active' : '' }, h('a', { href: `#/p/${pid}${k ? `/${k}` : ''}${k === 'a' ? '/profile' : ''}` }, icon(ic), h('span', { class: 'lbl' }, label), mark));
    })));
  clear(root, h('div', { class: 'editor' }, nav, body));
  const pages = { '': overview, components, component, vulns, docs, releases, members, activity };
  await (pages[sub] || overview)(body, p, id);
  window.scrollTo(0, 0);
}

const head = (title, sub) => h('div', { class: 'step-head' }, h('div', {}, sub ? h('div', { class: 'eyebrow' }, sub) : null, h('h1', {}, title)));

// ======================================================================== overview
const ITEM_LINKS = {
  1: [['Product description', 'a/product'], ['Components', 'components'], ['Hardware photos & manual', 'docs']],
  2: [['Architecture', 'a/architecture'], ['SBOMs', 'components'], ['Vulnerabilities', 'vulns'], ['CVD, updates, production', 'docs']],
  3: [['Risk assessment', 'a/summary']], 4: [['Support period', 'a/support']], 5: [['Standards', 'a/standards']],
  6: [['Test reports', 'docs']], 7: [['Declaration of conformity', 'docs']], 8: [['SBOMs', 'components'], ['SBOM procedure', 'docs']],
};
async function overview(body, p) {
  const t = p.techdoc;
  const v = p.components.reduce((s, c) => ({ open: s.open + c.vulns.open, kev: s.kev + c.vulns.kevOpen, crit: s.crit + c.vulns.critical + c.vulns.high }), { open: 0, kev: 0, crit: 0 });
  const sw = p.components.filter((c) => !cat().COMPONENT_TYPES.find((x) => x.id === c.type)?.noSbom);
  const tile = (n, l, lvl, href) => h('a', { class: `tile ${lvl || ''}`, href }, h('div', { class: 'n' }, n), h('div', { class: 'l' }, l));
  clear(body, head(p.name, 'Product overview · CRA technical documentation (Art. 31, Annex VII)'),
    h('div', { class: 'tiles' },
      tile(`${t.complete}/8`, 'Annex VII items complete', t.complete === 8 ? 'ok' : 'warning', `#/p/${p.id}/docs`),
      tile(p.components.length, 'Components', '', `#/p/${p.id}/components`),
      tile(`${sw.filter((c) => c.sbom).length}/${sw.length}`, 'SBOMs imported', sw.every((c) => c.sbom) && sw.length ? 'ok' : 'warning', `#/p/${p.id}/components`),
      tile(v.open, 'Open vulnerabilities', v.kev ? 'blocker' : v.open ? 'warning' : 'ok', `#/p/${p.id}/vulns`),
      tile(v.kev, 'Actively exploited', v.kev ? 'blocker' : 'ok', `#/p/${p.id}/vulns`),
      tile(p.assessment?.blockers ?? '—', 'Risk assessment blockers', p.assessment?.blockers ? 'blocker' : 'ok', `#/p/${p.id}/a/summary`),
      tile(p.releases.length ? p.releases[0].version : '—', 'Last documentation release', p.releases.length ? 'ok' : '', `#/p/${p.id}/releases`)),
    v.kev ? art14Banner(v.kev) : null,
    section('Annex VII – technical documentation status',
      h('p', { class: 'muted small' }, `Keep the documentation until: ${t.retention} (Art. 13(13)). Draw it up before placing on the market and keep it up to date during the support period (Art. 31).`),
      h('div', { class: 'annex7' }, t.items.map((i) => h('details', { class: `a7 ${i.status}`, open: i.status !== 'complete' && i.blockers > 0 },
        h('summary', {}, h('span', { class: 'a7-id' }, i.id), h('span', { class: 'a7-title' }, i.title, h('span', { class: 'muted small' }, ` · ${i.annex}`)), statusBadge(i.status)),
        h('ul', { class: 'checks' }, i.checks.map((c) => h('li', { class: c.ok ? 'ok' : c.level }, c.ok ? '✓ ' : c.level === 'blocker' ? '✗ ' : '! ', c.text))),
        h('div', { class: 'row small-gap' }, h('span', { class: 'small muted' }, 'Work on it:'), (ITEM_LINKS[i.id] || []).map(([l, href]) => h('a', { class: 'btn small ghost', href: `#/p/${p.id}/${href}` }, l))))))),
  );
}

function art14Banner(n) {
  return h('div', { class: 'readiness blocker' },
    `${n} open vulnerability(ies) are listed as actively exploited (CISA KEV / ENISA EUVD). If an actively exploited vulnerability is contained in your product, Art. 14 CRA requires an early warning to the CSIRT and ENISA via the single reporting platform within 24 hours of becoming aware, a notification within 72 hours and a final report within 14 days after a corrective measure is available. Triage these findings first.`);
}

// ======================================================================== components & SBOMs
async function components(body, p) {
  const list = await api.components(p.id);
  const can = p.permissions;
  const form = { name: '', type: 'firmware', version: '', data: { description: '' } };
  const scanState = h('div', {});
  const render = (comps) => h('table', { class: 'list' },
    h('thead', {}, h('tr', {}, ['Component', 'Type', 'Version', 'SBOM', 'Vulnerabilities (open)', ''].map((t) => h('th', {}, t)))),
    h('tbody', {}, comps.length ? comps.map((c) => h('tr', {},
      h('td', {}, h('a', { href: `#/p/${p.id}/component/${c.id}` }, c.name), c.data?.description ? h('div', { class: 'small muted' }, c.data.description) : null),
      h('td', { class: 'small' }, typeLabel(c.type)),
      h('td', { class: 'mono' }, c.version || h('span', { class: 'muted' }, '—')),
      h('td', {}, cat().COMPONENT_TYPES.find((t) => t.id === c.type)?.noSbom ? h('span', { class: 'muted small' }, 'not applicable') : c.sbom
        ? [h('div', {}, `${c.sbom.format} ${c.sbom.specVersion} · ${c.sbom.summary.packages} packages`), h('div', { class: 'small' }, qualityBadge(c.sbom.summary.quality), ` ${fmtDay(c.sbom.uploadedAt)}`)]
        : badge('blocker', 'missing')),
      h('td', {}, vulnSummary(c.vulns)),
      h('td', { class: 'actions' },
        can.edit && !cat().COMPONENT_TYPES.find((t) => t.id === c.type)?.noSbom ? [
          h('button', { class: 'btn small', onclick: () => uploadSbom(p, c) }, c.sbom ? 'New SBOM' : 'Import SBOM'),
          h('button', { class: 'btn small', disabled: !c.sbom || !state.me.vulnLookup.length, title: state.me.vulnLookup.length ? `Look up in ${state.me.vulnLookup.join(', ').toUpperCase()}` : 'Online lookup disabled on this server', onclick: () => startScan(p, c, scanState) }, 'Scan'),
          h('button', { class: 'btn small ghost', onclick: () => importVulns(p, c) }, 'Import results')] : null))) : h('tr', {}, h('td', { colspan: 6, class: 'muted' }, 'No components yet.'))));
  clear(body, head('Components & SBOMs', 'Annex VII(1)(b), (2)(b), (8) · Annex I Part II(1)'),
    h('div', { class: 'guidance' }, h('p', {}, 'List every part of the product with digital elements: firmware, backend / cloud services (remote data processing), web frontend, mobile and desktop apps. Each software component needs a version and an SBOM in a machine-readable format covering at least the top-level dependencies (Annex I Part II(1)). Import CycloneDX or SPDX JSON from your build (e.g. syft, cdxgen, cyclonedx-maven/-npm, Yocto create-spdx).'),
      h('p', {}, `Vulnerability lookup: ${state.me.vulnLookup.length ? state.me.vulnLookup.map((s) => ({ osv: 'OSV.dev (package URL)', nvd: 'NVD (CPE)', euvd: 'ENISA EUVD', kev: 'CISA KEV' }[s] || s)).join(', ') : 'disabled on this server – import scanner results (CycloneDX VEX, OSV-Scanner, Grype, Trivy JSON)'}.`)),
    scanState,
    section('Components', render(list)),
    can.edit ? section('Add component', h('div', { class: 'fields' },
      field(form, 'name', { label: 'Name', required: true }),
      field(form, 'type', { label: 'Type', type: 'select', options: cat().COMPONENT_TYPES.map((t) => [t.id, t.label]) }),
      field(form, 'version', { label: 'Version covered', help: 'Leave empty to take it from the SBOM.' }),
      field(form.data, 'description', { label: 'Description', wide: true })),
    h('button', { class: 'btn primary', onclick: async () => {
      if (!form.name.trim()) return toast('Enter a name.', 'error');
      try { await api.createComponent(p.id, form); toast('Component added.'); reload(p, 'components'); } catch (e) { toast(e.message, 'error'); }
    } }, 'Add component')) : null);
  pollScans(p, scanState);
}

const qualityBadge = (q) => (q ? badge(q.score >= 85 ? 'ok' : q.score >= 70 ? 'warning' : 'blocker', `quality ${q.score} %`) : null);
const vulnSummary = (v) => (!v || !v.total ? badge('ok', 'none known') : [
  v.open ? badge(v.kevOpen ? 'blocker' : 'warning', `${v.open} open`) : badge('ok', '0 open'),
  v.critical ? [' ', h('span', { class: 'sev sev-critical' }, `${v.critical} crit`)] : null,
  v.high ? [' ', h('span', { class: 'sev sev-high' }, `${v.high} high`)] : null,
  v.kevOpen ? [' ', badge('blocker', `${v.kevOpen} exploited`)] : null,
  v.untriaged ? h('div', { class: 'small muted' }, `${v.untriaged} in triage`) : null]);

async function uploadSbom(p, c) {
  const f = await pickFile('.json,application/json');
  if (!f) return;
  try {
    const s = await api.uploadSbom(p.id, c.id, f.name, await f.arrayBuffer());
    toast(`SBOM imported: ${s.summary.packages} packages, quality ${s.summary.quality.score} %.`);
    reload(p, `component/${c.id}`);
  } catch (e) { toast(e.message, 'error'); }
}
async function importVulns(p, c) {
  const f = await pickFile('.json,application/json');
  if (!f) return;
  try {
    const r = await api.importVulns(p.id, c.id, await f.arrayBuffer());
    toast(`${r.format}: ${r.findings} finding(s), ${r.added} new.${r.messages?.length ? ` ${r.messages[0]}` : ''}`);
    reload(p, 'vulns');
  } catch (e) { toast(e.message, 'error'); }
}
async function startScan(p, c, box) {
  try { await api.scan(p.id, c.id); toast(`Scan of ${c.name} started.`); pollScans(p, box, true); } catch (e) { toast(e.message, 'error'); }
}
let pollTimer;
// Shows scan progress; when a scan that was running finishes, the current page reloads to show the new findings.
async function pollScans(p, box, wasRunning = false) {
  clearTimeout(pollTimer);
  if (!box.isConnected && !wasRunning) return;
  const scans = await api.scans(p.id).catch(() => []);
  const running = scans.filter((s) => s.status === 'running');
  const last = scans[0];
  if (!running.length && wasRunning) return reload(p, location.hash.split('/').slice(3).join('/'));
  clear(box, running.length ? h('div', { class: 'readiness info' }, `Vulnerability lookup running for ${running.length} component(s)… (NVD lookups without API key take ~6 s per CPE)`)
    : last && Date.now() - new Date(last.finishedAt || last.startedAt).getTime() < 10 * 60_000 ? h('div', { class: `readiness ${last.status === 'done' ? 'ok' : 'blocker'}` },
      last.status === 'done' ? `Last scan: ${last.summary.findings} finding(s), ${last.summary.added ?? 0} new, ${last.summary.kev} actively exploited · ${last.summary.unidentified ? `${last.summary.unidentified} package(s) without package URL / CPE could not be looked up` : 'all packages identifiable'}${last.summary.messages?.length ? ` · ${last.summary.messages.join(' · ')}` : ''}`
        : `Last scan ${last.status}: ${last.summary.error || ''}`) : null);
  if (running.length) pollTimer = setTimeout(() => (box.isConnected ? pollScans(p, box, true) : null), 2000);
}
function reload(p, sub) {
  const target = `#/p/${p.id}/${sub}`;
  if (location.hash !== target) location.hash = target;
  else window.dispatchEvent(new HashChangeEvent('hashchange'));
}

// ---------------------------------------------------------------- component detail
async function component(body, p, cid) {
  const comps = await api.components(p.id);
  const c = comps.find((x) => x.id === cid);
  if (!c) return clear(body, h('p', {}, 'Component not found.'));
  const can = p.permissions;
  const [sb, findings] = await Promise.all([api.sboms(p.id, cid), api.vulns(p.id, cid)]);
  const edit = { name: c.name, type: c.type, version: c.version, data: { ...c.data } };
  const filter = { q: '' };
  const pkgBox = h('div', {});
  const drawPkgs = () => clear(pkgBox, h('table', { class: 'list small' },
    h('thead', {}, h('tr', {}, ['Package', 'Version', 'Identifier', 'Supplier', 'Licence', 'Top-level'].map((t) => h('th', {}, t)))),
    h('tbody', {}, sb.packages.filter((x) => !filter.q || `${x.name} ${x.purl} ${x.cpe}`.toLowerCase().includes(filter.q.toLowerCase())).slice(0, 500).map((x) => h('tr', {},
      h('td', {}, x.name), h('td', { class: 'mono' }, x.version), h('td', { class: 'mono small' }, x.purl || x.cpe || h('span', { class: 'sev sev-unknown' }, 'none')),
      h('td', {}, x.supplier), h('td', {}, x.licenses.join(', ')), h('td', {}, x.topLevel ? '✓' : ''))))));
  const scanBox = h('div', {});
  const current = sb.list.find((s) => s.isCurrent);
  clear(body, head(c.name, `Component · ${typeLabel(c.type)}`),
    scanBox,
    section('Details', h('div', { class: 'fields' },
      field(edit, 'name', { label: 'Name' }), field(edit, 'type', { label: 'Type', type: 'select', options: cat().COMPONENT_TYPES.map((t) => [t.id, t.label]) }),
      field(edit, 'version', { label: 'Version covered by the documentation' }), field(edit.data, 'repository', { label: 'Repository / build reference' }),
      field(edit.data, 'description', { label: 'Description', type: 'textarea', wide: true })),
    can.edit ? h('div', { class: 'row small-gap' },
      h('button', { class: 'btn primary', onclick: async () => { try { await api.updateComponent(p.id, cid, edit); toast('Saved.'); } catch (e) { toast(e.message, 'error'); } } }, 'Save'),
      h('button', { class: 'btn ghost danger', onclick: async () => { if (!confirm(`Delete ${c.name} with its SBOMs and findings?`)) return; await api.deleteComponent(p.id, cid); reload(p, 'components'); } }, 'Delete component')) : null),
    section('SBOM',
      current ? [
        h('p', {}, `${current.format} ${current.specVersion} · ${current.summary.packages} packages (${current.summary.topLevel} top-level) · imported ${fmtDate(current.uploadedAt)} by ${current.uploadedBy} · `,
          h('a', { href: api.sbomUrl(p.id, current.id) }, 'download original'), h('span', { class: 'muted small mono' }, ` sha256 ${current.sha256.slice(0, 16)}…`)),
        h('h3', {}, 'Quality check (NTIA minimum elements / BSI TR-03183-2) ', qualityBadge(current.summary.quality)),
        h('ul', { class: 'checks' }, current.summary.quality.checks.map((q) => h('li', { class: q.ok ? 'ok' : 'warning' }, q.ok ? '✓ ' : '! ', q.label, q.percent != null && q.percent < 100 ? h('span', { class: 'muted' }, ` (${q.percent} %)`) : null))),
      ] : h('p', { class: 'muted' }, 'No SBOM imported yet.'),
      can.edit ? h('div', { class: 'row small-gap' },
        h('button', { class: 'btn', onclick: () => uploadSbom(p, c) }, current ? 'Import new SBOM version' : 'Import SBOM'),
        h('button', { class: 'btn', disabled: !current || !state.me.vulnLookup.length, onclick: () => startScan(p, c, scanBox) }, 'Scan for vulnerabilities'),
        h('button', { class: 'btn ghost', onclick: () => importVulns(p, c) }, 'Import scanner results')) : null,
      sb.list.length > 1 ? h('details', {}, h('summary', {}, `SBOM history (${sb.list.length})`), h('table', { class: 'list small' }, h('tbody', {}, sb.list.map((s) => h('tr', {},
        h('td', {}, fmtDate(s.uploadedAt)), h('td', {}, s.uploadedBy), h('td', {}, s.filename), h('td', {}, `${s.summary.packages} packages`), h('td', {}, h('a', { href: api.sbomUrl(p.id, s.id) }, 'download')))))) ) : null),
    current ? section(`Packages (${sb.packages.length})`, field(filter, 'q', { placeholder: 'Filter…', onChange: drawPkgs }), pkgBox) : null,
    section(`Vulnerabilities (${findings.filter((f) => f.present).length})`, h('div', { class: 'row small-gap' }, h('a', { class: 'btn small', href: `#/p/${p.id}/vulns?c=${cid}` }, 'Open in vulnerability view'), h('a', { class: 'btn small ghost', href: api.vexUrl(p.id, cid) }, 'Export VEX (CycloneDX)')),
      vulnTable(p, findings.filter((f) => f.present).slice(0, 20), [c], () => reload(p, `component/${cid}`))));
  if (current) drawPkgs();
  pollScans(p, scanBox);
}

// ======================================================================== vulnerabilities
async function vulns(body, p) {
  const [list, comps] = await Promise.all([api.vulns(p.id), api.components(p.id)]);
  const pre = new URLSearchParams(location.hash.split('?')[1] || '');
  const f = { component: pre.get('c') || '', state: 'open', severity: '', kev: false, q: '', gone: false };
  const box = h('div', {});
  const kevOpen = list.filter((x) => x.present && x.kev && cat().VEX_STATES.find((s) => s.id === x.state)?.open).length;
  const draw = () => {
    const rows = list.filter((x) => (f.gone || x.present) && (!f.component || x.componentId === f.component)
      && (f.state === 'all' || (f.state === 'open' ? cat().VEX_STATES.find((s) => s.id === x.state)?.open : x.state === f.state))
      && (!f.severity || x.severity === f.severity) && (!f.kev || x.kev)
      && (!f.q || `${x.vulnId} ${x.aliases.join(' ')} ${x.pkgName} ${x.summary}`.toLowerCase().includes(f.q.toLowerCase())))
      .sort((a, b) => (b.kev - a.kev) || (SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)) || ((b.score || 0) - (a.score || 0)));
    clear(box, h('p', { class: 'muted small' }, `${rows.length} of ${list.length} finding(s)`), vulnTable(p, rows, comps, () => reload(p, 'vulns')));
  };
  clear(body, head('Vulnerabilities', 'Annex I Part I(2)(a), Part II · Art. 14'),
    kevOpen ? art14Banner(kevOpen) : null,
    h('div', { class: 'guidance' }, h('p', {}, 'Every finding needs a decision. "Not affected" and "false positive" need a justification (CycloneDX VEX). Fix exploitable vulnerabilities before placing the product on the market (Annex I Part I(2)(a)) and deliver security updates without delay during the support period (Part II(2), (8)). Decisions are kept when components are rescanned and are exported as VEX with every documentation release.')),
    section(null, h('div', { class: 'filters' },
      field(f, 'component', { label: 'Component', type: 'select', options: [['', 'All components'], ...comps.map((c) => [c.id, `${c.name} ${c.version}`])], onChange: draw }),
      field(f, 'state', { label: 'State', type: 'select', options: [['open', 'Open (in triage / exploitable)'], ['all', 'All'], ...cat().VEX_STATES.map((s) => [s.id, s.label])], onChange: draw }),
      field(f, 'severity', { label: 'Severity', type: 'select', options: [['', 'Any'], ...SEV_ORDER.map((s) => [s, s])], onChange: draw }),
      field(f, 'q', { label: 'Search', placeholder: 'CVE, package…', onChange: draw }),
      field(f, 'kev', { type: 'checkbox', label: 'Actively exploited only', onChange: draw }),
      field(f, 'gone', { type: 'checkbox', label: 'Include findings no longer in the current SBOM', onChange: draw })),
    h('div', { class: 'row small-gap' }, h('a', { class: 'btn small', href: api.vexUrl(p.id) }, 'Export VEX for the whole product (CycloneDX)')), box));
  draw();
}

function vulnTable(p, rows, comps, after) {
  const compName = (id) => comps.find((c) => c.id === id)?.name || '';
  const link = (id) => (id.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${id}` : id.startsWith('EUVD-') ? `https://euvd.enisa.europa.eu/vulnerability/${id}` : `https://osv.dev/vulnerability/${id}`);
  if (!rows.length) return h('p', { class: 'muted' }, 'No findings.');
  return h('table', { class: 'list vulns' },
    h('thead', {}, h('tr', {}, ['Severity', 'Vulnerability', 'Package', 'Exploited / EPSS', 'Fixed in', 'Decision', ''].map((t) => h('th', {}, t)))),
    h('tbody', {}, rows.map((v) => h('tr', { class: v.present ? '' : 'gone' },
      h('td', {}, sevBadge(v.severity, v.score)),
      h('td', {}, h('a', { href: link(v.vulnId), target: '_blank', rel: 'noopener noreferrer' }, v.vulnId), h('div', { class: 'small muted' }, v.aliases.filter((a) => a !== v.vulnId).slice(0, 3).join(' · ')),
        h('div', { class: 'small clamp' }, v.summary)),
      h('td', {}, h('span', { class: 'mono small' }, `${v.pkgName}@${v.pkgVersion}`), h('div', { class: 'small muted' }, compName(v.componentId))),
      h('td', {}, v.kev ? badge('blocker', 'actively exploited') : null, v.epss != null ? h('div', { class: 'small' }, `EPSS ${Number(v.epss).toFixed(1)} %`) : null),
      h('td', { class: 'mono small' }, (v.info?.fixed || []).slice(0, 3).join(', ')),
      h('td', {}, h('span', { class: `state st-${v.state}` }, stateLabel(v.state)), v.justification ? h('div', { class: 'small muted' }, v.justification.replace(/_/g, ' ')) : null,
        v.updatedBy ? h('div', { class: 'small muted' }, `${v.updatedBy}, ${fmtDay(v.updatedAt)}`) : null, !v.present ? h('div', { class: 'small muted' }, 'no longer in SBOM') : null),
      h('td', {}, p.permissions.edit ? h('button', { class: 'btn small', onclick: () => triage(p, v, after) }, 'Decide') : null)))));
}

function triage(p, v, after) {
  const t = { state: v.state, justification: v.justification, response: v.response, analysis: v.analysis };
  const extra = h('div', {});
  const draw = () => clear(extra,
    ['not_affected', 'false_positive'].includes(t.state) ? field(t, 'justification', { label: 'Justification (VEX)', type: 'select', options: [['', '—'], ...cat().VEX_JUSTIFICATIONS.map((j) => [j, j.replace(/_/g, ' ')])] }) : null,
    ['exploitable', 'resolved', 'resolved_with_pedigree'].includes(t.state) ? field(t, 'response', { label: 'Response', type: 'select', options: [['', '—'], ...cat().VEX_RESPONSES.map((j) => [j, j.replace(/_/g, ' ')])] }) : null);
  draw();
  const dlg = modal(`${v.vulnId} in ${v.pkgName}@${v.pkgVersion}`, h('div', {},
    h('p', {}, sevBadge(v.severity, v.score), ' ', v.kev ? badge('blocker', 'actively exploited') : null, ' ', v.summary),
    v.info?.fixed?.length ? h('p', { class: 'small' }, `Fixed in: ${v.info.fixed.join(', ')}`) : null,
    v.info?.references?.length ? h('details', { class: 'small' }, h('summary', {}, 'References'), h('ul', {}, v.info.references.map((r) => h('li', {}, h('a', { href: r, target: '_blank', rel: 'noopener noreferrer' }, r))))) : null,
    h('div', { class: 'fields' }, field(t, 'state', { label: 'Decision', type: 'select', options: cat().VEX_STATES.map((s) => [s.id, s.label]), onChange: draw })),
    extra,
    field(t, 'analysis', { label: 'Analysis / reasoning (kept in the VEX and the technical documentation)', type: 'textarea', rows: 4, wide: true })),
  [h('button', { class: 'btn', onclick: () => dlg.close() }, 'Cancel'),
    h('button', { class: 'btn primary', onclick: async () => {
      try { await api.triage(p.id, v.id, t); dlg.close(); toast('Decision saved.'); after(); } catch (e) { toast(e.message, 'error'); }
    } }, 'Save decision')]);
}

// ======================================================================== technical documentation
async function docs(body, p) {
  const can = p.permissions;
  const d = p.data;
  let revision = p.revision;
  const saveState = document.getElementById('save-state');
  let timer;
  const save = () => {
    clearTimeout(timer);
    saveState.textContent = 'Unsaved changes…';
    timer = setTimeout(async () => {
      try { const r = await api.saveProduct(p.id, revision, d); revision = r.revision; saveState.textContent = `Saved ${new Date(r.updatedAt).toLocaleTimeString()}`; }
      catch (e) { saveState.textContent = 'Not saved'; toast(e.message, 'error'); }
    }, 800);
  };
  const o = { onChange: save };
  const files = p.files;
  const item = (id) => p.techdoc.items.find((i) => i.id === String(id));
  const itemHead = (id) => { const i = item(id); return h('div', { class: 'a7-head' }, h('h2', {}, `${i.id}. ${i.title}`), h('span', { class: 'muted small' }, i.annex), statusBadge(i.status)); };
  const checks = (id) => h('ul', { class: 'checks' }, item(id).checks.map((c) => h('li', { class: c.ok ? 'ok' : c.level }, c.ok ? '✓ ' : c.level === 'blocker' ? '✗ ' : '! ', c.text)));
  const link = (label, href) => h('a', { class: 'btn small ghost', href: `#/p/${p.id}/${href}` }, label);
  const fileList = (sectionId, { tests = false } = {}) => {
    const list = files.filter((f) => f.section === sectionId);
    return h('div', { class: 'files' },
      list.length ? h('table', { class: 'list small' }, h('tbody', {}, list.map((f) => h('tr', {},
        h('td', {}, h('a', { href: api.fileUrl(p.id, f.id) }, f.meta?.title || f.name), f.meta?.title && f.meta.title !== f.name ? h('div', { class: 'muted' }, f.name) : null),
        tests ? h('td', {}, [f.meta?.type, f.meta?.date, f.meta?.result].filter(Boolean).join(' · '), f.meta?.annex?.length ? h('div', { class: 'muted' }, `Annex I: ${f.meta.annex.join(', ')}`) : null) : null,
        h('td', { class: 'muted' }, `${bytes(f.size)} · ${fmtDay(f.uploadedAt)} · ${f.uploadedBy}`), h('td', { class: 'mono muted', title: f.sha256 }, f.sha256.slice(0, 12)),
        h('td', { class: 'actions' }, can.edit ? [
          tests ? h('button', { class: 'btn small ghost', onclick: () => testMeta(p, f) }, 'Edit') : null,
          h('button', { class: 'icon danger', title: 'Delete', onclick: async () => { if (!confirm(`Delete ${f.name}?`)) return; await api.deleteFile(p.id, f.id); reload(p, 'docs'); } }, '×')] : null))))) : null,
      can.edit ? h('button', { class: 'btn small', onclick: async () => {
        const file = await pickFile('');
        if (!file) return;
        if (tests) return testMeta(p, null, file);
        try { await api.uploadFile(p.id, sectionId, file, await file.arrayBuffer(), { title: file.name }); toast('Uploaded.'); reload(p, 'docs'); } catch (e) { toast(e.message, 'error'); }
      } }, '+ Upload') : null);
  };
  const sub = (title, ...c) => h('div', { class: 'sub' }, h('h3', {}, title), c);

  clear(body, head('Technical documentation', 'Art. 31 and Annex VII CRA'),
    h('div', { class: 'guidance' }, h('p', {}, 'Draw up the technical documentation before placing the product on the market and keep it up to date during the support period. Content captured in the risk assessment (purpose, architecture, support period, standards, user information) is referenced here and not entered twice. Upload the evidence where it lives today (test reports, signed declaration, policies) – files are fingerprinted (SHA-256) and included in every release package.'),
      h('div', { class: 'row small-gap ro-ok' }, h('a', { class: 'btn small', href: api.draftZipUrl(p.id) }, icon('arrow-download', 16), 'Download draft package (ZIP)'), link('Freeze a release', 'releases'))),
    section('Product', h('div', { class: 'fields' },
      field(d, 'name', { label: 'Product name', ...o }),
      field(d, 'placedOnMarket', { label: 'Placed on the market (first unit, planned or actual)', type: 'date', ...o, help: 'Starts the 10-year retention period (Art. 13(13)).' }),
      field(d, 'sme', { label: 'Enterprise size', type: 'select', options: [['', 'Medium-sized or large'], ['small', 'Small enterprise'], ['micro', 'Microenterprise']], ...o, help: 'Micro and small enterprises may use the simplified form once the Commission has adopted it (Art. 33(5)).' }))),
    section(null, itemHead(1), checks(1),
      h('div', { class: 'row small-gap' }, link('Intended purpose → Product description', 'a/product'), link('Components & versions', 'components'), link('User information (Annex II)', 'a/userinfo')),
      sub('(c) Photos / illustrations of the hardware', fileList('1c')),
      sub('(d) User information and instructions', h('div', { class: 'fields' }, field(d.docs, 'userInfoUrl', { label: 'Internet address of the instructions', ...o })), fileList('1d'))),
    section(null, itemHead(2), checks(2),
      sub('(a) Design and development, system architecture', h('div', { class: 'row small-gap' }, link('Architecture & interfaces', 'a/architecture'), link('Threat model', 'a/stride')),
        field(d.docs, 'designDescription', { label: 'Design and development information (how software components build on and interact with each other, processing overview)', type: 'textarea', rows: 4, wide: true, ...o }), fileList('2a')),
      sub('(b) Vulnerability handling', h('div', { class: 'row small-gap' }, link('SBOMs', 'components'), link('Vulnerabilities', 'vulns')),
        h('div', { class: 'fields' },
          field(d.docs, 'cvdPolicyUrl', { label: 'Coordinated vulnerability disclosure policy (URL)', ...o }),
          field(d.docs, 'contactEmail', { label: 'Contact for vulnerability reports (e-mail)', ...o }),
          field(d.docs, 'contactUrl', { label: 'Contact page / security.txt URL', ...o }),
          field(d.docs, 'cvdPolicySummary', { label: 'CVD policy summary (scope, response times, safe harbour)', type: 'textarea', wide: true, ...o }),
          field(d.docs, 'updateDistribution', { label: 'Technical solution for the secure distribution of updates (signing, secure boot, channels, automatic updates)', type: 'textarea', rows: 3, wide: true, ...o })),
        h('h4', {}, 'CVD policy'), fileList('2b-cvd'), h('h4', {}, 'Evidence that the contact address is published'), fileList('2b-contact'), h('h4', {}, 'Update distribution design'), fileList('2b-update')),
      sub('(c) Production and monitoring processes', h('div', { class: 'fields' },
        field(d.docs, 'productionProcesses', { label: 'Production and monitoring processes (key provisioning, firmware flashing, secure manufacturing, monitoring in the field)', type: 'textarea', rows: 3, wide: true, ...o }),
        field(d.docs, 'productionValidation', { label: 'How these processes are validated', type: 'textarea', rows: 2, wide: true, ...o })), fileList('2c'))),
    section(null, itemHead(3), checks(3), h('div', { class: 'row small-gap' }, link('Open risk assessment', 'a/summary'))),
    section(null, itemHead(4), checks(4), h('div', { class: 'row small-gap' }, link('Support period', 'a/support'))),
    section(null, itemHead(5), checks(5), h('div', { class: 'row small-gap' }, link('Standards applied', 'a/standards')),
      field(d.docs, 'solutionsWithoutStandards', { label: 'Where no harmonised standard / common specification / certification scheme is applied: description of the solutions meeting Annex I Parts I and II, and other technical specifications used', type: 'textarea', rows: 3, wide: true, ...o }),
      sub('Certificates and specifications', fileList('5'))),
    section(null, itemHead(6), checks(6), h('p', { class: 'muted small' }, 'Map each report to the Annex I requirements it verifies – the check above shows which applicable requirements have no test evidence yet.'), fileList('6', { tests: true })),
    section(null, itemHead(7), checks(7), h('div', { class: 'fields' },
      field(d.docs, 'docDate', { label: 'Date of the declaration', type: 'date', ...o }), field(d.docs, 'docVersion', { label: 'Declaration version / reference', ...o }),
      field(d.docs, 'docUrl', { label: 'Internet address where the declaration is available (Annex II(6))', ...o })), fileList('7')),
    section(null, itemHead(8), checks(8), field(d.docs, 'sbomOnRequest', { label: 'Procedure for handing over the SBOM on a reasoned request of a market surveillance authority (who, how, within which time)', type: 'textarea', rows: 2, wide: true, ...o })),
    section('Other supporting documents', fileList('other')));
}

function testMeta(p, f, newFile) {
  const m = { title: f?.meta?.title || newFile?.name || '', type: f?.meta?.type || '', date: f?.meta?.date || '', result: f?.meta?.result || '', summary: f?.meta?.summary || '', annex: [...(f?.meta?.annex || [])] };
  const dlg = modal(f ? 'Test report details' : 'Upload test report', h('div', {},
    h('div', { class: 'fields' },
      field(m, 'title', { label: 'Title', wide: true }), field(m, 'type', { label: 'Type', type: 'select', options: ['', ...cat().TEST_TYPES] }),
      field(m, 'date', { label: 'Date', type: 'date' }), field(m, 'result', { label: 'Result', type: 'select', options: ['', ...cat().TEST_RESULTS] }),
      field(m, 'summary', { label: 'Scope and summary', type: 'textarea', wide: true })),
    h('div', { class: 'field wide' }, h('label', {}, 'Annex I requirements verified by this report'), chips(m, 'annex', cat().ANNEX_I.map((r) => r.id), { titleOf: (id) => cat().ANNEX_I.find((r) => r.id === id)?.text }))),
  [h('button', { class: 'btn', onclick: () => dlg.close() }, 'Cancel'),
    h('button', { class: 'btn primary', onclick: async () => {
      try {
        if (f) await api.updateFile(p.id, f.id, { meta: m });
        else await api.uploadFile(p.id, '6', newFile, await newFile.arrayBuffer(), m);
        dlg.close(); toast('Saved.'); reload(p, 'docs');
      } catch (e) { toast(e.message, 'error'); }
    } }, f ? 'Save' : 'Upload')]);
  dlg.classList.add('wide');
}

// ======================================================================== releases
async function releases(body, p) {
  const can = p.permissions;
  const form = { version: '', note: '' };
  clear(body, head('Releases of the technical documentation', 'Art. 31(2), Art. 13(13)'),
    h('div', { class: 'guidance' }, h('p', {}, 'A release freezes the complete technical documentation as a ZIP package: Annex VII index (PDF), risk assessment (PDF, XLSX, JSON), threat-model diagram, SBOMs, VEX and vulnerability list, and all evidence files – each with a SHA-256 checksum in manifest.json. Create a release for every product version placed on the market and whenever the documentation changes during the support period. Releases cannot be changed or deleted by product members.')),
    can.release ? section('Freeze a new release',
      p.techdoc.blockers ? h('div', { class: 'readiness blocker' }, `${p.techdoc.blockers} blocking point(s) are open in the Annex VII checks. You can still freeze an interim release.`) : h('div', { class: 'readiness ok' }, 'No blocking points in the Annex VII checks.'),
      h('div', { class: 'fields' }, field(form, 'version', { label: 'Release / documentation version', required: true, placeholder: 'e.g. 1.0 or 2026-11 product release' }), field(form, 'note', { label: 'Note', wide: true })),
      h('button', { class: 'btn primary', onclick: async (e) => {
        if (!form.version.trim()) return toast('Enter a version.', 'error');
        if (p.techdoc.blockers && !confirm('Freeze despite open blocking points?')) return;
        e.target.disabled = true; e.target.textContent = 'Building package…';
        try { const r = await api.release(p.id, form.version, form.note); toast(`Release ${r.version} frozen.`); reload(p, 'releases'); } catch (err) { toast(err.message, 'error'); e.target.disabled = false; e.target.textContent = 'Freeze release'; }
      } }, 'Freeze release')) : h('p', { class: 'muted' }, 'Releases are frozen by an approver or owner of this product.'),
    section('Releases', p.releases.length ? h('table', { class: 'list' },
      h('thead', {}, h('tr', {}, ['Version', 'Frozen', 'By', 'Note', 'Annex VII status', 'SHA-256', ''].map((t) => h('th', {}, t)))),
      h('tbody', {}, p.releases.map((r) => h('tr', {},
        h('td', {}, h('b', {}, r.version)), h('td', { class: 'small' }, fmtDate(r.createdAt)), h('td', {}, r.createdBy), h('td', { class: 'small' }, r.note),
        h('td', { class: 'small' }, Object.values(r.manifest?.completeness || {}).filter((x) => x === 'complete').length, ' / 8 complete'),
        h('td', { class: 'mono small', title: r.sha256 }, `${r.sha256.slice(0, 16)}…`),
        h('td', {}, h('a', { class: 'btn small', href: api.releaseUrl(p.id, r.id) }, icon('arrow-download', 16), 'Download ZIP')))))) : h('p', { class: 'muted' }, 'No releases yet.')));
}

// ======================================================================== members
async function members(body, p) {
  const list = await api.members(p.id);
  const can = p.permissions;
  const dir = can.members ? await api.directory().catch(() => []) : [];
  const add = { user: '', role: 'editor' };
  const roles = cat().PRODUCT_ROLES;
  clear(body, head('Members', 'Who may read, edit, approve and release this product'),
    h('table', { class: 'list roles' }, h('tbody', {}, roles.map((r) => h('tr', {}, h('td', {}, h('b', {}, r.label)), h('td', { class: 'muted' }, r.description))))),
    h('p', { class: 'muted small' }, 'Administrators and auditors see all products through their global role.'),
    section('Members', h('table', { class: 'list' },
      h('thead', {}, h('tr', {}, ['User', 'Role', ''].map((t) => h('th', {}, t)))),
      h('tbody', {}, list.map((m) => h('tr', {},
        h('td', {}, m.user.name || m.user.email, h('div', { class: 'small muted' }, m.user.email), m.user.disabled ? badge('muted', 'disabled') : null),
        h('td', {}, can.members ? (() => {
          const s = h('select', {}, roles.map((r) => h('option', { value: r.id }, r.label)));
          s.value = m.role;
          s.addEventListener('change', async () => { try { await api.setMember(p.id, m.user.id, s.value); toast('Role changed.'); } catch (e) { toast(e.message, 'error'); s.value = m.role; } });
          return s;
        })() : roleLabel(m.role)),
        h('td', {}, can.members ? h('button', { class: 'btn small ghost danger', onclick: async () => { try { await api.setMember(p.id, m.user.id, null); reload(p, 'members'); } catch (e) { toast(e.message, 'error'); } } }, 'Remove') : null)))))),
    can.members ? section('Add member', dir.length ? h('div', { class: 'fields' },
      field(add, 'user', { label: 'User', type: 'select', options: [['', '— select —'], ...dir.filter((u) => !list.some((m) => m.user.id === u.id)).map((u) => [u.id, `${u.name ? `${u.name} – ` : ''}${u.email}`])] }),
      field(add, 'role', { label: 'Role', type: 'select', options: roles.map((r) => [r.id, r.label]) })) : h('p', { class: 'muted' }, 'No users available.'),
    h('button', { class: 'btn primary', onclick: async () => {
      if (!add.user) return toast('Select a user.', 'error');
      try { await api.setMember(p.id, add.user, add.role); reload(p, 'members'); } catch (e) { toast(e.message, 'error'); }
    } }, 'Add'), h('p', { class: 'muted small' }, state.authMode === 'header' ? 'Users appear here after their first single sign-on, or when an administrator registers their e-mail address.' : 'New users are created by an administrator.')) : null,
    can.delete ? section('Danger zone', h('button', { class: 'btn ghost danger', onclick: async () => {
      if (prompt(`Type the product name to delete "${p.name}" with all components, SBOMs, findings, files and its risk assessment:`) !== p.name) return;
      try { await api.deleteProduct(p.id); location.hash = '#/'; } catch (e) { toast(e.message, 'error'); }
    } }, 'Delete product')) : null);
}

// ======================================================================== activity
async function activity(body, p) {
  const ev = await api.productEvents(p.id);
  clear(body, head('Activity', 'Audit trail of changes to this product'),
    section(null, h('table', { class: 'list' }, h('tbody', {}, ev.map((x) => h('tr', {},
      h('td', { class: 'small muted' }, fmtDate(x.at)), h('td', {}, x.actor), h('td', {}, x.action), h('td', { class: 'small' }, x.detail)))))));
}
