import { h, clear, field, chips, grid, guidance, badge, ratingBadge, modal, toast } from './ui.js';
import { api } from './api.js';
import { diagramSvg, DIAGRAM } from '../shared/diagram.js';
import { FOUR_QUESTIONS, WALKTHROUGH, tutorialAssessment, TUTORIAL_ID } from '../shared/tutorial.js';
import { newRisk, nextId, presetFor, scoreRisk, splitRefs, heatmap, userInfoItems, visibleSteps, STEPS, strideTargets, strideCell } from '../shared/model.js';

export function renderStep(ctx, id) {
  const fn = RENDER[id];
  return fn ? fn(ctx) : h('p', {}, 'Unknown step');
}

const on = (ctx, opts) => () => ctx.changed(opts);
const isConsumer = (a) => a.profile.markets.includes('consumer');
const isPro = (a) => a.profile.markets.includes('professional');
const section = (title, ...body) => h('section', { class: 'card' }, title && h('h2', {}, title), body);
const fields = (...f) => h('div', { class: 'fields' }, f);

// ---------------------------------------------------------------- 1 profile
function profile(ctx) {
  const { a, catalog } = ctx;
  const p = a.profile;
  const marketBox = h('div', { class: 'fields' }, catalog.MARKETS.map((m) => {
    const box = { v: p.markets.includes(m.id) };
    return field(box, 'v', { type: 'checkbox', label: m.label, onChange: () => {
      p.markets = catalog.MARKETS.map((x) => x.id).filter((x) => (x === m.id ? box.v : p.markets.includes(x)));
      for (const s of catalog.STANDARDS) if (s.defaultFor === m.id && box.v) p.standards[s.id] = true;
      const preset = presetFor(p.markets);
      const rated = a.risks.some((r) => r.inherentL || r.residualL);
      if (p.markets.length && a.method.preset !== preset && a.method.preset !== 'imported' && !rated && !a.method.approvedBy) {
        Object.assign(a.method, structuredClone({ preset, ...catalog.METHOD_PRESETS[preset] }));
        toast(`Risk method switched to the "${catalog.METHOD_PRESETS[preset].label}" scales.`);
      }
      ctx.changed({ rerender: true });
    } });
  }));
  return h('div', {},
    guidance('What this step decides',
      h('p', {}, 'The CRA applies the same essential requirements to consumer and commercial products, but the threat landscape, foreseeable misuse and impact differ. Your choice here switches on the matching impact scales, threat library entries, checklists and mapping columns. Products sold to both groups get a combined view.'),
      h('ul', {},
        h('li', {}, h('b', {}, 'Consumer: '), 'non-expert users, home networks, mass automated attacks, privacy and safety of household members; ETSI EN 303 645 checklist; UK PSTI if sold in the UK.'),
        h('li', {}, h('b', {}, 'Commercial / industrial: '), 'zones & conduits, security levels (IEC 62443), remote service access, operational and environmental impact; tailor-made agreements with business users (Annex I(2)(b), II(8)).'))),
    section('Assessment', fields(
      field(a.meta, 'title', { label: 'Assessment title', onChange: on(ctx), wide: true }),
      field(a.meta, 'version', { label: 'Document version', help: 'Increase before freezing a new version.', onChange: on(ctx) }))),
    section('Target markets', marketBox),
    section('Standards used for mapping',
      h('p', { class: 'muted' }, 'Selected standards add mapping columns to the risk register and suggestions in the Annex I view.'),
      h('div', { class: 'fields' }, catalog.STANDARDS.map((s) => field(p.standards, s.id, { type: 'checkbox', label: s.label, onChange: on(ctx, { rerender: true }) })))),
    section('Market specifics', h('div', { class: 'fields' },
      isConsumer(a) && field(p, 'ukMarket', { type: 'checkbox', label: 'Also sold in the United Kingdom (PSTI statement of compliance)', onChange: on(ctx) }),
      isPro(a) && field(p, 'tailorMade', { type: 'checkbox', label: 'Tailor-made variants exist for specific business users (deviations from secure default / free updates must be contractually agreed)', onChange: on(ctx) }))),
  );
}

// ---------------------------------------------------------------- 2 product
function product(ctx) {
  const { a } = ctx;
  const p = a.product;
  const o = { onChange: on(ctx) };
  const c = isConsumer(a);
  return h('div', {},
    guidance('Art. 13(3) – the minimum basis of the assessment',
      h('p', {}, 'The risk analysis must be based on the intended purpose and reasonably foreseeable use, such as the operating environment and the assets to be protected, taking the expected lifetime into account. These entries also form the general description in the technical documentation (Annex VII(1)).')),
    section('Identification', fields(
      field(p, 'name', { label: 'Product name', required: true, ...o }),
      field(p, 'model', { label: 'Model / type designation', ...o }),
      field(p, 'versions', { label: 'Hardware / firmware / software / cloud versions in scope', required: true, help: 'List every version this assessment covers (Annex VII(1)(b)).', ...o, wide: true }),
      field(p, 'manufacturer', { label: 'Manufacturer', ...o }),
      field(p, 'securityOwner', { label: 'Product security owner', ...o }))),
    section('Purpose and use', fields(
      field(p, 'intendedPurpose', { label: 'Intended purpose', type: 'textarea', required: true, ...o, wide: true }),
      field(p, 'foreseeableUse', { label: 'Reasonably foreseeable use and misuse', type: 'textarea', required: true, wide: true, ...o,
        help: c ? 'E.g. installed without professional help, setup left half-finished, weak or reused passwords, shared household accounts, resale.' : 'E.g. operation on flat networks without segmentation, shared technician accounts, remote access left open, unattended sites.' }),
      field(p, 'users', { label: 'Users and roles', type: 'textarea', ...o, wide: true }),
      field(p, 'environment', { label: 'Operating environment', type: 'textarea', required: true, wide: true, ...o,
        help: c ? 'Private homes, consumer router without IT management, children present …' : 'Sector (e.g. NIS2 essential entity), site conditions, network uplink, physical protection …' }),
      field(p, 'essentialFunctions', { label: 'Essential / basic functions that must stay available', type: 'textarea', required: true, wide: true, help: 'Drives Annex I(2)(h).', ...o }),
      field(p, 'safetyFunctions', { label: 'Safety-relevant functions', type: 'textarea', wide: true, help: 'Functions whose manipulation can harm health, property or the environment (Art. 13(2): impact on health and safety of users).', ...o }),
      field(p, 'expectedLifetime', { label: 'Expected lifetime / period of use', required: true, help: 'Art. 13(3) requires the expected lifetime to be considered; it also informs the support period.', ...o }))),
    section('Scope', fields(
      field(p, 'rdps', { label: 'Remote data processing solutions in scope', type: 'textarea', wide: true, help: 'Cloud backends, apps, portals designed by you that the product needs to perform its functions.', ...o }),
      field(p, 'outOfScope', { label: 'Components out of scope (and why)', type: 'textarea', wide: true, ...o }),
      field(p, 'personalData', { label: 'Personal data processed', type: 'textarea', wide: true, help: 'GDPR; Annex I(2)(e), (g).', ...o }),
      field(p, 'thirdParty', { label: 'Third-party and open-source components – due diligence', type: 'textarea', wide: true, help: 'How components are selected, checked and monitored (Art. 13(5)); reference to SBOM process.', ...o }),
      field(p, 'hardwareDocs', { label: 'Photos / drawings of hardware (reference)', wide: true, help: 'Document reference for Annex VII(1)(c).', ...o }))),
  );
}

// ---------------------------------------------------------------- 3 classification
function classification(ctx) {
  const { a, catalog } = ctx;
  const cl = a.classification;
  const result = h('div', { class: 'result-card' });
  ctx.hooks.push((ev) => {
    const cat = ev.classification.category;
    clear(result,
      h('div', { class: 'eyebrow' }, 'Resulting category'),
      h('div', { class: `big cat-${cat}` }, catalog.CATEGORY_LABELS[cat]),
      h('p', {}, catalog.CONFORMITY_ROUTES[cat]));
  });
  return h('div', {},
    guidance('How to classify',
      h('p', {}, 'A product is an important or critical product when its core functionality corresponds to a category in Annex III or IV (Art. 7(1), Art. 8). Integrating such a component (e.g. a secure element) does not by itself make your product important. Tick only categories that match the core functionality and record your reasoning – especially for borderline cases.')),
    result,
    catalog.CLASSIFICATION.map((g) => section(g.label, h('div', { class: 'checklist' }, g.items.map((label, i) => {
      const key = `${g.category}:${i}`;
      const box = { v: !!cl.selected[key] };
      return field(box, 'v', { type: 'checkbox', label, onChange: () => { if (box.v) cl.selected[key] = true; else delete cl.selected[key]; ctx.changed(); } });
    })))),
    section('Decision', fields(
      field(cl, 'standardsInFull', { label: 'Harmonised standards, common specifications or EU certification scheme applied in full?', type: 'select', options: ['', 'Yes', 'No', 'Not yet available'], onChange: on(ctx), help: 'Relevant for Important Class I (Art. 32(2)).' }),
      field(cl, 'route', { label: 'Chosen conformity assessment route', onChange: on(ctx) }),
      field(cl, 'notes', { label: 'Reasoning (include borderline categories considered)', type: 'textarea', rows: 4, wide: true, onChange: on(ctx) }),
      field(cl, 'reviewed', { type: 'checkbox', label: 'All Annex III and IV categories have been reviewed', onChange: on(ctx) }))),
  );
}

// ---------------------------------------------------------------- 4 support period
function support(ctx) {
  const sp = ctx.a.supportPeriod;
  const o = { onChange: on(ctx) };
  return h('div', {},
    guidance('Art. 13(8) and (19)',
      h('p', {}, 'The support period must reflect the time the product is expected to be in use, taking into account reasonable user expectations, the nature and intended purpose of the product and relevant Union law. It is at least five years, unless the product is expected to be in use for less. The end date (at least month and year) must be shown clearly at the time of purchase. Record what you considered – it becomes Annex VII(4) of the technical documentation.')),
    section('Support period', fields(
      field(sp, 'years', { label: 'Support period (years)', type: 'number', required: true, ...o }),
      field(sp, 'endDate', { label: 'End date (month / year or rule)', placeholder: 'e.g. 12/2036 or "5 years after last unit sold"', required: true, ...o }),
      field(sp, 'rationale', { label: 'Information considered (Annex VII(4))', type: 'textarea', rows: 4, wide: true, ...o,
        help: 'Expected period of use, user expectations, support periods of comparable products, availability of the operating environment, support of key third-party components, ADCO / Commission guidance.' }))),
    section('Updates', fields(
      field(sp, 'updateChannel', { label: 'Security update channel', wide: true, ...o }),
      field(sp, 'autoUpdates', { label: 'Automatic security updates (default, notification, postpone, opt-out)', type: 'textarea', wide: true, ...o, help: 'Annex I(2)(c). For products integrated into industrial systems, explain if automatic installation is not appropriate.' }),
      field(sp, 'endOfSupport', { label: 'Behaviour at end of support', type: 'textarea', wide: true, ...o }))),
  );
}

// ---------------------------------------------------------------- 5 standards
function standards(ctx) {
  const { a } = ctx;
  const rg = a.regulation;
  const o = { onChange: on(ctx) };
  const quick = ['EN 18031-1', 'EN 18031-2', 'EN 18031-3', 'ETSI EN 303 645', 'IEC 62443-4-1', 'IEC 62443-4-2', 'ISO/IEC 29147', 'ISO/IEC 30111'];
  return h('div', {},
    guidance('Why this matters',
      h('p', {}, 'Art. 13(4): where the product is also subject to other Union law, the CRA risk assessment can be part of the risk assessment required there. Annex VII(5) requires a list of harmonised standards, common specifications or certification schemes applied – in full or in part – or, where none are applied, a description of the solutions adopted.')),
    section('Related regulation', fields(
      field(rg, 'red', { label: 'RED delegated act (EN 18031-1/-2/-3)', ...o, wide: true }),
      field(rg, 'machinery', { label: 'Machinery Regulation (EU) 2023/1230', ...o, wide: true }),
      field(rg, 'productSafety', { label: 'Product safety (LVD, GPSR, EN 60335 …)', ...o, wide: true }),
      isPro(a) && field(rg, 'nis2', { label: 'NIS2 / customer sector context', ...o, wide: true }),
      isPro(a) && field(rg, 'customerFrameworks', { label: 'Customer frameworks (e.g. IEC 62443-2-4 requests)', ...o, wide: true }),
      isConsumer(a) && field(rg, 'ecosystems', { label: 'Smart-home ecosystems / certification (Matter, …)', ...o, wide: true }),
      isConsumer(a) && a.profile.ukMarket && field(rg, 'psti', { label: 'UK PSTI', ...o, wide: true }),
      field(rg, 'other', { label: 'Other', ...o, wide: true }))),
    section('Standards and specifications applied (Annex VII(5))',
      h('div', { class: 'row small-gap' }, h('span', { class: 'muted' }, 'Quick add:'), quick.map((q) => h('button', { type: 'button', class: 'btn small ghost', onclick: () => {
        if (a.standardsApplied.some((x) => x.standard === q)) return toast(`${q} is already listed.`);
        a.standardsApplied.push({ standard: q, application: 'Partial', notes: '' }); ctx.changed({ rerender: true });
      } }, q))),
      grid(a.standardsApplied, [
        { key: 'standard', label: 'Standard / specification', width: 'm' },
        { key: 'application', label: 'Application', options: ['Full', 'Partial', 'Reference only'], width: 's' },
        { key: 'notes', label: 'Parts applied / notes', multiline: true },
      ], { onChange: on(ctx), newRow: () => ({ standard: '', application: 'Partial', notes: '' }), addLabel: 'Add standard' })),
  );
}

// ---------------------------------------------------------------- 6 architecture
function architecture(ctx) {
  const { a, catalog } = ctx;
  const L = catalog.LISTS;
  const pro = isPro(a);
  const sl = a.profile.standards.iec62443;
  return h('div', {},
    guidance('Describe the attack surface',
      h('p', {}, pro
        ? 'Partition the system into zones (groups of components with common security needs – e.g. field controller, gateway, cloud, support access, apps) and list the conduits between them (IEC 62443-3-2). Mark remote-access paths: they usually carry the highest risk.'
        : 'List the components (device, app, cloud, integrations) and every way into the product: radio, LAN, cloud, app, debug, field bus. Record the default state – Annex I(2)(b) and (j) expect unneeded interfaces to be disabled by default.'),
      h('p', {}, 'This is also the system architecture description for Annex VII(2)(a). IDs are referenced from the risk register.')),
    section(pro ? 'Zones / components' : 'Components', grid(a.components, [
      { key: 'id', label: 'ID', width: 'xs' },
      { key: 'name', label: pro ? 'Zone / component' : 'Component', width: 'm' },
      { key: 'description', label: 'Contents / description', multiline: true },
      pro && { key: 'location', label: 'Location', width: 's' },
      pro && { key: 'operatedBy', label: 'Operated by', width: 's' },
      { key: 'scope', label: 'CRA scope', options: ['', ...L.scope], width: 'm' },
      sl && { key: 'slT', label: 'SL-T', options: L.securityLevel, width: 'xs' },
      { key: 'rationale', label: 'Criticality rationale', multiline: true },
      pro && { key: 'assumptions', label: 'Assumptions', multiline: true },
    ].filter(Boolean), { onChange: on(ctx), newRow: () => ({ id: nextId('Z-', a.components, 1), name: '', description: '', location: '', operatedBy: '', scope: '', slT: '', rationale: '', assumptions: '' }), addLabel: pro ? 'Add zone' : 'Add component' })),
    section(pro ? 'Conduits / interfaces' : 'Interfaces', grid(a.interfaces, [
      { key: 'id', label: 'ID', width: 'xs' },
      { key: 'name', label: 'Interface / purpose', width: 'm' },
      { key: 'from', label: 'From', help: 'Component / zone ID, or the external party (e.g. "Technician laptop")', width: 's' },
      { key: 'to', label: 'To', help: 'Component / zone ID, or the external party. Leave empty if the outside party is given by the exposure.', width: 's' },
      { key: 'protocol', label: 'Protocol / port', width: 's' },
      { key: 'exposure', label: 'Exposure', options: ['', ...L.exposure], width: 's' },
      { key: 'protection', label: 'Authentication / protection', multiline: true },
      { key: 'defaultState', label: 'Default state', options: ['', ...L.defaultState], width: 's' },
      { key: 'needed', label: 'Needed for intended function?', options: ['', 'Yes', 'No'], width: 'xs' },
      pro && { key: 'remoteAccess', label: 'Remote access path?', options: ['', 'Yes', 'No'], width: 'xs' },
      { key: 'notes', label: 'Notes', multiline: true },
    ].filter(Boolean), { onChange: on(ctx), newRow: () => ({ id: nextId(pro ? 'C-' : 'I-', a.interfaces, pro ? 1 : 2), name: '', from: '', to: '', protocol: '', exposure: '', protection: '', defaultState: '', needed: '', remoteAccess: '', notes: '' }), addLabel: 'Add interface' })),
    ctx.productComponents?.length ? section('Product components',
      h('p', { class: 'muted small' }, 'Components registered for this product (firmware, backend, apps …). Add missing ones here as components / zones so the architecture and threat model cover them.'),
      h('div', { class: 'row small-gap' }, ctx.productComponents.map((pc) => {
        const present = a.components.some((c) => c.productComponentId === pc.id || c.name === pc.name);
        return h('button', { type: 'button', class: 'btn small' + (present ? ' ghost' : ''), disabled: present, title: present ? 'Already in the architecture' : 'Add as component / zone', onclick: () => {
          a.components.push({ id: nextId('Z-', a.components, 1), name: pc.name, description: `${pc.type}${pc.version ? `, version ${pc.version}` : ''}`, location: '', operatedBy: '',
            scope: pc.type === 'backend' ? 'Remote data processing (RDPS)' : ['mobile', 'frontend', 'desktop'].includes(pc.type) ? 'Product (software/app)' : 'Product (hardware/firmware)',
            slT: '', rationale: '', assumptions: '', productComponentId: pc.id });
          ctx.changed({ rerender: true });
        } }, `${present ? '✓ ' : '+ '}${pc.name}`);
      }))) : null,
    section('Diagram preview',
      h('p', { class: 'muted small' }, 'Updates as you type. Use component / zone IDs in From and To to connect boxes; any other text becomes an external party. Interfaces with only one side filled in are drawn from the outside world (given by Exposure) to that component.'),
      diagramBox(ctx)),
  );
}

// ---------------------------------------------------------------- 7 assets
function assets(ctx) {
  const { a, catalog } = ctx;
  const L = catalog.LISTS;
  return h('div', {},
    guidance('What must be protected',
      h('p', {}, 'Functions (essential and safety-relevant), security assets (keys, credentials, firmware, signing keys), network assets (configuration, enabled services), data and personal data. Rate the confidentiality / integrity / availability need of each. EN 18031 "security assets" and "network assets" can be reused here.')),
    section('Assets', grid(a.assets, [
      { key: 'id', label: 'ID', width: 'xs' },
      { key: 'name', label: 'Asset', width: 'm' },
      { key: 'component', label: 'Zone / component', width: 'xs' },
      { key: 'type', label: 'Type', options: ['', ...L.assetType], width: 's' },
      { key: 'description', label: 'Description', multiline: true },
      { key: 'c', label: 'C', options: L.cia, width: 'xs' },
      { key: 'i', label: 'I', options: L.cia, width: 'xs' },
      { key: 'a', label: 'A', options: L.cia, width: 'xs' },
      { key: 'impact', label: 'Impact if compromised', multiline: true },
    ], { onChange: on(ctx), newRow: () => ({ id: nextId('A-', a.assets), name: '', component: '', type: '', description: '', c: '', i: '', a: '', impact: '' }), addLabel: 'Add asset' })),
  );
}

// ---------------------------------------------------------------- threat-model diagram & explainer
// Diagram with an "Arrange boxes" mode: drag (mouse / touch / pen) or arrow keys move boxes.
// Positions are stored in a.diagram.positions and reused by the PDF / SVG exports.
function diagramBox(ctx, { onPick } = {}) {
  const { a } = ctx;
  const st = { editing: false, drag: null, selected: null, frame: 0 };
  const box = h('div', { class: 'diagram', tabindex: '-1' });
  const hint = h('span', { class: 'small muted' });
  const editBtn = h('button', { type: 'button', class: 'btn small', 'aria-pressed': 'false' }, 'Arrange boxes');
  const resetBtn = h('button', { type: 'button', class: 'btn small ghost' }, 'Reset to automatic layout');
  const zoom = h('select', { class: 'zoom', 'aria-label': 'Zoom', title: 'Zoom while arranging' }, [50, 75, 100, 125].map((z) => h('option', { value: z }, `${z} %`)));
  zoom.value = '100';
  zoom.addEventListener('change', () => draw());
  const minPos = Math.ceil(DIAGRAM.PAD / DIAGRAM.GRID) * DIAGRAM.GRID;
  const snap = (v) => Math.max(minPos, Math.round(v / DIAGRAM.GRID) * DIAGRAM.GRID);
  const placed = () => Object.keys(a.diagram.positions).length;

  const draw = () => {
    box.innerHTML = diagramSvg(a, { stride: ctx.ev.stride, interactive: true });
    box.classList.toggle('editing', st.editing);
    zoom.hidden = !st.editing;
    const svgEl = box.querySelector('svg');
    if (st.editing && svgEl) svgEl.style.width = `${(svgEl.viewBox.baseVal.width * Number(zoom.value)) / 100}px`;
    resetBtn.disabled = !placed();
    clear(hint, st.editing
      ? 'Drag boxes to arrange them; arrow keys move the selected box (Shift = larger steps). The layout is saved and used in the PDF.'
      : placed() ? `${placed()} box(es) placed by hand.` : '');
    const sel = st.selected && box.querySelector(`[data-node="${CSS.escape(st.selected)}"]`);
    if (st.editing && sel) {
      const x = Number(sel.dataset.x), y = Number(sel.dataset.y);
      const r = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      for (const [k, v] of Object.entries({ x: x - 10, y: y - 10, width: DIAGRAM.W + 20, height: DIAGRAM.H + 20, rx: 12, fill: 'none', stroke: '#2D5487', 'stroke-width': 2.5 })) r.setAttribute(k, v);
      sel.prepend(r);
    }
  };
  const redrawSoon = () => { cancelAnimationFrame(st.frame); st.frame = requestAnimationFrame(draw); };
  const move = (id, x, y) => { a.diagram.positions[id] = { x: snap(x), y: snap(y) }; };

  editBtn.addEventListener('click', () => {
    st.editing = !st.editing; st.selected = null;
    editBtn.setAttribute('aria-pressed', String(st.editing));
    editBtn.textContent = st.editing ? 'Done arranging' : 'Arrange boxes';
    editBtn.classList.toggle('primary', st.editing);
    draw();
    if (st.editing) box.focus();
  });
  resetBtn.addEventListener('click', () => {
    if (!confirm('Discard all hand-placed positions and use the automatic layout?')) return;
    a.diagram.positions = {}; st.selected = null; ctx.changed();
  });

  box.addEventListener('pointerdown', (e) => {
    if (!st.editing) return;
    const g = e.target.closest('[data-node]');
    if (!g) { st.selected = null; draw(); return; }
    const svg = box.querySelector('svg');
    const scale = svg.viewBox.baseVal.width / svg.getBoundingClientRect().width;
    st.drag = { id: g.dataset.node, sx: e.clientX, sy: e.clientY, sl: box.scrollLeft, stp: box.scrollTop, x0: Number(g.dataset.x), y0: Number(g.dataset.y), scale, moved: false };
    st.selected = g.dataset.node;
    box.setPointerCapture(e.pointerId);
    e.preventDefault();
    box.focus({ preventScroll: true });
  });
  box.addEventListener('pointermove', (e) => {
    const d = st.drag;
    if (!d) return;
    // auto-scroll when the pointer gets close to the edge of the visible area
    const r = box.getBoundingClientRect(), edge = 40, speed = 18;
    if (e.clientX > r.right - edge) box.scrollLeft += speed; else if (e.clientX < r.left + edge) box.scrollLeft -= speed;
    if (e.clientY > r.bottom - edge) box.scrollTop += speed; else if (e.clientY < r.top + edge) box.scrollTop -= speed;
    const dx = (e.clientX - d.sx + box.scrollLeft - d.sl) * d.scale, dy = (e.clientY - d.sy + box.scrollTop - d.stp) * d.scale;
    if (!d.moved && Math.hypot(dx, dy) < 3) return;
    d.moved = true;
    move(d.id, d.x0 + dx, d.y0 + dy);
    redrawSoon();
  });
  const endDrag = () => {
    const d = st.drag;
    st.drag = null;
    if (d?.moved) ctx.changed(); else if (d) draw();
  };
  box.addEventListener('pointerup', endDrag);
  box.addEventListener('pointercancel', endDrag);
  box.addEventListener('keydown', (e) => {
    if (!st.editing || !st.selected || !e.key.startsWith('Arrow')) return;
    const g = box.querySelector(`[data-node="${CSS.escape(st.selected)}"]`);
    if (!g) return;
    const step = e.shiftKey ? 50 : DIAGRAM.GRID;
    const [dx, dy] = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[e.key];
    move(st.selected, Number(g.dataset.x) + dx, Number(g.dataset.y) + dy);
    e.preventDefault();
    ctx.changed();
  });
  box.addEventListener('click', (e) => {
    if (st.editing || !onPick) return;
    const t = e.target.closest('[data-target]');
    if (t) onPick(t.getAttribute('data-target'));
  });

  ctx.hooks.push(() => { if (!st.drag) draw(); });
  return h('div', {}, h('div', { class: 'row small-gap diagram-tools' }, editBtn, zoom, resetBtn, hint), box);
}

function downloadSvg(ctx) {
  const svg = diagramSvg(ctx.a, { stride: ctx.ev.stride });
  const url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
  const link = h('a', { href: url, download: `threat-model_${(ctx.a.product.name || ctx.a.meta.title).replace(/[^A-Za-z0-9._-]+/g, '_')}.svg` });
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function threatModelExplainer() {
  const tut = tutorialAssessment();
  const diag = h('div', { class: 'diagram' });
  diag.innerHTML = diagramSvg(tut);
  const dlg = modal('What is threat modelling? – a worked example', h('div', { class: 'explainer' },
    h('p', {}, 'Threat modelling is a structured way to find out what can go wrong with a product before attackers do. Instead of brainstorming a list of threats, you look at the product\'s design element by element and ask the same six questions (STRIDE) everywhere. The result is the list of threat scenarios that the risk assessment then rates and treats.'),
    h('h3', {}, 'The four questions'),
    h('table', { class: 'list' }, h('thead', {}, h('tr', {}, h('th', {}, 'Question'), h('th', {}, 'What you do'), h('th', {}, 'Where in this tool'))),
      h('tbody', {}, FOUR_QUESTIONS.map((x, i) => h('tr', {}, h('td', {}, h('b', {}, `${i + 1}. ${x.q}`)), h('td', {}, x.a), h('td', { class: 'muted' }, x.step))))),
    h('h3', {}, 'Example: a smart thermostat'),
    h('p', {}, 'Step 1 is a picture of the system. Boxes with a dashed red line are parts you build (each inside its own trust boundary); grey boxes are the outside world. Every arrow is an interface where something crosses a boundary – that is where attacks happen.'),
    diag,
    h('h3', {}, `Step 2: one interface through all six STRIDE questions – ${WALKTHROUGH.element}`),
    h('p', { class: 'muted' }, WALKTHROUGH.context),
    h('table', { class: 'list walk' }, h('thead', {}, h('tr', {}, ['', 'Question', 'Answer for this interface', 'Outcome'].map((t) => h('th', {}, t)))),
      h('tbody', {}, WALKTHROUGH.rows.map((r) => h('tr', {}, h('td', { class: 'mono big' }, r.letter), h('td', { class: 'small' }, r.question), h('td', {}, r.answer),
        h('td', {}, h('span', { class: `cell ${r.decision === 'na' ? 'na' : 'covered'}` }, r.outcome)))))),
    h('p', {}, 'Repeat this for every interface and component. In the matrix each answer becomes a green cell (a risk covers it) or a grey cell (justified as not applicable). Amber cells are questions nobody has answered yet.'),
    h('h3', {}, 'Step 3: from threat to risk'),
    h('p', {}, 'The Bluetooth spoofing threat becomes risk R-002: likelihood 3 (radio range needed, simple tools) × impact 4 (heating controlled by a stranger) = 12, High. Controls: per-device setup code, encrypted pairing, setup mode only after a button press. Residual: 1 × 4 = 4, Low. The controls map to CRA Annex I(2)(b) secure by default and (2)(d) protection from unauthorised access.'),
    h('h3', {}, 'Tips'),
    h('ul', {}, WALKTHROUGH.tips.map((t) => h('li', {}, t)))),
  [h('button', { class: 'btn', onclick: () => dlg.close() }, 'Close'),
    h('button', { class: 'btn primary', onclick: async () => {
      const r = await api.fromExample(TUTORIAL_ID); dlg.close(); location.hash = `#/p/${r.id}/a/stride`;
    } }, 'Open the thermostat as a practice assessment')]);
  dlg.classList.add('wide');
}

// ---------------------------------------------------------------- STRIDE sweep
const CELL_TEXT = { covered: null, na: 'N/A', 'na-missing': 'N/A – reason?', open: 'open' };

function stride(ctx) {
  const { a, catalog } = ctx;
  const matrix = h('div', {});
  const progress = h('div', { class: 'stride-progress' });
  const draw = (ev) => {
    const targets = strideTargets(a);
    const st = ev.stride;
    const total = targets.length * 6;
    const done = targets.reduce((n, t) => n + catalog.STRIDE.filter((x) => ['covered', 'na'].includes(st[t.id][x.letter].status)).length, 0);
    clear(progress, total ? [h('b', {}, `${done} / ${total}`), ' decisions made', h('div', { class: 'bar' }, h('span', { class: `fill p${Math.round((done / total) * 20) * 5}` }))] : null);
    clear(matrix, targets.length ? h('div', { class: 'grid-wrap' }, h('table', { class: 'stride' },
      h('thead', {}, h('tr', {}, h('th', {}, 'Element'), catalog.STRIDE.map((x) => h('th', { title: `${x.label} – ${x.property}` }, x.letter, h('div', { class: 'prop' }, x.property))))),
      h('tbody', {}, targets.map((t) => h('tr', {},
        h('th', { class: 'el' }, h('span', { class: 'mono' }, t.id), ' ', t.name || '', h('div', { class: 'small muted' }, t.kind === 'component' ? 'component / zone' : 'interface / conduit', t.detail ? ` · ${t.detail}` : '')),
        catalog.STRIDE.map((x) => {
          const c = st[t.id][x.letter];
          return h('td', {}, h('button', { type: 'button', class: `cell ${c.status}`, title: `${t.id} – ${x.label}`, onclick: () => strideCellEditor(ctx, t, x) },
            c.status === 'covered' ? c.risks.join(', ') : CELL_TEXT[c.status]));
        })))))) : h('p', { class: 'muted' }, 'Define components and interfaces in the Architecture step first.'));
  };
  ctx.hooks.push(draw);
  const pick = (id) => {
    const row = [...matrix.querySelectorAll('th.el')].find((th) => th.querySelector('.mono')?.textContent === id)?.closest('tr');
    if (!row) return;
    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    row.classList.add('flash'); setTimeout(() => row.classList.remove('flash'), 1600);
  };
  const untouched = !Object.keys(a.stride).length && !a.risks.some((r) => r.stride);
  return h('div', {},
    h('div', { class: 'callout' + (untouched ? ' strong' : '') },
      h('div', {}, h('b', {}, 'New to threat modelling? '), 'See a short worked example – a smart thermostat taken through all six STRIDE questions – before you start.'),
      h('button', { class: 'btn ro-ok' + (untouched ? ' primary' : ''), onclick: threatModelExplainer }, 'Show worked example')),
    section('Threat model diagram',
      h('p', { class: 'muted small' }, 'Generated from the Architecture step. Colours show the STRIDE status of each interface and component. Click a box or label to jump to its row in the matrix; use “Arrange boxes” to lay out larger systems by hand.'),
      diagramBox(ctx, { onPick: pick }),
      h('div', { class: 'row small-gap' }, h('button', { class: 'btn small ro-ok', onclick: () => downloadSvg(ctx) }, 'Download diagram (SVG)'), h('a', { class: 'btn small ghost', href: `#/p/${ctx.pid}/a/architecture` }, 'Edit architecture'))),
    guidance('Systematic threat identification',
      h('p', {}, 'Go through every in-scope component / zone and every interface / conduit with the six STRIDE categories. For each cell, either link the threat scenario(s) in the risk register that address it, or record why the category is not applicable. This documents that threat identification was complete – not only that some threats were found.'),
      h('p', {}, 'A cell is covered automatically when a risk references the element and has the matching STRIDE category. Click a cell to see the guiding question, create a scenario (blank or from the library) or mark it not applicable.'),
      h('p', { class: 'legend' }, h('span', { class: 'cell covered' }, 'R-001'), ' covered by risk  ', h('span', { class: 'cell na' }, 'N/A'), ' not applicable (justified)  ', h('span', { class: 'cell open' }, 'open'), ' decision missing')),
    section('STRIDE matrix', progress, matrix),
  );
}

function strideCellEditor(ctx, t, x) {
  const { a, catalog } = ctx;
  const ensure = () => {
    a.stride[t.id] = a.stride[t.id] || {};
    a.stride[t.id][x.letter] = strideCell(a, t.id, x.letter);
    return a.stride[t.id][x.letter];
  };
  const cell = strideCell(a, t.id, x.letter);
  const derived = a.risks.filter((r) => String(r.stride || '').startsWith(x.letter) && splitRefs(r.interfaces).includes(t.id));
  const others = a.risks.filter((r) => !derived.includes(r)).map((r) => r.id);
  const save = (k, v) => { const c = ensure(); c[k] = v; ctx.changed(); };
  const openRisk = (r) => { dlg.close(); editRisk(ctx, r, () => ctx.refresh()); };
  const create = (tpl) => {
    const r = newRisk(a, tpl);
    r.interfaces = t.id; r.stride = tpl ? tpl.stride : x.label;
    if (!tpl) r.vector = [t.name, t.detail].filter(Boolean).join(' – ');
    a.risks.push(r); ctx.changed(); openRisk(r);
  };
  const suggestions = catalog.THREAT_LIBRARY.filter((l) => l.stride.startsWith(x.letter) && l.markets.some((m) => a.profile.markets.includes(m)));
  const refBox = { v: splitRefs(cell.refs) };
  const naBox = { na: cell.na, justification: cell.justification };

  const dlg = modal(`${t.id} ${t.name || ''} – ${x.label}`, h('div', { class: 'stride-editor' },
    h('div', { class: 'guidance' }, h('b', {}, `${x.property}: `), x.question, h('div', { class: 'small muted' }, `Typical: ${x.examples}`)),
    h('h3', {}, 'Risk scenarios covering this cell'),
    derived.length ? h('ul', { class: 'plain' }, derived.map((r) => h('li', {}, h('button', { type: 'button', class: 'link', onclick: () => openRisk(r) }, r.id), ' ', r.scenario || h('i', { class: 'muted' }, 'empty scenario'))))
      : h('p', { class: 'muted small' }, `No risk references ${t.id} with category ${x.letter} yet.`),
    others.length ? h('div', { class: 'field wide' }, h('label', {}, 'Also covered by (existing risks with a different STRIDE category or element)'),
      chips(refBox, 'v', others, { titleOf: (id) => a.risks.find((r) => r.id === id)?.scenario, onChange: () => save('refs', refBox.v) })) : null,
    h('div', { class: 'row small-gap' },
      h('button', { type: 'button', class: 'btn primary', onclick: () => create(null) }, '+ New scenario for this cell')),
    suggestions.length ? h('details', {}, h('summary', {}, `Suggestions from the threat library (${suggestions.length})`),
      h('ul', { class: 'plain' }, suggestions.map((l) => h('li', {}, h('button', { type: 'button', class: 'btn small ghost', onclick: () => create(l) }, 'Use'), ' ', h('b', {}, l.title), ' – ', h('span', { class: 'small' }, l.scenario))))) : null,
    h('h3', {}, 'Or: not applicable'),
    field(naBox, 'na', { type: 'checkbox', label: `${x.letter} is not applicable to ${t.id}`, onChange: () => save('na', naBox.na) }),
    field(naBox, 'justification', { label: 'Justification', type: 'textarea', rows: 2, wide: true,
      placeholder: 'e.g. read-only diagnostic output, no data or commands accepted; physical access already implies full control …', onChange: () => save('justification', naBox.justification) })),
  [h('button', { class: 'btn primary', onclick: () => dlg.close() }, 'Done')]);
}

// ---------------------------------------------------------------- approvals (four-eyes: recorded server-side with the approver's identity)
function approvalBox(ctx, { target, index, approvedBy, approvedAt, label }) {
  const act = async (revoke) => {
    await ctx.flush();
    try { ctx.applyApproval(await api.approve(ctx.pid, { target, index, revoke })); toast(revoke ? 'Approval withdrawn.' : 'Approved.'); } catch (e) { toast(e.message, 'error'); }
  };
  return h('div', { class: 'approval ro-ok' },
    approvedBy ? [badge('ok', 'Approved'), ' ', h('span', {}, approvedBy), approvedAt ? h('span', { class: 'muted' }, ` · ${approvedAt}`) : null]
      : badge('warning', 'Not approved'),
    ctx.perms.approve ? h('button', { type: 'button', class: 'btn small' + (approvedBy ? ' ghost' : ' primary'), onclick: () => act(!!approvedBy) }, approvedBy ? 'Withdraw approval' : label || 'Approve')
      : !approvedBy ? h('span', { class: 'small muted' }, ' An approver or owner of this product approves.') : null);
}

// ---------------------------------------------------------------- 8 method
function method(ctx) {
  const { a, catalog } = ctx;
  const m = a.method;
  // any change to the yardstick invalidates its approval
  const baseChanged = ctx.changed;
  ctx = { ...ctx, changed: (opts) => {
    if (m.approvedBy) { m.approvedBy = ''; m.approvedAt = ''; toast('Risk method changed – the approval was withdrawn.'); baseChanged({ rerender: true }); return; }
    baseChanged(opts);
  } };
  const scaleTable = (rows, cols, title) => h('div', {}, h('h3', {}, title),
    h('table', { class: 'grid' },
      h('thead', {}, h('tr', {}, h('th', { class: 'w-xs' }, 'Level'), h('th', { class: 'w-s' }, 'Label'), cols.map((c, i) => h('th', {}, (() => { const inp = h('input', { type: 'text', value: c }); inp.addEventListener('input', () => { cols[i] = inp.value; ctx.changed(); }); return inp; })())))),
      h('tbody', {}, rows.map((r) => h('tr', {}, h('td', { class: 'mono' }, r.level),
        h('td', {}, (() => { const inp = h('input', { type: 'text', value: r.label }); inp.addEventListener('input', () => { r.label = inp.value; ctx.changed(); }); return inp; })()),
        cols.map((_, i) => h('td', {}, (() => { const t = h('textarea', { rows: 2, value: r.criteria[i] ?? '' }); t.addEventListener('input', () => { r.criteria[i] = t.value; ctx.changed(); }); return t; })())))))));
  const presetSel = { v: '' };
  return h('div', {},
    guidance('Agree the yardstick before rating',
      h('p', {}, 'Risk score = likelihood × impact (1–25). Adapt scales and acceptance thresholds to your company and have them approved before risks are rated – otherwise ratings are not comparable between products or reviews.')),
    section('Scale preset', h('div', { class: 'row' },
      h('span', {}, 'Current: ', h('b', {}, m.label || m.preset)),
      field(presetSel, 'v', { type: 'select', options: [['', 'Replace with preset…'], ...Object.entries(catalog.METHOD_PRESETS).map(([k, v]) => [k, v.label])], onChange: () => {
        if (!presetSel.v) return;
        if (!confirm('Replace the current scales and thresholds with this preset? Existing risk ratings keep their numbers.')) { presetSel.v = ''; return; }
        Object.assign(a.method, structuredClone({ preset: presetSel.v, ...catalog.METHOD_PRESETS[presetSel.v] }), { approvedBy: '', approvedAt: '' });
        ctx.changed({ rerender: true });
      } }))),
    section('Scales', scaleTable(m.likelihood, m.likelihoodColumns, 'Likelihood'), scaleTable(m.impact, m.impactColumns, 'Impact')),
    section('Rating thresholds & acceptance', grid(m.thresholds, [
      { key: 'rating', label: 'Rating', readonly: true, width: 's' },
      { key: 'min', label: 'Min. score', width: 'xs' },
      { key: 'rule', label: 'Acceptance rule', multiline: true },
    ], { onChange: () => { for (const t of m.thresholds) t.min = Number(t.min) || t.min; ctx.changed(); } }), heat(m)),
    section('Approval', h('p', { class: 'muted small' }, 'Approval is recorded with the approver’s sign-in identity. Changing scales or thresholds withdraws an existing approval.'),
      approvalBox(ctx, { target: 'method', approvedBy: m.approvedBy, approvedAt: m.approvedAt, label: 'Approve risk method' })),
  );
}

function heat(m) {
  const rows = [5, 4, 3, 2, 1];
  const rating = (s) => [...m.thresholds].sort((x, y) => y.min - x.min).find((t) => s >= t.min)?.rating || '';
  return h('table', { class: 'heat' }, h('tr', {}, h('th', {}, 'L \\ I'), [1, 2, 3, 4, 5].map((i) => h('th', {}, i))),
    rows.map((l) => h('tr', {}, h('th', {}, l), [1, 2, 3, 4, 5].map((i) => h('td', { class: `r-${rating(l * i).toLowerCase()}` }, l * i)))));
}

// ---------------------------------------------------------------- 9 risks
function risks(ctx) {
  const { a, catalog } = ctx;
  const list = h('div', {});
  const coverage = h('div', {});
  const render = () => {
    const ev = ctx.ev;
    clear(list, a.risks.length ? h('table', { class: 'list risks' },
      h('thead', {}, h('tr', {}, ['ID', 'Where', 'Threat scenario', 'Inherent', 'Controls', 'Residual', 'Treatment', 'Status', ''].map((t) => h('th', {}, t)))),
      h('tbody', {}, ev.risks.map((r, idx) => h('tr', { class: 'clickable', onclick: () => editRisk(ctx, a.risks[idx], render) },
        h('td', { class: 'mono' }, r.id),
        h('td', { class: 'mono small' }, splitRefs(r.interfaces).join(', '), h('br'), splitRefs(r.assets).join(', ')),
        h('td', {}, r.scenario || h('i', { class: 'muted' }, 'empty')),
        h('td', {}, r.inherentScore ?? '', ' ', ratingBadge(r.inherentRating)),
        h('td', { class: 'small clamp' }, r.controls),
        h('td', {}, r.residualScore ?? '', ' ', ratingBadge(r.residualRating)),
        h('td', {}, r.treatment),
        h('td', {}, r.status),
        h('td', {}, h('button', { class: 'icon danger', title: 'Delete risk', 'aria-label': `Delete ${r.id}`, onclick: (e) => {
          e.stopPropagation();
          if (!confirm(`Delete ${r.id}?`)) return;
          a.risks.splice(idx, 1); ctx.changed(); render();
        } }, '×')))))) : h('p', { class: 'muted' }, 'No risks yet. Start from the threat library or add a blank scenario.'));
    const usedIf = new Set(a.risks.flatMap((r) => splitRefs(r.interfaces).flatMap((x) => x.split(/\s*\/\s*/))));
    const usedAs = new Set(a.risks.flatMap((r) => splitRefs(r.assets)));
    const openIf = a.interfaces.filter((i) => !usedIf.has(i.id));
    const openAs = a.assets.filter((x) => !usedAs.has(x.id));
    clear(coverage, (openIf.length || openAs.length) ? h('div', { class: 'coverage' },
      h('b', {}, 'Not yet covered by a scenario: '),
      openIf.map((i) => badge('warning', `${i.id} ${i.name || ''}`)), ' ', openAs.map((x) => badge('muted', `${x.id} ${x.name || ''}`))) : null);
  };
  ctx.hooks.push(render);
  return h('div', {},
    guidance('One row per threat scenario',
      h('p', {}, 'For each interface / zone and asset ask: who could misuse it (actor), how (attack vector), and what would happen (consequence, including physical and safety effects – Art. 13(2)). Rate inherent risk before controls, describe controls, map them to Annex I requirements, and rate residual risk. STRIDE helps to check completeness per interface.'),
      h('p', {}, 'Residual Critical blocks placing on the market; residual High needs documented management acceptance.')),
    section('Risk register',
      h('div', { class: 'row small-gap' },
        h('button', { class: 'btn primary', onclick: () => library(ctx, render) }, '+ From threat library'),
        h('button', { class: 'btn', onclick: () => { const r = newRisk(a); a.risks.push(r); ctx.changed(); render(); editRisk(ctx, r, render); } }, '+ Blank scenario')),
      coverage, list),
    section('Heat maps (number of risks per cell)', h('div', { class: 'row' }, heatCounts(ctx, 'inherent'), heatCounts(ctx, 'residual'))),
  );
}

function heatCounts(ctx, which) {
  const box = h('div', {});
  const draw = (ev) => {
    const g = heatmap(ev.risks, which);
    const m = ctx.a.method;
    const rating = (s) => [...m.thresholds].sort((x, y) => y.min - x.min).find((t) => s >= t.min)?.rating || '';
    clear(box, h('h3', {}, which === 'inherent' ? 'Inherent' : 'Residual'), h('table', { class: 'heat' },
      h('tr', {}, h('th', {}, 'L \\ I'), [1, 2, 3, 4, 5].map((i) => h('th', {}, i))),
      g.map((row, ri) => h('tr', {}, h('th', {}, 5 - ri), row.map((n, ci) => h('td', { class: `r-${rating((5 - ri) * (ci + 1)).toLowerCase()}` }, n || ''))))));
  };
  ctx.hooks.push(draw);
  return box;
}

function library(ctx, after) {
  const { a, catalog } = ctx;
  const sel = new Set();
  const used = new Set(a.risks.map((r) => r.source));
  const items = catalog.THREAT_LIBRARY.filter((t) => t.markets.some((m) => a.profile.markets.includes(m)));
  const dlg = modal('Threat library', h('div', {},
    h('p', { class: 'muted' }, 'Generic scenarios from the company templates. Selected entries are added as new risks with suggested controls and mappings – adapt scenario, references and ratings to your product.'),
    h('div', { class: 'library' }, items.map((t) => h('label', { class: 'lib-item' + (used.has(t.id) ? ' used' : '') },
      h('input', { type: 'checkbox', onchange: (e) => (e.target.checked ? sel.add(t) : sel.delete(t)) }),
      h('div', {}, h('b', {}, t.title), used.has(t.id) ? badge('muted', 'already used') : null, h('div', { class: 'small' }, t.scenario),
        h('div', { class: 'small muted' }, `${t.stride} · Annex I: ${t.annex.join(', ')}`)))))),
  [h('button', { class: 'btn', onclick: () => dlg.close() }, 'Cancel'),
    h('button', { class: 'btn primary', onclick: () => {
      for (const t of sel) a.risks.push(newRisk(a, t));
      dlg.close(); ctx.changed(); after(); toast(`${sel.size} scenario(s) added – open each one to adapt and rate it.`);
    } }, 'Add selected')]);
}

function refChips(obj, key, options, onChange, titleOf) {
  // stored as comma-separated string for readability in exports
  if (!options.length) return h('div', { class: 'help' }, 'Nothing defined yet – add entries in the Architecture / Assets steps first.');
  const tmp = { v: splitRefs(obj[key]) };
  return chips(tmp, 'v', options, { titleOf, onChange: () => { obj[key] = tmp.v.join(', '); onChange(); } });
}

function editRisk(ctx, r, after) {
  const { a, catalog } = ctx;
  const st = a.profile.standards;
  const L = catalog.LISTS;
  const o = { onChange: () => { ctx.changed(); upd(); } };
  const scale = (lvls) => [['', '—'], ...lvls.map((l) => [String(l.level), `${l.level} – ${l.label}`])];
  const inh = h('div', { class: 'score' });
  const res = h('div', { class: 'score' });
  const upd = () => {
    const s = scoreRisk(r, a.method);
    clear(inh, 'Inherent score: ', h('b', {}, s.inherentScore ?? '—'), ' ', ratingBadge(s.inherentRating));
    clear(res, 'Residual score: ', h('b', {}, s.residualScore ?? '—'), ' ', ratingBadge(s.residualRating));
  };
  upd();
  const actors = [...L.actors.common, ...(isConsumer(a) ? L.actors.consumer : []), ...(isPro(a) ? L.actors.professional : [])];
  const dl = h('datalist', { id: 'actors' }, actors.map((x) => h('option', { value: x })));
  const actorField = field(r, 'actor', { label: 'Threat actor', ...o });
  actorField.querySelector('input').setAttribute('list', 'actors');
  const levelHelp = (lv) => lv.map((l) => `${l.level} ${l.label}: ${l.criteria.join(' / ')}`).join('\n');
  const annexTitle = (id) => catalog.ANNEX_I.find((x) => x.id === id)?.text;

  const dlg = modal(`Risk ${r.id}`, h('div', { class: 'risk-form' }, dl,
    h('h3', {}, 'Scenario'),
    fields(
      field(r, 'id', { label: 'Risk ID', ...o }),
      field(r, 'stride', { label: 'STRIDE', type: 'select', options: ['', ...L.stride], ...o }),
      actorField,
      field(r, 'vector', { label: 'Attack vector / entry point', ...o }),
      field(r, 'scenario', { label: 'Threat scenario', type: 'textarea', wide: true, ...o }),
      field(r, 'consequence', { label: 'Consequence (safety / property / privacy / operations / others)', type: 'textarea', rows: 2, wide: true, ...o })),
    h('div', { class: 'field wide' }, h('label', {}, 'Interfaces / zones affected'), refChips(r, 'interfaces', [...a.components.map((c) => c.id), ...a.interfaces.map((i) => i.id)], o.onChange,
      (id) => [...a.components, ...a.interfaces].find((x) => x.id === id)?.name)),
    h('div', { class: 'field wide' }, h('label', {}, 'Assets affected'), refChips(r, 'assets', a.assets.map((x) => x.id), o.onChange, (id) => a.assets.find((x) => x.id === id)?.name)),
    h('h3', {}, 'Inherent risk (before controls)'),
    fields(
      field(r, 'inherentL', { label: 'Likelihood', type: 'select', options: scale(a.method.likelihood), ...o }),
      field(r, 'inherentI', { label: 'Impact', type: 'select', options: scale(a.method.impact), ...o }), inh),
    h('h3', {}, 'Controls and traceability'),
    fields(
      field(r, 'controls', { label: 'Controls / mitigations', type: 'textarea', rows: 4, wide: true, ...o }),
      field(r, 'evidence', { label: 'Verification evidence (test report, document ref)', wide: true, ...o })),
    h('div', { class: 'field wide' }, h('label', {}, 'CRA Annex I requirements addressed'), refChips(r, 'annex', catalog.ANNEX_I.map((x) => x.id), o.onChange, annexTitle)),
    st.en18031 && h('div', { class: 'field wide' }, h('label', {}, 'EN 18031 mechanisms'), refChips(r, 'en18031', catalog.EN18031_MECHANISMS.map((x) => x.id), o.onChange, (id) => catalog.EN18031_MECHANISMS.find((x) => x.id === id)?.label)),
    st.en303645 && h('div', { class: 'field wide' }, h('label', {}, 'EN 303 645 clauses'), refChips(r, 'en303645', catalog.EN303645.map((x) => x.id), o.onChange, (id) => catalog.EN303645.find((x) => x.id === id)?.topic)),
    st.iec62443 && fields(field(r, 'iec62443', { label: 'IEC 62443 references', placeholder: 'e.g. 4-2 CR 1.1, CR 2.1', wide: true, ...o })),
    h('h3', {}, 'Residual risk (after controls)'),
    fields(
      field(r, 'residualL', { label: 'Likelihood', type: 'select', options: scale(a.method.likelihood), ...o }),
      field(r, 'residualI', { label: 'Impact', type: 'select', options: scale(a.method.impact), ...o }), res),
    h('h3', {}, 'Treatment'),
    fields(
      field(r, 'treatment', { label: 'Treatment', type: 'select', options: L.treatment, ...o }),
      field(r, 'owner', { label: 'Risk owner', ...o }),
      field(r, 'status', { label: 'Status', type: 'select', options: L.status, ...o }),
      field(r, 'lastReviewed', { label: 'Last reviewed', type: 'date', ...o }),
      field(r, 'acceptance', { label: 'Acceptance justification and approver (required for "Accept")', type: 'textarea', rows: 2, wide: true, ...o })),
    h('details', { class: 'small' }, h('summary', {}, 'Scale definitions'), h('pre', {}, 'Likelihood\n' + levelHelp(a.method.likelihood) + '\n\nImpact\n' + levelHelp(a.method.impact)))),
  [h('button', { class: 'btn primary', onclick: () => dlg.close() }, 'Done')]);
  dlg.classList.add('wide');
  dlg.addEventListener('close', () => after());
}

// ---------------------------------------------------------------- 10 Annex I
function annex1(ctx) {
  const { a, catalog } = ctx;
  const st = a.profile.standards;
  const card = (req) => {
    const e = a.annexI[req.id];
    const status = h('span', {});
    const just = h('div', {});
    const drawJust = () => clear(just, e.applicable === 'No'
      ? field(e, 'justification', { label: 'Clear justification why not applicable (Art. 13(4))', type: 'textarea', rows: 2, wide: true, onChange: on(ctx) })
      : null);
    drawJust();
    ctx.hooks.push((ev) => {
      const s = ev.annex[req.id];
      clear(status, badge(s.level === 'ok' ? 'ok' : s.level, s.status), s.linked.length ? h('span', { class: 'small muted' }, ' ', s.linked.join(', ')) : null);
    });
    return h('div', { class: 'req' },
      h('div', { class: 'req-head' }, h('span', { class: 'mono' }, req.id), h('span', { class: 'muted small' }, req.ref), h('span', { class: 'spacer' }), status),
      h('p', {}, req.text),
      h('details', { class: 'small' }, h('summary', {}, 'Official German text'), h('p', { lang: 'de' }, req.textDe)),
      h('div', { class: 'small muted' }, [
        st.en18031 && req.en18031.length ? `EN 18031: ${req.en18031.join(', ')}` : '',
        st.en303645 && req.en303645.length ? `EN 303 645: ${req.en303645.join(', ')}` : '',
        st.iec62443 && req.iec62443 && req.iec62443 !== '—' ? `IEC 62443: ${req.iec62443}` : '',
        req.process ? `Process: ${req.process}` : '',
      ].filter(Boolean).join(' · ')),
      fields(
        field(e, 'applicable', { label: 'Applicable?', type: 'select', options: catalog.LISTS.applicable, onChange: () => { drawJust(); ctx.changed(); } }),
        field(e, 'evidence', { label: 'Evidence / document reference', onChange: on(ctx) }),
        field(e, 'implementation', { label: 'How it is implemented', type: 'textarea', rows: 2, wide: true, onChange: on(ctx) })),
      just);
  };
  return h('div', {},
    guidance('Art. 13(3)-(4)',
      h('p', {}, 'For every requirement of Annex I Part I(2) state whether it is applicable and how it is implemented based on the risk assessment. Also state how Part I(1) is applied and how the vulnerability-handling requirements of Part II are applied. Where a requirement is not applicable, a clear justification is mandatory. Coverage is derived from risks that reference the requirement.'),
      h('div', { class: 'row small-gap' }, h('button', { class: 'btn small ghost', onclick: () => {
        let n = 0;
        for (const r of catalog.ANNEX_I) if (!a.annexI[r.id].applicable) { a.annexI[r.id].applicable = 'Yes'; n++; }
        toast(`${n} requirement(s) set to "Yes".`); ctx.changed({ rerender: true });
      } }, 'Mark all unassessed as applicable'))),
    section('Part I – Cybersecurity requirements relating to the properties of products', catalog.ANNEX_I.filter((r) => r.part === 'I').map(card)),
    section('Part II – Vulnerability handling requirements', h('p', { class: 'muted' }, 'Part II describes manufacturer processes (PSIRT). They apply to every product; reference shared company processes where applicable.'),
      catalog.ANNEX_I.filter((r) => r.part === 'II').map(card)),
  );
}

// ---------------------------------------------------------------- 11 EN 303 645
function en303645(ctx) {
  const { a, catalog } = ctx;
  return h('div', {},
    guidance('Clause-level checklist',
      h('p', {}, 'Clause-level summary for consumer IoT. Expand into individual provisions (e.g. 5.1-1, 5.1-2) in the evidence field if you assess against the standard in detail; test per ETSI TS 103 701. Risks referencing a clause or provision count as coverage.')),
    section('ETSI EN 303 645', catalog.EN303645.map((c) => {
      const e = a.en303645[c.id];
      const status = h('span', {});
      ctx.hooks.push((ev) => clear(status, badge(ev.en303645[c.id].level, ev.en303645[c.id].status)));
      return h('div', { class: 'req' },
        h('div', { class: 'req-head' }, h('span', { class: 'mono' }, c.id), h('b', {}, c.topic), h('span', { class: 'spacer' }), status),
        h('p', { class: 'small' }, c.intent, ' ', h('span', { class: 'muted' }, `Annex I: ${c.annex.join(', ')}${c.psti && a.profile.ukMarket ? ` · PSTI: ${c.psti}` : ''}`)),
        fields(
          field(e, 'applicable', { label: 'Applicable?', type: 'select', options: catalog.LISTS.applicable, onChange: on(ctx) }),
          field(e, 'evidence', { label: 'Evidence (TS 103 701 / test report)', onChange: on(ctx) }),
          field(e, 'implementation', { label: 'Implementation / justification', type: 'textarea', rows: 2, wide: true, onChange: (k, v) => { if (e.applicable === 'No') e.justification = v; ctx.changed(); } })));
    })),
  );
}

// ---------------------------------------------------------------- 12 user info
function userinfo(ctx) {
  const { a, catalog } = ctx;
  return h('div', {},
    guidance('Annex II and Art. 13(18)-(19)',
      h('p', {}, 'Information and instructions that must accompany the product, in a language easily understood by users and market surveillance authorities. They must remain available for at least 10 years or the support period, whichever is longer. Annex II applies to consumer and commercial products alike.')),
    section('User information', h('table', { class: 'grid' },
      h('thead', {}, h('tr', {}, ['ID', 'Requirement', 'Where provided', 'Content / link', 'Owner', 'Status', 'Evidence'].map((t) => h('th', {}, t)))),
      h('tbody', {}, userInfoItems(a).map((u) => {
        const e = a.userInfo[u.id];
        const sel = (key, opts) => { const s = h('select', {}, opts.map((x) => h('option', { value: x }, x || '—'))); s.value = e[key]; s.addEventListener('change', () => { e[key] = s.value; ctx.changed(); }); return s; };
        const txt = (key, multi) => { const t = multi ? h('textarea', { rows: 2, value: e[key] }) : h('input', { type: 'text', value: e[key] }); t.addEventListener('input', () => { e[key] = t.value; ctx.changed(); }); return t; };
        return h('tr', {}, h('td', { class: 'mono' }, u.id), h('td', { class: 'small' }, u.text, h('div', { class: 'muted' }, u.ref)),
          h('td', {}, sel('where', ['', ...catalog.LISTS.userInfoWhere])), h('td', {}, txt('content', true)), h('td', {}, txt('owner')),
          h('td', {}, sel('status', catalog.LISTS.userInfoStatus)), h('td', {}, txt('evidence')));
      })))),
  );
}

// ---------------------------------------------------------------- 13 review
function review(ctx) {
  const { a } = ctx;
  const events = h('div', {}, h('p', { class: 'muted' }, 'Loading…'));
  api.productEvents(ctx.pid).then((ev) => clear(events, h('table', { class: 'list' }, h('tbody', {}, ev.map((x) => h('tr', {}, h('td', { class: 'small muted' }, new Date(x.at).toLocaleString()), h('td', {}, x.actor), h('td', {}, x.action), h('td', { class: 'small mono' }, x.detail))))))).catch(() => clear(events, 'Could not load the change history.'));
  return h('div', {},
    guidance('Keep the assessment alive',
      h('p', {}, 'The assessment is documented and updated as appropriate during the support period (Art. 13(3), Art. 31(2)). Re-assess on: hardware / firmware / cloud design changes, new interfaces or remote-access features, new integrations, new exploitable vulnerabilities or incidents (Art. 13(7), Art. 14), and at least at the agreed periodic review.')),
    section('Document state', fields(
      field(a.meta, 'version', { label: 'Version', onChange: on(ctx) }),
      a.meta.status === 'approved'
        ? h('div', { class: 'field' }, h('label', {}, 'Status'), approvalBox(ctx, { target: 'status', approvedBy: 'Assessment approved', label: 'Approve assessment' }))
        : h('div', {}, field(a.meta, 'status', { label: 'Status', type: 'select', options: [['draft', 'Draft'], ['in_review', 'In review']], onChange: on(ctx) }),
          ctx.perms.approve ? h('div', { class: 'ro-ok' }, h('button', { type: 'button', class: 'btn small primary', onclick: async () => { await ctx.flush(); try { ctx.applyApproval(await api.approve(ctx.pid, { target: 'status' })); toast('Assessment approved.'); } catch (e) { toast(e.message, 'error'); } } }, 'Approve assessment')) : null))),
    section('Review log', grid(a.reviewLog, [
      { key: 'version', label: 'Version', width: 'xs' }, { key: 'date', label: 'Date', width: 's' }, { key: 'author', label: 'Author', width: 's' },
      { key: 'trigger', label: 'Trigger', multiline: true }, { key: 'summary', label: 'Summary of changes', multiline: true },
      { key: 'risks', label: 'Risks added / changed', width: 's' },
      { key: 'approvedBy', label: 'Approval', width: 'm', render: (row, i) => approvalBox(ctx, { target: 'revision', index: i, approvedBy: row.approvedBy, approvedAt: row.approvalDate }) },
    ], { onChange: on(ctx), newRow: () => ({ version: a.meta.version, date: new Date().toISOString().slice(0, 10), author: '', trigger: '', summary: '', risks: '', approvedBy: '', approvalDate: '' }), addLabel: 'Add revision' })),
    section('Change history (audit trail)', events),
  );
}

// ---------------------------------------------------------------- 14 summary
function summary(ctx) {
  const { a } = ctx;
  const dash = h('div', {});
  const snaps = h('div', {});
  const loadSnaps = () => api.snapshots(ctx.pid).then((list) => clear(snaps, list.length ? h('table', { class: 'list' },
    h('thead', {}, h('tr', {}, ['Version', 'Frozen', 'By', 'Note', 'SHA-256', 'Download'].map((t) => h('th', {}, t)))),
    h('tbody', {}, list.map((s) => h('tr', {}, h('td', {}, s.version), h('td', { class: 'small' }, new Date(s.createdAt).toLocaleString()), h('td', {}, s.createdBy),
      h('td', { class: 'small' }, s.note), h('td', { class: 'mono small', title: s.sha256 }, s.sha256.slice(0, 16) + '…'),
      h('td', { class: 'actions' }, ['pdf', 'xlsx', 'json'].map((f) => h('a', { class: 'btn small ghost', href: api.exportUrl(ctx.pid, f, s.id) }, f.toUpperCase()))))))) : h('p', { class: 'muted' }, 'No frozen versions yet.')));
  loadSnaps();
  const note = { v: '' };
  const steps = visibleSteps(a);
  const label = (id) => STEPS.find((s) => s.id === id)?.label;

  ctx.hooks.push((ev) => {
    const tile = (n, l, lvl) => h('div', { class: `tile ${lvl || ''}` }, h('div', { class: 'n' }, n), h('div', { class: 'l' }, l));
    const groups = steps.map((s) => [s, ev.findings.filter((f) => f.step === s.id && f.level !== 'info')]).filter(([, f]) => f.length);
    clear(dash,
      h('div', { class: 'tiles' },
        tile(ev.risks.length, 'Risks'),
        tile(ev.counts.residual.Critical || 0, 'Residual critical', (ev.counts.residual.Critical || 0) ? 'blocker' : 'ok'),
        tile(ev.counts.residual.High || 0, 'Residual high', (ev.counts.residual.High || 0) ? 'warning' : ''),
        tile(ev.openRisks, 'Open risks'),
        tile(Object.values(ev.annex).filter((x) => x.level !== 'ok').length, 'Annex I open', Object.values(ev.annex).some((x) => x.level === 'blocker') ? 'blocker' : ''),
        tile(ev.userInfoOpen, 'User info open'),
        tile(ev.blockers, 'Blocking findings', ev.blockers ? 'blocker' : 'ok'),
        tile(ev.warnings, 'Warnings', ev.warnings ? 'warning' : 'ok')),
      h('div', { class: `readiness ${ev.blockers ? 'blocker' : 'ok'}` }, ev.blockers
        ? `Not ready: ${ev.blockers} blocking finding(s) must be resolved before the assessment can support placing the product on the market.`
        : 'No blocking findings. Review the warnings, then approve and freeze the version for the technical documentation.'),
      groups.length ? h('div', { class: 'finding-groups' }, groups.map(([s, f]) => h('details', { open: f.some((x) => x.level === 'blocker') },
        h('summary', {}, h('a', { href: `#/p/${ctx.pid}/a/${s.id}` }, label(s.id)), ' ', f.filter((x) => x.level === 'blocker').length ? badge('blocker', f.filter((x) => x.level === 'blocker').length) : null, ' ', badge('warning', f.filter((x) => x.level === 'warning').length)),
        h('ul', { class: 'findings' }, f.map((x) => h('li', { class: x.level }, badge(x.level, x.level), ' ', x.message)))))) : null);
  });

  return h('div', {},
    section('Status', dash),
    section('Export working draft',
      h('p', { class: 'muted' }, 'Drafts are marked as such. For the technical documentation, freeze a version below and export that.'),
      h('div', { class: 'row small-gap' }, ['pdf', 'xlsx', 'json'].map((f) => h('a', { class: 'btn', href: api.exportUrl(ctx.pid, f), onclick: async (e) => {
        e.preventDefault(); await ctx.flush(); location.href = api.exportUrl(ctx.pid, f);
      } }, `Download ${f.toUpperCase()}`)))),
    !ctx.perms.release ? section('Freeze version', h('p', { class: 'muted' }, 'Freezing is done by an approver or owner of this product.'), h('h3', {}, 'Frozen versions'), snaps) : section('Freeze version for technical documentation',
      h('p', {}, 'Freezing stores an immutable copy of the assessment with a SHA-256 fingerprint. Exports of a frozen version are reproducible and carry the fingerprint, so the document filed in the technical documentation can be verified later.'),
      fields(
        h('div', { class: 'field' }, h('label', {}, 'Version to freeze'), h('div', { class: 'mono big' }, a.meta.version || '—'), h('div', { class: 'help' }, h('a', { href: `#/p/${ctx.pid}/a/review` }, 'Change in Review & approval'))),
        field(note, 'v', { label: 'Note (e.g. release, approval reference)', wide: true })),
      h('button', { class: 'btn primary ro-ok', onclick: async () => {
        if (ctx.ev.blockers && !confirm(`There are ${ctx.ev.blockers} blocking findings. Freeze anyway (e.g. as an interim version)?`)) return;
        await ctx.flush();
        try { const s = await api.freeze(ctx.pid, note.v); toast(`Version ${s.version} frozen.`); loadSnaps(); } catch (e) { toast(e.message, 'error'); }
      } }, 'Freeze this version'),
      h('h3', {}, 'Frozen versions'), snaps),
  );
}

const RENDER = { profile, product, classification, support, standards, architecture, assets, stride, method, risks, annex1, en303645, userinfo, review, summary };
