// Assessment data model, scoring and completeness checks.
// Pure functions only: imported by the browser UI and by the server (exports).
import { ANNEX_I, USER_INFO, EN303645, METHOD_PRESETS, CLASSIFICATION, CATALOG_VERSION, STRIDE } from './catalog.js';

export const SCHEMA_VERSION = 1;

export const STEPS = [
  { id: 'profile', label: 'Profile & scope', cra: 'Art. 13(3)' },
  { id: 'product', label: 'Product description', cra: 'Art. 13(3), Annex VII(1)' },
  { id: 'classification', label: 'CRA classification', cra: 'Art. 7, 8, 32; Annex III/IV' },
  { id: 'support', label: 'Support period', cra: 'Art. 13(8), (19); Annex VII(4)' },
  { id: 'standards', label: 'Related regulation & standards', cra: 'Art. 13(4), Annex VII(5)' },
  { id: 'architecture', label: 'Architecture & interfaces', cra: 'Annex VII(2)(a), Annex I(2)(j)' },
  { id: 'assets', label: 'Assets', cra: 'Art. 13(3)' },
  { id: 'stride', label: 'Threat identification (STRIDE)', cra: 'Art. 13(2)-(3)' },
  { id: 'method', label: 'Risk method', cra: 'Art. 13(2)' },
  { id: 'risks', label: 'Risk register', cra: 'Art. 13(2)-(3)' },
  { id: 'annex1', label: 'Annex I applicability', cra: 'Art. 13(3)-(4), Annex I' },
  { id: 'en303645', label: 'EN 303 645 checklist', cra: 'ETSI EN 303 645', when: (a) => a.profile.standards.en303645 },
  { id: 'userinfo', label: 'User information', cra: 'Art. 13(18)-(19), Annex II' },
  { id: 'review', label: 'Review & approval', cra: 'Art. 13(3), Art. 31(2)' },
  { id: 'summary', label: 'Summary & export', cra: 'Annex VII(3)' },
];

export function visibleSteps(a) {
  return STEPS.filter((s) => !s.when || s.when(a));
}

const today = () => new Date().toISOString().slice(0, 10);

export function presetFor(markets) {
  const c = markets.includes('consumer');
  const p = markets.includes('professional');
  return c && p ? 'combined' : c ? 'consumer' : 'professional';
}

export function newAssessment({ title = 'New assessment', markets = ['professional'] } = {}) {
  const preset = presetFor(markets);
  return normalize({
    schema: SCHEMA_VERSION,
    catalogVersion: CATALOG_VERSION,
    meta: { title, status: 'draft', version: '0.1' },
    profile: {
      markets,
      standards: {
        en18031: true,
        en303645: markets.includes('consumer'),
        iec62443: markets.includes('professional'),
      },
      ukMarket: false,
      tailorMade: false,
    },
    method: structuredClone({ preset, ...METHOD_PRESETS[preset], approvedBy: '', approvedAt: '' }),
    reviewLog: [{ version: '0.1', date: today(), author: '', trigger: 'Initial assessment', summary: 'Assessment created.', risks: '', approvedBy: '', approvalDate: '' }],
  });
}

// Fill in any missing structure so older or imported documents keep working.
export function normalize(a) {
  a = a || {};
  a.schema = a.schema || SCHEMA_VERSION;
  a.meta = { title: 'Untitled', status: 'draft', version: '0.1', ...(a.meta || {}) };
  a.profile = { markets: ['professional'], standards: {}, ukMarket: false, tailorMade: false, ...(a.profile || {}) };
  a.profile.standards = { en18031: true, en303645: false, iec62443: false, ...a.profile.standards };
  a.product = {
    name: '', model: '', versions: '', manufacturer: '', securityOwner: '', intendedPurpose: '', foreseeableUse: '',
    users: '', environment: '', essentialFunctions: '', safetyFunctions: '', expectedLifetime: '', rdps: '',
    outOfScope: '', personalData: '', thirdParty: '', hardwareDocs: '',
    ...(a.product || {}),
  };
  a.classification = { selected: {}, notes: '', reviewed: false, standardsInFull: '', route: '', ...(a.classification || {}) };
  a.supportPeriod = { years: '', endDate: '', rationale: '', updateChannel: '', autoUpdates: '', endOfSupport: '', ...(a.supportPeriod || {}) };
  a.regulation = { red: '', machinery: '', productSafety: '', nis2: '', customerFrameworks: '', ecosystems: '', psti: '', other: '', ...(a.regulation || {}) };
  a.standardsApplied = a.standardsApplied || [];
  a.components = a.components || [];
  a.interfaces = a.interfaces || [];
  a.assets = a.assets || [];
  if (!a.method || !a.method.likelihood) {
    const preset = presetFor(a.profile.markets);
    a.method = structuredClone({ preset, ...METHOD_PRESETS[preset], approvedBy: '', approvedAt: '' });
  }
  a.risks = a.risks || [];
  a.stride = a.stride && typeof a.stride === 'object' && !Array.isArray(a.stride) ? a.stride : {};
  a.diagram = a.diagram && typeof a.diagram === 'object' && !Array.isArray(a.diagram) ? a.diagram : {};
  a.diagram.positions = a.diagram.positions && typeof a.diagram.positions === 'object' ? a.diagram.positions : {};
  a.annexI = a.annexI || {};
  for (const r of ANNEX_I) a.annexI[r.id] = { applicable: '', justification: '', implementation: '', evidence: '', ...(a.annexI[r.id] || {}) };
  a.en303645 = a.en303645 || {};
  for (const c of EN303645) a.en303645[c.id] = { applicable: '', justification: '', implementation: '', evidence: '', ...(a.en303645[c.id] || {}) };
  a.userInfo = a.userInfo || {};
  for (const u of USER_INFO) a.userInfo[u.id] = { where: '', content: '', owner: '', status: 'Open', evidence: '', ...(a.userInfo[u.id] || {}) };
  a.reviewLog = a.reviewLog || [];
  return a;
}

export function newRisk(a, template) {
  const r = {
    id: nextId('R-', a.risks), interfaces: '', assets: '', scenario: '', stride: '', actor: '', vector: '', consequence: '',
    inherentL: '', inherentI: '', controls: '', annex: [], en18031: [], en303645: [], iec62443: '', evidence: '',
    residualL: '', residualI: '', treatment: 'Mitigate', acceptance: '', owner: '', status: 'Open', lastReviewed: today(), source: '',
  };
  if (template) {
    Object.assign(r, {
      scenario: template.scenario, stride: template.stride, vector: template.vector, consequence: template.consequence,
      controls: template.controls, annex: [...template.annex], en18031: [...template.en18031], en303645: [...template.en303645],
      iec62443: template.iec62443, source: template.id,
    });
  }
  return r;
}

export function nextId(prefix, list, width = prefix === 'R-' ? 3 : 2) {
  let max = 0;
  for (const it of list) {
    const m = String(it.id || '').match(/(\d+)$/);
    if (String(it.id || '').startsWith(prefix) && m) max = Math.max(max, Number(m[1]));
  }
  return prefix + String(max + 1).padStart(width, '0');
}

// ---------------------------------------------------------------- scoring
const num = (v) => {
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 5 ? n : null;
};

export function rate(score, thresholds) {
  if (score == null) return '';
  const sorted = [...thresholds].sort((x, y) => y.min - x.min);
  for (const t of sorted) if (score >= Number(t.min)) return t.rating;
  return sorted.at(-1)?.rating || '';
}

export function scoreRisk(r, method) {
  const iL = num(r.inherentL), iI = num(r.inherentI), rL = num(r.residualL), rI = num(r.residualI);
  const inherentScore = iL && iI ? iL * iI : null;
  const residualScore = rL && rI ? rL * rI : null;
  return {
    inherentScore, inherentRating: rate(inherentScore, method.thresholds),
    residualScore, residualRating: rate(residualScore, method.thresholds),
  };
}

export const splitRefs = (v) => (Array.isArray(v) ? v : String(v || '').split(/[,;/]+/)).map((s) => String(s).trim()).filter(Boolean);

// ---------------------------------------------------------------- STRIDE coverage
export const strideLetter = (v) => {
  const m = /^\s*([STRIDE])\b/.exec(String(v || ''));
  return m ? m[1] : '';
};

// Elements swept with STRIDE: in-scope components / zones and all interfaces / conduits.
export function strideTargets(a) {
  const comps = a.components.filter((c) => !/^Out of scope/i.test(c.scope || '')).map((c) => ({ id: c.id, name: c.name, kind: 'component', detail: c.scope || '' }));
  const ifs = a.interfaces.map((i) => ({ id: i.id, name: i.name, kind: 'interface', detail: [i.protocol, i.exposure].filter(Boolean).join(' · ') }));
  return [...comps, ...ifs].filter((t) => t.id);
}

export function strideCell(a, targetId, letter) {
  return { na: false, justification: '', refs: [], ...((a.stride[targetId] || {})[letter] || {}) };
}

// status per target and category: covered | na | na-missing | open
export function strideStatus(a, risks = a.risks) {
  const out = {};
  for (const t of strideTargets(a)) {
    out[t.id] = {};
    for (const s of STRIDE) {
      const cell = strideCell(a, t.id, s.letter);
      const derived = risks.filter((r) => strideLetter(r.stride) === s.letter && splitRefs(r.interfaces).includes(t.id)).map((r) => r.id);
      const linked = splitRefs(cell.refs).filter((id) => risks.some((r) => r.id === id));
      const ids = [...new Set([...derived, ...linked])];
      let status = 'open';
      if (ids.length) status = 'covered';
      else if (cell.na) status = String(cell.justification || '').trim() ? 'na' : 'na-missing';
      out[t.id][s.letter] = { status, risks: ids, justification: cell.justification };
    }
  }
  return out;
}

// ---------------------------------------------------------------- derived state & findings
export function classificationResult(a) {
  const order = ['default', 'important1', 'important2', 'critical'];
  let cat = 'default';
  const hits = [];
  for (const group of CLASSIFICATION) {
    group.items.forEach((label, i) => {
      if (a.classification.selected[`${group.category}:${i}`]) {
        hits.push({ category: group.category, label });
        if (order.indexOf(group.category) > order.indexOf(cat)) cat = group.category;
      }
    });
  }
  return { category: cat, hits };
}

export function annexStatus(a, risks) {
  const out = {};
  for (const req of ANNEX_I) {
    const e = a.annexI[req.id];
    const linked = risks.filter((r) => splitRefs(r.annex).includes(req.id)).map((r) => r.id);
    let status, level;
    if (e.applicable === 'No') {
      [status, level] = e.justification.trim() ? ['Not applicable – justified', 'ok'] : ['MISSING JUSTIFICATION', 'blocker'];
    } else if (!e.applicable) {
      [status, level] = ['NOT ASSESSED', 'blocker'];
    } else if (linked.length) {
      [status, level] = [`Covered by ${linked.length} risk(s)`, 'ok'];
    } else if (e.implementation.trim()) {
      [status, level] = ['Implemented (no linked risk)', 'ok'];
    } else {
      [status, level] = ['GAP – no linked risk or implementation', 'warning'];
    }
    out[req.id] = { status, level, linked };
  }
  return out;
}

export function en303645Status(a, risks) {
  const out = {};
  for (const c of EN303645) {
    const e = a.en303645[c.id];
    const linked = risks.filter((r) => splitRefs(r.en303645).some((x) => x === c.id || x.startsWith(c.id + '-') || (c.id === '6' && /^6(\.|-|$)/.test(x)))).map((r) => r.id);
    let status, level;
    if (e.applicable === 'No') [status, level] = e.justification.trim() ? ['Not applicable – justified', 'ok'] : ['MISSING JUSTIFICATION', 'blocker'];
    else if (!e.applicable) [status, level] = ['NOT ASSESSED', 'warning'];
    else if (linked.length) [status, level] = [`Covered by ${linked.length} risk(s)`, 'ok'];
    else if (e.implementation.trim()) [status, level] = ['Implemented (no linked risk)', 'ok'];
    else [status, level] = ['GAP', 'warning'];
    out[c.id] = { status, level, linked };
  }
  return out;
}

export function userInfoItems(a) {
  return USER_INFO.filter((u) => !u.consumerOnly || (a.profile.markets.includes('consumer') && a.profile.ukMarket));
}

const blank = (v) => !String(v ?? '').trim();

export function evaluate(a) {
  const findings = [];
  const add = (level, step, message) => findings.push({ level, step, message });

  const risks = a.risks.map((r) => ({ ...r, ...scoreRisk(r, a.method) }));
  const counts = { inherent: {}, residual: {} };
  for (const t of a.method.thresholds) { counts.inherent[t.rating] = 0; counts.residual[t.rating] = 0; }
  for (const r of risks) {
    if (r.inherentRating) counts.inherent[r.inherentRating] = (counts.inherent[r.inherentRating] || 0) + 1;
    if (r.residualRating) counts.residual[r.residualRating] = (counts.residual[r.residualRating] || 0) + 1;
  }

  // profile
  if (!a.profile.markets.length) add('blocker', 'profile', 'Select at least one target market (consumer and/or commercial).');

  // product
  const p = a.product;
  const required = { name: 'Product name', versions: 'Versions in scope', intendedPurpose: 'Intended purpose', foreseeableUse: 'Reasonably foreseeable use / misuse', environment: 'Operating environment', essentialFunctions: 'Essential functions', expectedLifetime: 'Expected lifetime / period of use' };
  for (const [k, label] of Object.entries(required)) if (blank(p[k])) add('blocker', 'product', `${label} is missing (Art. 13(3)).`);
  if (blank(p.thirdParty)) add('warning', 'product', 'Describe how third-party / open-source components are selected and checked (Art. 13(5) due diligence).');

  // classification
  const cls = classificationResult(a);
  if (!a.classification.reviewed) add('warning', 'classification', 'Confirm that the Annex III / IV categories have been reviewed.');
  if (cls.category === 'important1' && a.classification.standardsInFull !== 'Yes') add('info', 'classification', 'Important Class I without harmonised standards applied in full requires a notified body (Module B+C or H).');
  if (cls.category === 'important2' || cls.category === 'critical') add('info', 'classification', 'Third-party conformity assessment required for this category.');

  // support period
  const sp = a.supportPeriod;
  const years = Number(sp.years);
  if (blank(sp.years) || !(years > 0)) add('blocker', 'support', 'Support period (years) is missing.');
  else if (years < 5 && blank(sp.rationale)) add('blocker', 'support', 'Support period below 5 years requires a justification that the expected period of use is shorter (Art. 13(8)).');
  if (blank(sp.endDate)) add('warning', 'support', 'End date of the support period (month/year) is missing (Art. 13(19)).');
  if (blank(sp.rationale)) add('warning', 'support', 'Record the information considered when setting the support period (Annex VII(4)).');

  // standards
  if (!a.standardsApplied.length) add('warning', 'standards', 'List the harmonised standards / specifications applied, or describe the solutions used (Annex VII(5)).');

  // architecture
  if (!a.components.length) add('warning', 'architecture', 'No components / zones described.');
  if (!a.interfaces.length) add('warning', 'architecture', 'No interfaces / conduits listed – the attack surface is undocumented.');
  for (const i of a.interfaces) {
    if (i.defaultState === 'Enabled' && i.needed === 'No') add('warning', 'architecture', `${i.id}: enabled by default but not needed for the intended function (Annex I(2)(b), (j)).`);
    if (['Internet', 'Radio range (BLE / Wi-Fi / Zigbee / LTE)', 'Customer / home LAN'].includes(i.exposure) && blank(i.protection)) add('warning', 'architecture', `${i.id}: exposed interface without described protection.`);
  }

  // assets
  if (!a.assets.length) add('warning', 'assets', 'No assets listed.');
  const assetIds = new Set(a.assets.map((x) => x.id));
  const ifaceIds = new Set([...a.interfaces.map((x) => x.id), ...a.components.map((x) => x.id)]);
  const referencedAssets = new Set(risks.flatMap((r) => splitRefs(r.assets)));
  for (const as of a.assets) if (!referencedAssets.has(as.id)) add('warning', 'assets', `${as.id} (${as.name || 'unnamed'}) is not referenced by any risk.`);

  // STRIDE sweep
  const stride = strideStatus(a, risks);
  for (const t of strideTargets(a)) {
    const st = stride[t.id];
    const open = STRIDE.filter((s) => st[s.letter].status === 'open').map((s) => s.letter);
    const naMissing = STRIDE.filter((s) => st[s.letter].status === 'na-missing').map((s) => s.letter);
    if (open.length) add('warning', 'stride', `${t.id} (${t.name || t.kind}): no threat decision for ${open.join(', ')}.`);
    if (naMissing.length) add('warning', 'stride', `${t.id}: "not applicable" without justification for ${naMissing.join(', ')}.`);
  }

  // method
  if (blank(a.method.approvedBy)) add('warning', 'method', 'Risk method (scales and acceptance thresholds) not yet approved.');

  // risks
  if (!risks.length) add('blocker', 'risks', 'Risk register is empty.');
  for (const r of risks) {
    if (blank(r.scenario)) add('warning', 'risks', `${r.id}: threat scenario is empty.`);
    if (r.inherentScore == null) add('warning', 'risks', `${r.id}: inherent likelihood / impact not rated.`);
    if (r.residualScore == null) add('warning', 'risks', `${r.id}: residual likelihood / impact not rated.`);
    if (r.residualRating === 'Critical') add('blocker', 'risks', `${r.id}: residual risk is Critical – not acceptable for placing on the market.`);
    if (r.residualRating === 'High' && r.treatment !== 'Accept') add('warning', 'risks', `${r.id}: residual High without documented acceptance.`);
    if (r.treatment === 'Accept' && blank(r.acceptance)) add('warning', 'risks', `${r.id}: accepted risk without acceptance justification / approver.`);
    if (!splitRefs(r.annex).length) add('warning', 'risks', `${r.id}: no Annex I requirement linked.`);
    for (const id of splitRefs(r.assets)) if (!assetIds.has(id)) add('warning', 'risks', `${r.id}: unknown asset ID "${id}".`);
    for (const id of splitRefs(r.interfaces)) if (/^[A-Z]-\d+$/.test(id) && !ifaceIds.has(id)) add('warning', 'risks', `${r.id}: unknown interface / zone ID "${id}".`);
    if (blank(r.evidence) && ['Implemented', 'Verified'].includes(r.status)) add('warning', 'risks', `${r.id}: status ${r.status} without verification evidence.`);
  }

  // Annex I
  const annex = annexStatus(a, risks);
  for (const req of ANNEX_I) {
    const s = annex[req.id];
    const e = a.annexI[req.id];
    if (s.level !== 'ok') add(s.level, 'annex1', `${req.id}: ${s.status}.`);
    if (req.part === 'II' && e.applicable === 'No') add('warning', 'annex1', `${req.id}: Part II vulnerability-handling requirements apply to every manufacturer – check the justification.`);
    if (e.applicable === 'Yes' && blank(e.implementation)) add('warning', 'annex1', `${req.id}: implementation summary missing.`);
    if (e.applicable === 'Yes' && blank(e.evidence)) add('info', 'annex1', `${req.id}: no evidence / document reference.`);
  }

  // EN 303 645
  let en = null;
  if (a.profile.standards.en303645) {
    en = en303645Status(a, risks);
    for (const c of EN303645) if (en[c.id].level !== 'ok') add(en[c.id].level, 'en303645', `Clause ${c.id}: ${en[c.id].status}.`);
  }

  // user information
  const ui = userInfoItems(a);
  for (const u of ui) {
    const e = a.userInfo[u.id];
    if (!['Implemented', 'Verified', 'Not applicable'].includes(e.status)) add('warning', 'userinfo', `${u.id} (${u.ref}) not yet implemented.`);
    if (e.status === 'Not applicable' && blank(e.content) && !u.optional && u.id !== 'U-06' && u.id !== 'U-14' && u.id !== 'U-15') add('warning', 'userinfo', `${u.id}: marked not applicable without explanation.`);
  }

  // review
  if (!a.reviewLog.length) add('warning', 'review', 'Review log is empty.');
  else if (blank(a.reviewLog.at(-1).approvedBy)) add('info', 'review', `Latest revision ${a.reviewLog.at(-1).version} not yet approved.`);

  const byStep = {};
  for (const s of STEPS) byStep[s.id] = { blocker: 0, warning: 0, info: 0 };
  for (const f of findings) byStep[f.step][f.level]++;

  return {
    risks, counts, annex, en303645: en, stride, classification: cls, findings, byStep,
    blockers: findings.filter((f) => f.level === 'blocker').length,
    warnings: findings.filter((f) => f.level === 'warning').length,
    openRisks: risks.filter((r) => ['Open', 'In progress'].includes(r.status)).length,
    userInfoOpen: ui.filter((u) => !['Implemented', 'Verified', 'Not applicable'].includes(a.userInfo[u.id].status)).length,
  };
}

export function heatmap(risks, which = 'residual') {
  const grid = Array.from({ length: 5 }, () => Array(5).fill(0));
  for (const r of risks) {
    const L = num(r[which + 'L']), I = num(r[which + 'I']);
    if (L && I) grid[5 - L][I - 1]++;
  }
  return grid; // rows: L=5..1, cols: I=1..5
}
