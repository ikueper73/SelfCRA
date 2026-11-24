// Import of the company's Excel risk-assessment templates (industrial and consumer variants).
import ExcelJS from 'exceljs';
import { newAssessment, normalize, splitRefs } from '../shared/model.js';

function text(v) {
  if (v == null) return '';
  if (typeof v === 'object') {
    if (v instanceof Date) return v.toISOString().slice(0, 10);
    if ('result' in v) return text(v.result);
    if ('formula' in v) return '';
    if (v.richText) return v.richText.map((t) => t.text).join('');
    if ('text' in v) return text(v.text);
    return '';
  }
  return String(v).trim();
}

function rows(ws) {
  const out = [];
  ws.eachRow({ includeEmpty: false }, (row) => {
    const vals = [];
    for (let i = 1; i <= ws.columnCount; i++) vals.push(text(row.getCell(i).value));
    out.push(vals);
  });
  return out;
}

// Data rows following the header row whose first cell equals `first`.
// Section rows (only the first cell filled, e.g. "PART II") are skipped.
function tableAfter(all, first, { until } = {}) {
  const start = all.findIndex((r) => r[0] === first);
  if (start < 0) return { header: [], body: [] };
  const header = all[start];
  const body = [];
  for (const r of all.slice(start + 1)) {
    if (until && until(r)) break;
    if (!r[0] || r.slice(1).filter(Boolean).length < 2) continue;
    body.push(Object.fromEntries(header.map((h, i) => [h, r[i] ?? ''])));
  }
  return { header, body };
}

const pick = (obj, ...keys) => {
  for (const k of keys) {
    const hs = Object.keys(obj);
    const hit = hs.find((h) => h.toLowerCase() === k.toLowerCase()) || hs.find((h) => h.toLowerCase().startsWith(k.toLowerCase()));
    if (hit && obj[hit]) return obj[hit];
  }
  return '';
};

const PRODUCT_MAP = [
  [/^product name/i, 'name'], [/versions in scope/i, 'versions'], [/^manufacturer/i, 'manufacturer'],
  [/^intended purpose/i, 'intendedPurpose'], [/foreseeable use/i, 'foreseeableUse'], [/^users and roles/i, 'users'],
  [/^operating environment/i, 'environment'], [/^essential/i, 'essentialFunctions'], [/^safety-relevant/i, 'safetyFunctions'],
  [/^remote data processing/i, 'rdps'], [/^components out of scope/i, 'outOfScope'], [/^personal data/i, 'personalData'],
];

export async function importTemplateXlsx(buffer) {
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.load(buffer);
  const sheet = (re) => wb.worksheets.find((w) => re.test(w.name));
  const consumer = !!sheet(/EN 303 645/i);
  const a = newAssessment({ markets: [consumer ? 'consumer' : 'professional'] });
  const warnings = [];

  // Product & scope
  const ps = sheet(/^Product & Scope/i);
  if (ps) {
    for (const [label, entry] of rows(ps)) {
      for (const [re, key] of PRODUCT_MAP) if (re.test(label) && !a.product[key]) a.product[key] = entry;
      if (/^Assessment version/i.test(label)) a.meta.version = (entry.match(/v?([\d.]+)/) || [])[1] || a.meta.version;
      if (/^Support period/i.test(label)) {
        a.supportPeriod.rationale = entry;
        const y = entry.match(/(\d+)\s*years?/i); if (y) a.supportPeriod.years = y[1];
      }
      if (/^Security update channel/i.test(label)) a.supportPeriod.updateChannel = entry;
      if (/^Automatic security updates/i.test(label)) a.supportPeriod.autoUpdates = entry;
      if (/^End-of-support/i.test(label)) a.supportPeriod.endOfSupport = entry;
      if (/^Conformity assessment route/i.test(label)) a.classification.route = entry;
      if (/^RED delegated/i.test(label)) a.regulation.red = entry;
      if (/^Machinery/i.test(label)) a.regulation.machinery = entry;
      if (/^Product safety/i.test(label)) a.regulation.productSafety = entry;
      if (/^Customer frameworks/i.test(label)) a.regulation.customerFrameworks = entry;
      if (/^Smart-home ecosystems/i.test(label)) a.regulation.ecosystems = entry;
      if (/^UK PSTI/i.test(label)) a.regulation.psti = entry;
      if (label.includes('?') && /Annex III|Annex IV|Router|toy|virtual assistant|security function/i.test(label) && entry) {
        a.classification.notes += `${label}: ${entry}\n`;
      }
    }
    a.meta.title = a.product.name || 'Imported assessment';
  } else warnings.push('Sheet "Product & Scope" not found.');

  // Zones & conduits (industrial) / architecture & interfaces (consumer)
  const zc = sheet(/^Zones & Conduits/i);
  if (zc) {
    const all = rows(zc);
    a.components = tableAfter(all, 'Zone ID', { until: (r) => r[0] === 'Conduits' || r[0] === 'Conduit ID' }).body.map((r) => ({
      id: r['Zone ID'], name: pick(r, 'Zone name'), description: pick(r, 'Components'), location: pick(r, 'Location'), operatedBy: pick(r, 'Operated by'),
      scope: pick(r, 'CRA scope'), slT: pick(r, 'Target SL'), rationale: pick(r, 'Criticality'), assumptions: pick(r, 'Assumptions'),
    }));
    a.interfaces = tableAfter(all, 'Conduit ID').body.map((r) => ({
      id: r['Conduit ID'], name: pick(r, 'Purpose'), from: pick(r, 'From zone'), to: pick(r, 'To zone'), protocol: pick(r, 'Protocol'),
      exposure: '', protection: pick(r, 'Protection'), defaultState: '', needed: '', remoteAccess: pick(r, 'Remote access'),
      notes: [pick(r, 'Initiated by'), pick(r, 'Notes')].filter(Boolean).join(' · '),
    }));
  }
  const ai = sheet(/^Architecture & Interfaces/i);
  if (ai) {
    const body = tableAfter(rows(ai), 'Interface ID').body;
    const comps = [...new Set(body.map((r) => pick(r, 'Component')).filter(Boolean))];
    a.components = comps.map((name, i) => ({ id: `Z-${i + 1}`, name, description: '', location: '', operatedBy: '', scope: '', slT: '', rationale: '', assumptions: '' }));
    for (const c of a.components) {
      const scopes = [...new Set(body.filter((r) => pick(r, 'Component') === c.name).map((r) => pick(r, 'CRA scope')).filter(Boolean))];
      if (scopes.length === 1) c.scope = scopes[0];
    }
    a.interfaces = body.map((r) => ({
      id: r['Interface ID'], name: pick(r, 'Interface'), from: a.components.find((c) => c.name === pick(r, 'Component'))?.id || '', to: '',
      protocol: pick(r, 'Protocol'), exposure: mapExposure(pick(r, 'Exposure')), protection: pick(r, 'Authentication'),
      defaultState: pick(r, 'Default state'), needed: pick(r, 'Needed'), remoteAccess: '', notes: pick(r, 'Notes'),
    }));
  }

  // Assets
  const as = sheet(/^Assets/i);
  if (as) {
    a.assets = tableAfter(rows(as), 'Asset ID').body.map((r) => ({
      id: r['Asset ID'], name: pick(r, 'Asset'), component: pick(r, 'Zone', 'Component'), type: pick(r, 'Type'), description: pick(r, 'Description'),
      c: pick(r, 'Confidentiality'), i: pick(r, 'Integrity'), a: pick(r, 'Availability'), impact: pick(r, 'Impact'),
    }));
  }

  // Method (labels / criteria and thresholds)
  const me = sheet(/^Method/i);
  if (me) {
    const all = rows(me);
    const li = all.findIndex((r) => r[0] === 'Likelihood');
    const im = all.findIndex((r) => r[0] === 'Impact');
    const th = all.findIndex((r) => r[0] === 'Rating');
    const scale = (from) => {
      const header = all[from + 1];
      const lv = all.slice(from + 2, from + 7).filter((r) => /^[1-5]$/.test(r[0]));
      return { columns: header.slice(2).filter(Boolean), levels: lv.map((r) => ({ level: Number(r[0]), label: r[1], criteria: r.slice(2, 2 + header.slice(2).filter(Boolean).length) })) };
    };
    if (li >= 0 && im >= 0) {
      const L = scale(li), I = scale(im);
      if (L.levels.length === 5 && I.levels.length === 5) {
        Object.assign(a.method, { preset: 'imported', label: 'Imported from template', likelihoodColumns: L.columns, likelihood: L.levels, impactColumns: I.columns, impact: I.levels });
      }
    }
    if (th >= 0) {
      const t = all.slice(th + 1, th + 5).filter((r) => r[0] && /^\d+$/.test(r[1])).map((r) => ({ rating: r[0], min: Number(r[1]), rule: r[2] }));
      if (t.length === 4) a.method.thresholds = t;
    }
  }

  // Risk register
  const rr = sheet(/^Risk Register/i);
  if (rr) {
    a.risks = tableAfter(rows(rr), 'Risk ID').body.filter((r) => pick(r, 'Threat scenario')).map((r) => ({
      id: r['Risk ID'], interfaces: pick(r, 'Zone / Conduit', 'Interface / component'), assets: pick(r, 'Asset ID'),
      scenario: pick(r, 'Threat scenario'), stride: pick(r, 'STRIDE'), actor: pick(r, 'Threat actor'), vector: pick(r, 'Attack vector'),
      consequence: pick(r, 'Consequence'), inherentL: pick(r, 'Inherent L'), inherentI: pick(r, 'Inherent I'), controls: pick(r, 'Controls'),
      annex: splitRefs(pick(r, 'CRA Annex I')), en18031: splitRefs(pick(r, 'EN 18031')), en303645: splitRefs(pick(r, 'EN 303 645')),
      iec62443: pick(r, 'IEC 62443'), evidence: pick(r, 'Verification'), residualL: pick(r, 'Residual L'), residualI: pick(r, 'Residual I'),
      treatment: pick(r, 'Treatment') || 'Mitigate', acceptance: '', owner: pick(r, 'Risk owner'), status: pick(r, 'Status') || 'Open',
      lastReviewed: pick(r, 'Last reviewed'), source: 'xlsx-import',
    }));
  } else warnings.push('Sheet "Risk Register" not found.');

  // Annex I
  const an = sheet(/^Annex I/i);
  if (an) {
    for (const r of tableAfter(rows(an), 'ID').body) {
      if (!a.annexI[r.ID]) continue;
      a.annexI[r.ID] = { applicable: pick(r, 'Applicable'), justification: pick(r, 'Justification'), implementation: pick(r, 'Implementation'), evidence: pick(r, 'Evidence') };
    }
  }
  const en = sheet(/EN 303 645/i);
  if (en) {
    for (const r of tableAfter(rows(en), 'Clause').body) {
      if (!a.en303645[r.Clause]) continue;
      a.en303645[r.Clause] = { applicable: pick(r, 'Applicable'), justification: pick(r, 'Justification'), implementation: pick(r, 'Implementation'), evidence: pick(r, 'Evidence') };
    }
  }
  const ui = sheet(/^User Information/i);
  if (ui) {
    for (const r of tableAfter(rows(ui), 'ID').body) {
      if (!a.userInfo[r.ID]) continue;
      a.userInfo[r.ID] = { where: pick(r, 'Where'), content: pick(r, 'Content'), owner: pick(r, 'Owner'), status: pick(r, 'Status') || 'Open', evidence: pick(r, 'Evidence') };
    }
  }
  const rl = sheet(/^Review Log/i);
  if (rl) {
    const body = tableAfter(rows(rl), 'Version').body.map((r) => ({
      version: r.Version, date: pick(r, 'Date'), author: pick(r, 'Author'), trigger: pick(r, 'Trigger'), summary: pick(r, 'Summary'),
      risks: pick(r, 'Risks'), approvedBy: pick(r, 'Approved by'), approvalDate: pick(r, 'Approval date'),
    }));
    if (body.length) a.reviewLog = body;
  }

  const ex = sheet(/^Examples/i);
  if (ex) warnings.push(`Sheet "${ex.name}" contains reference examples and was not imported.`);
  return { data: normalize(a), warnings };
}

function mapExposure(v) {
  if (/internet/i.test(v)) return 'Internet';
  if (/radio/i.test(v)) return 'Radio range (BLE / Wi-Fi / Zigbee / LTE)';
  if (/lan/i.test(v)) return 'Customer / home LAN';
  if (/physical/i.test(v)) return 'Physical access to device';
  if (/cloud/i.test(v)) return 'Cloud-side only';
  return v;
}
