import ExcelJS from 'exceljs';
import { ANNEX_I, EN303645, CATEGORY_LABELS, CONFORMITY_ROUTES, MARKETS, STRIDE } from '../shared/catalog.js';
import { evaluate, userInfoItems, heatmap, strideTargets } from '../shared/model.js';
import { join } from './common.js';

const HEADER_FILL = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0F6CBD' } };
const RATING_FILL = { Critical: 'FFC50F1F', High: 'FFDA3B01', Medium: 'FFEAA300', Low: 'FF9FD89F' };

function sheet(wb, name, title, subtitle) {
  const ws = wb.addWorksheet(name.slice(0, 31), { views: [{ state: 'frozen', ySplit: 0 }] });
  ws.addRow([title]).font = { bold: true, size: 14, color: { argb: 'FF0F6CBD' } };
  if (subtitle) ws.addRow([subtitle]).font = { italic: true, color: { argb: 'FF555555' } };
  ws.addRow([]);
  return ws;
}

function table(ws, columns, rows, { freeze = true } = {}) {
  const startRow = ws.rowCount + 1;
  const header = ws.addRow(columns.map((c) => c.header));
  header.eachCell((c) => {
    c.fill = HEADER_FILL; c.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    c.alignment = { vertical: 'middle', wrapText: true };
  });
  columns.forEach((c, i) => { ws.getColumn(i + 1).width = Math.max(ws.getColumn(i + 1).width || 0, c.width || 18); });
  for (const r of rows) {
    const row = ws.addRow(columns.map((c) => (typeof c.value === 'function' ? c.value(r) : r[c.key]) ?? ''));
    row.alignment = { vertical: 'top', wrapText: true };
    columns.forEach((c, i) => {
      if (c.rating) {
        const v = row.getCell(i + 1).value;
        if (RATING_FILL[v]) { row.getCell(i + 1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: RATING_FILL[v] } }; if (v === 'Critical' || v === 'High') row.getCell(i + 1).font = { bold: true, color: { argb: 'FFFFFFFF' } }; }
      }
    });
  }
  if (rows.length) ws.autoFilter = { from: { row: startRow, column: 1 }, to: { row: startRow + rows.length, column: columns.length } };
  if (freeze) ws.views = [{ state: 'frozen', ySplit: startRow }];
  return ws;
}

function keyValue(ws, pairs) {
  ws.getColumn(1).width = 45; ws.getColumn(2).width = 90;
  for (const [k, v] of pairs) {
    if (v === null) { const r = ws.addRow([k]); r.font = { bold: true, color: { argb: 'FF0F6CBD' } }; continue; }
    const r = ws.addRow([k, v ?? '']);
    r.getCell(1).font = { bold: true };
    r.alignment = { vertical: 'top', wrapText: true };
  }
}

export async function toXlsx(dc) {
  const a = dc.data;
  const ev = evaluate(a);
  const wb = new ExcelJS.Workbook();
  wb.creator = 'CRA Self Assessment Helper';
  wb.created = new Date(dc.exportedAt);
  wb.title = `Cybersecurity risk assessment – ${a.product.name || a.meta.title}`;

  // Document control
  let ws = sheet(wb, 'Document control', 'Cybersecurity Risk Assessment', 'Regulation (EU) 2024/2847 – Art. 13(2)-(4), Annex VII(3)');
  keyValue(ws, [
    ['Assessment', a.meta.title], ['Product', a.product.name], ['Version', dc.version],
    ['Document state', dc.frozen ? `Frozen version (${dc.frozenAt} by ${dc.frozenBy || 'n/a'})` : 'Working draft – not a frozen version'],
    ['Status', a.meta.status], ['SHA-256 of assessment data', dc.sha256], ['Exported at', dc.exportedAt],
    ['Assessment ID', dc.assessmentId], ['Catalogue version', a.catalogVersion || ''],
    ['Note', 'Requirement texts are paraphrased; the Official Journal text prevails. Not legal advice.'],
  ]);

  // Dashboard
  ws = sheet(wb, 'Dashboard', 'Dashboard', 'Summary for management review and the technical file.');
  table(ws, [{ header: 'Rating', key: 'r', width: 18 }, { header: 'Inherent', key: 'i', width: 12 }, { header: 'Residual', key: 's', width: 12 }],
    a.method.thresholds.map((t) => ({ r: t.rating, i: ev.counts.inherent[t.rating] || 0, s: ev.counts.residual[t.rating] || 0 })), { freeze: false });
  ws.addRow([]);
  keyValue(ws, [
    ['Key indicators', null],
    ['Risks in register', ev.risks.length], ['Open risks (Open / In progress)', ev.openRisks],
    ['Residual Critical (must be zero to release)', ev.counts.residual.Critical || 0],
    ['Annex I requirements not assessed', Object.values(ev.annex).filter((s) => s.status === 'NOT ASSESSED').length],
    ['Annex I gaps', Object.values(ev.annex).filter((s) => s.status.startsWith('GAP')).length],
    ['User-information items not implemented', ev.userInfoOpen],
    ['Blocking findings', ev.blockers], ['Warnings', ev.warnings],
  ]);
  ws.addRow([]);
  ws.addRow(['Residual heat map (rows: likelihood 5→1, columns: impact 1→5)']).font = { bold: true };
  heatmap(ev.risks).forEach((row, i) => ws.addRow([`L${5 - i}`, ...row]));

  // Product & scope
  const p = a.product;
  ws = sheet(wb, 'Product & Scope', '1. Product & scope', 'Art. 13(3): intended purpose, reasonably foreseeable use, operating environment, expected lifetime.');
  keyValue(ws, [
    ['IDENTIFICATION', null], ['Product name', p.name], ['Model / type', p.model], ['Versions in scope (HW / FW / SW / cloud)', p.versions],
    ['Manufacturer', p.manufacturer], ['Product security owner', p.securityOwner],
    ['Target markets', a.profile.markets.map((m) => MARKETS.find((x) => x.id === m)?.label).join('; ')],
    ['PURPOSE & USE', null], ['Intended purpose', p.intendedPurpose], ['Reasonably foreseeable use / misuse', p.foreseeableUse],
    ['Users and roles', p.users], ['Operating environment', p.environment], ['Essential / basic functions', p.essentialFunctions],
    ['Safety-relevant functions', p.safetyFunctions], ['Expected lifetime / period of use', p.expectedLifetime],
    ['SCOPE', null], ['Remote data processing solutions in scope', p.rdps], ['Out of scope (and why)', p.outOfScope],
    ['Personal data processed', p.personalData], ['Third-party components & due diligence (Art. 13(5))', p.thirdParty],
    ['Photos / drawings of hardware (Annex VII(1)(c))', p.hardwareDocs],
  ]);

  // Classification & support
  ws = sheet(wb, 'Classification & Support', '2. CRA classification & support period', 'Art. 7, 8, 13(8), 13(19), 32; Annex III / IV; Annex VII(4).');
  keyValue(ws, [
    ['CLASSIFICATION', null],
    ['Matching Annex III / IV categories', ev.classification.hits.map((h) => `${CATEGORY_LABELS[h.category]}: ${h.label}`).join('\n') || 'None'],
    ['Resulting category', CATEGORY_LABELS[ev.classification.category]],
    ['Harmonised standards / EUCC applied in full?', a.classification.standardsInFull],
    ['Conformity assessment route (guidance)', CONFORMITY_ROUTES[ev.classification.category]],
    ['Chosen route', a.classification.route], ['Reasoning / notes', a.classification.notes],
    ['Categories reviewed', a.classification.reviewed ? 'Yes' : 'No'],
    ['SUPPORT PERIOD', null], ['Support period (years)', a.supportPeriod.years], ['End date (month/year)', a.supportPeriod.endDate],
    ['Information considered (Annex VII(4))', a.supportPeriod.rationale], ['Security update channel', a.supportPeriod.updateChannel],
    ['Automatic security updates', a.supportPeriod.autoUpdates], ['End-of-support behaviour', a.supportPeriod.endOfSupport],
  ]);

  // Regulation & standards
  ws = sheet(wb, 'Standards', '3. Related regulation & standards', 'Art. 13(4), Annex VII(5).');
  const rg = a.regulation;
  keyValue(ws, [
    ['RED delegated act (EN 18031)', rg.red], ['Machinery Regulation (EU) 2023/1230', rg.machinery], ['Product safety (LVD, GPSR, …)', rg.productSafety],
    ['NIS2 / customer sector context', rg.nis2], ['Customer frameworks', rg.customerFrameworks], ['Ecosystems / certification schemes', rg.ecosystems],
    ['UK PSTI', rg.psti], ['Other', rg.other],
  ]);
  ws.addRow([]);
  table(ws, [
    { header: 'Standard / specification', key: 'standard', width: 40 }, { header: 'Application', key: 'application', width: 16 },
    { header: 'Parts applied / notes', key: 'notes', width: 70 },
  ], a.standardsApplied, { freeze: false });

  // Architecture
  ws = sheet(wb, 'Architecture', '4. Architecture – components / zones and interfaces / conduits', 'Annex VII(2)(a); Annex I Part I(2)(j) attack surface.');
  table(ws, [
    { header: 'ID', key: 'id', width: 8 }, { header: 'Component / zone', key: 'name', width: 24 }, { header: 'Description', key: 'description', width: 40 },
    { header: 'Location', key: 'location', width: 16 }, { header: 'Operated by', key: 'operatedBy', width: 14 }, { header: 'CRA scope', key: 'scope', width: 24 },
    { header: 'SL-T', key: 'slT', width: 8 }, { header: 'Criticality rationale', key: 'rationale', width: 34 }, { header: 'Assumptions', key: 'assumptions', width: 34 },
  ], a.components, { freeze: false });
  ws.addRow([]);
  table(ws, [
    { header: 'ID', key: 'id', width: 8 }, { header: 'Interface / conduit', key: 'name', width: 24 }, { header: 'From', key: 'from', width: 10 },
    { header: 'To', key: 'to', width: 10 }, { header: 'Protocol / port', key: 'protocol', width: 22 }, { header: 'Exposure', key: 'exposure', width: 20 },
    { header: 'Authentication / protection', key: 'protection', width: 32 }, { header: 'Default state', key: 'defaultState', width: 14 },
    { header: 'Needed for intended function', key: 'needed', width: 12 }, { header: 'Remote access path', key: 'remoteAccess', width: 10 },
    { header: 'Notes', key: 'notes', width: 30 },
  ], a.interfaces, { freeze: false });

  // Assets
  ws = sheet(wb, 'Assets', '5. Assets', 'What must be protected, with confidentiality / integrity / availability needs.');
  table(ws, [
    { header: 'ID', key: 'id', width: 8 }, { header: 'Asset', key: 'name', width: 30 }, { header: 'Component', key: 'component', width: 14 },
    { header: 'Type', key: 'type', width: 22 }, { header: 'Description', key: 'description', width: 40 }, { header: 'C', key: 'c', width: 9 },
    { header: 'I', key: 'i', width: 9 }, { header: 'A', key: 'a', width: 9 }, { header: 'Impact if compromised', key: 'impact', width: 40 },
  ], a.assets);

  // STRIDE
  ws = sheet(wb, 'STRIDE Matrix', 'Threat identification (STRIDE)', 'Per element and category: covering risk IDs, or N/A with justification.');
  const cellText = (c) => (c.status === 'covered' ? c.risks.join(', ') : c.status === 'open' ? 'OPEN' : `N/A: ${c.justification || 'MISSING JUSTIFICATION'}`);
  table(ws, [
    { header: 'Element', key: 'id', width: 10 }, { header: 'Name', key: 'name', width: 28 }, { header: 'Kind', key: 'kind', width: 12 },
    ...STRIDE.map((x) => ({ header: `${x.letter} – ${x.property}`, value: (t) => cellText(ev.stride[t.id][x.letter]), width: 24 })),
  ], strideTargets(a));

  // Method
  const m = a.method;
  ws = sheet(wb, 'Method', '6. Risk method', `Risk score = likelihood × impact (1–25). Preset: ${m.preset}. Approved by: ${m.approvedBy || '—'} ${m.approvedAt || ''}`);
  ws.addRow(['Likelihood']).font = { bold: true };
  table(ws, [{ header: 'Level', key: 'level', width: 8 }, { header: 'Label', key: 'label', width: 16 },
    ...m.likelihoodColumns.map((h, i) => ({ header: h, value: (r) => r.criteria[i], width: 34 }))], m.likelihood, { freeze: false });
  ws.addRow([]); ws.addRow(['Impact']).font = { bold: true };
  table(ws, [{ header: 'Level', key: 'level', width: 8 }, { header: 'Label', key: 'label', width: 16 },
    ...m.impactColumns.map((h, i) => ({ header: h, value: (r) => r.criteria[i], width: 34 }))], m.impact, { freeze: false });
  ws.addRow([]); ws.addRow(['Rating thresholds & acceptance']).font = { bold: true };
  table(ws, [{ header: 'Rating', key: 'rating', rating: true }, { header: 'Min. score', key: 'min' }, { header: 'Acceptance rule', key: 'rule', width: 80 }], m.thresholds, { freeze: false });

  // Risk register
  ws = sheet(wb, 'Risk Register', '7. Threat & risk register (traceability matrix)', 'Inherent = before the listed controls; residual = after.');
  table(ws, [
    { header: 'Risk ID', key: 'id', width: 9 }, { header: 'Interface / zone', key: 'interfaces', width: 12 }, { header: 'Asset ID(s)', key: 'assets', width: 12 },
    { header: 'Threat scenario', key: 'scenario', width: 44 }, { header: 'STRIDE', key: 'stride', width: 16 }, { header: 'Threat actor', key: 'actor', width: 20 },
    { header: 'Attack vector / entry point', key: 'vector', width: 22 }, { header: 'Consequence', key: 'consequence', width: 30 },
    { header: 'Inh. L', key: 'inherentL', width: 6 }, { header: 'Inh. I', key: 'inherentI', width: 6 }, { header: 'Inh. score', key: 'inherentScore', width: 7 },
    { header: 'Inh. rating', key: 'inherentRating', width: 10, rating: true }, { header: 'Controls / mitigations', key: 'controls', width: 50 },
    { header: 'CRA Annex I', value: (r) => join(r.annex), width: 16 }, { header: 'EN 18031', value: (r) => join(r.en18031), width: 12 },
    ...(a.profile.standards.en303645 ? [{ header: 'EN 303 645', value: (r) => join(r.en303645), width: 12 }] : []),
    ...(a.profile.standards.iec62443 ? [{ header: 'IEC 62443', key: 'iec62443', width: 18 }] : []),
    { header: 'Verification evidence', key: 'evidence', width: 26 },
    { header: 'Res. L', key: 'residualL', width: 6 }, { header: 'Res. I', key: 'residualI', width: 6 }, { header: 'Res. score', key: 'residualScore', width: 7 },
    { header: 'Res. rating', key: 'residualRating', width: 10, rating: true }, { header: 'Treatment', key: 'treatment', width: 11 },
    { header: 'Acceptance justification', key: 'acceptance', width: 26 }, { header: 'Risk owner', key: 'owner', width: 14 },
    { header: 'Status', key: 'status', width: 12 }, { header: 'Last reviewed', key: 'lastReviewed', width: 12 },
  ], ev.risks);

  // Annex I
  ws = sheet(wb, 'Annex I Applicability', '8. CRA Annex I – applicability & coverage', 'Art. 13(3)-(4): applicability, justification if not applicable, implementation.');
  table(ws, [
    { header: 'ID', key: 'id', width: 8 }, { header: 'CRA ref', key: 'ref', width: 18 }, { header: 'Requirement (paraphrased)', key: 'text', width: 60 },
    { header: 'Applicable?', value: (r) => a.annexI[r.id].applicable, width: 11 },
    { header: 'Justification (if No)', value: (r) => a.annexI[r.id].justification, width: 34 },
    { header: 'Linked risks', value: (r) => ev.annex[r.id].linked.join(', '), width: 16 },
    { header: 'Coverage check', value: (r) => ev.annex[r.id].status, width: 26 },
    { header: 'Implementation summary', value: (r) => a.annexI[r.id].implementation, width: 50 },
    { header: 'Evidence / document ref', value: (r) => a.annexI[r.id].evidence, width: 28 },
    { header: 'Suggested EN 18031', value: (r) => join(r.en18031), width: 16 },
    ...(a.profile.standards.en303645 ? [{ header: 'Suggested EN 303 645', value: (r) => join(r.en303645), width: 14 }] : []),
    ...(a.profile.standards.iec62443 ? [{ header: 'Suggested IEC 62443', key: 'iec62443', width: 22 }] : []),
  ], ANNEX_I);

  if (a.profile.standards.en303645) {
    ws = sheet(wb, 'EN 303 645', '9. ETSI EN 303 645 – clause checklist', 'Clause-level summary (paraphrased).');
    table(ws, [
      { header: 'Clause', key: 'id', width: 8 }, { header: 'Topic', key: 'topic', width: 30 }, { header: 'Intent (paraphrased)', key: 'intent', width: 50 },
      { header: 'Related Annex I', value: (r) => join(r.annex), width: 18 },
      { header: 'Applicable?', value: (r) => a.en303645[r.id].applicable, width: 11 },
      { header: 'Justification', value: (r) => a.en303645[r.id].justification, width: 30 },
      { header: 'Implementation', value: (r) => a.en303645[r.id].implementation, width: 40 },
      { header: 'Evidence', value: (r) => a.en303645[r.id].evidence, width: 26 },
      { header: 'Coverage check', value: (r) => ev.en303645[r.id].status, width: 24 },
    ], EN303645);
  }

  ws = sheet(wb, 'User Information', '10. User information', 'Annex II; Art. 13(18)-(19).');
  table(ws, [
    { header: 'ID', key: 'id', width: 8 }, { header: 'Requirement (paraphrased)', key: 'text', width: 60 }, { header: 'CRA ref', key: 'ref', width: 14 },
    { header: 'Where provided', value: (r) => a.userInfo[r.id].where, width: 22 }, { header: 'Content / link', value: (r) => a.userInfo[r.id].content, width: 44 },
    { header: 'Owner', value: (r) => a.userInfo[r.id].owner, width: 16 }, { header: 'Status', value: (r) => a.userInfo[r.id].status, width: 14 },
    { header: 'Evidence', value: (r) => a.userInfo[r.id].evidence, width: 24 },
  ], userInfoItems(a));

  ws = sheet(wb, 'Review Log', '11. Review log', 'Art. 13(3): documented and updated during the support period.');
  table(ws, [
    { header: 'Version', key: 'version', width: 9 }, { header: 'Date', key: 'date', width: 12 }, { header: 'Author', key: 'author', width: 18 },
    { header: 'Trigger', key: 'trigger', width: 30 }, { header: 'Summary of changes', key: 'summary', width: 50 }, { header: 'Risks added / changed', key: 'risks', width: 20 },
    { header: 'Approved by', key: 'approvedBy', width: 18 }, { header: 'Approval date', key: 'approvalDate', width: 13 },
  ], a.reviewLog);

  ws = sheet(wb, 'Findings', 'Completeness findings at export time', 'Generated by the tool’s consistency checks.');
  table(ws, [{ header: 'Level', key: 'level', width: 10 }, { header: 'Step', key: 'step', width: 16 }, { header: 'Finding', key: 'message', width: 100 }], ev.findings);

  return Buffer.from(await wb.xlsx.writeBuffer());
}
