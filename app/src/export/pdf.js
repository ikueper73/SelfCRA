// PDF report for the technical documentation (Annex VII(3)).
import { createRequire } from 'node:module';
import path from 'node:path';
import { ANNEX_I, EN303645, CATEGORY_LABELS, CONFORMITY_ROUTES, MARKETS, STRIDE } from '../shared/catalog.js';
import { evaluate, userInfoItems, heatmap, strideTargets } from '../shared/model.js';
import { join } from './common.js';
import { diagramSvg } from '../shared/diagram.js';

const require = createRequire(import.meta.url);
const pdfmake = require('pdfmake');
const fontDir = path.join(path.dirname(require.resolve('pdfmake/package.json')), 'fonts', 'Roboto');
pdfmake.setFonts({
  Roboto: {
    normal: path.join(fontDir, 'Roboto-Regular.ttf'), bold: path.join(fontDir, 'Roboto-Medium.ttf'),
    italics: path.join(fontDir, 'Roboto-Italic.ttf'), bolditalics: path.join(fontDir, 'Roboto-MediumItalic.ttf'),
  },
});
// No remote downloads; local reads only for the bundled fonts.
pdfmake.setUrlAccessPolicy(() => false);
pdfmake.setLocalAccessPolicy((p) => path.resolve(p).startsWith(fontDir));

export const C = { navy: '#0F6CBD', grey: '#616161', light: '#F5F5F5' };
const RATING = { Critical: '#C50F1F', High: '#DA3B01', Medium: '#EAA300', Low: '#9FD89F' };
const s = (v) => (v == null ? '' : String(v));

// Section counter; toPdf resets it and builds all headings synchronously, so concurrent exports cannot interleave.
let secNo = 0;
const h1 = (text, opts = {}) => ({ text: `${++secNo}. ${text}`, style: 'h1', tocItem: true, ...opts });
const h2 = (text) => ({ text, style: 'h2' });
const para = (text) => ({ text: s(text) || '—', margin: [0, 0, 0, 6] });

export function kv(rows) {
  return {
    table: { widths: [170, '*'], body: rows.map(([k, v]) => [{ text: k, bold: true, color: C.navy }, v && typeof v === 'object' ? v : (s(v) || '—')]) },
    layout: 'lightHorizontalLines', margin: [0, 0, 0, 10],
  };
}

export function grid(headers, rows, widths, { fontSize = 8, ratingCols = [] } = {}) {
  const body = [headers.map((h) => ({ text: h, style: 'th' }))];
  for (const r of rows) {
    body.push(r.map((v, i) => (ratingCols.includes(i) && RATING[v]
      ? { text: v, fillColor: RATING[v], color: v === 'Critical' || v === 'High' ? 'white' : 'black', bold: true }
      : v && typeof v === 'object' ? v : { text: s(v) })));
  }
  if (rows.length === 0) body.push([{ text: 'None recorded.', colSpan: headers.length, italics: true, color: C.grey }, ...Array(headers.length - 1).fill('')]);
  return {
    table: { headerRows: 1, widths: widths || headers.map(() => '*'), body, dontBreakRows: true },
    layout: { fillColor: (row) => (row === 0 ? C.navy : row % 2 === 0 ? C.light : null), hLineColor: '#CCCCCC', vLineColor: '#CCCCCC', hLineWidth: () => 0.5, vLineWidth: () => 0.5 },
    fontSize, margin: [0, 0, 0, 10],
  };
}

const CELL = { covered: '#E6F4E7', na: '#F4F6F9', 'na-missing': '#FFF3DC', open: '#FFF3DC' };
function strideTable(a, ev) {
  const body = [[{ text: 'Element', style: 'th' }, ...STRIDE.map((x) => ({ text: `${x.letter}\n${x.property}`, style: 'th', alignment: 'center' }))]];
  for (const t of strideTargets(a)) {
    body.push([
      { text: [{ text: `${t.id} `, bold: true }, s(t.name), { text: t.detail ? `\n${t.detail}` : '', color: C.grey, fontSize: 7 }] },
      ...STRIDE.map((x) => {
        const c = ev.stride[t.id][x.letter];
        return { text: c.status === 'covered' ? c.risks.join(', ') : c.status === 'open' ? 'OPEN' : 'N/A', alignment: 'center', fillColor: CELL[c.status], bold: c.status !== 'covered' && c.status !== 'na' };
      }),
    ]);
  }
  if (body.length === 1) body.push([{ text: 'No components or interfaces defined.', colSpan: 7, italics: true }, '', '', '', '', '', '']);
  return { table: { headerRows: 1, widths: [170, '*', '*', '*', '*', '*', '*'], body, dontBreakRows: true },
    layout: { fillColor: (row) => (row === 0 ? C.navy : null), hLineColor: '#CCCCCC', vLineColor: '#CCCCCC', hLineWidth: () => 0.5, vLineWidth: () => 0.5 }, fontSize: 8, margin: [0, 0, 0, 10] };
}

export async function toPdf(dc) {
  secNo = 0;
  const a = dc.data;
  const ev = evaluate(a);
  const p = a.product;
  const st = a.profile.standards;
  const landscape = { pageBreak: 'before', pageOrientation: 'landscape' };
  const portrait = { pageBreak: 'before', pageOrientation: 'portrait' };

  const content = [
    // Cover
    { text: 'Cybersecurity Risk Assessment', style: 'title', margin: [0, 120, 0, 8] },
    { text: s(p.name) || a.meta.title, fontSize: 18, color: C.navy, margin: [0, 0, 0, 4] },
    { text: 'Regulation (EU) 2024/2847 (Cyber Resilience Act) – Art. 13(2)-(4), Annex VII(3)', color: C.grey, margin: [0, 0, 0, 40] },
    kv([
      ['Version', dc.version], ['Document state', dc.frozen ? `Frozen version – ${dc.frozenAt} by ${dc.frozenBy || 'n/a'}` : 'WORKING DRAFT – not a frozen version'],
      ['Status', a.meta.status], ['Manufacturer', p.manufacturer], ['Product security owner', p.securityOwner],
      ['Versions in scope', p.versions], ['Exported', dc.exportedAt], ['Assessment ID', dc.assessmentId],
      ['SHA-256 (assessment data)', { text: dc.sha256, fontSize: 7 }], ['Frozen-version note', dc.note],
    ]),
    { text: 'Requirement texts are paraphrased; the text published in the Official Journal prevails. This document is the manufacturer’s cybersecurity risk assessment and is part of the technical documentation under Art. 31.', fontSize: 8, color: C.grey, margin: [0, 20, 0, 0] },

    { toc: { title: { text: 'Contents', style: 'h1' } }, pageBreak: 'before' },

    // Summary
    h1('Summary', { pageBreak: 'before' }),
    kv([
      ['Resulting CRA category', CATEGORY_LABELS[ev.classification.category]],
      ['Risks in register', ev.risks.length], ['Open risks', ev.openRisks],
      ['Residual Critical', ev.counts.residual.Critical || 0],
      ['Annex I requirements not assessed', Object.values(ev.annex).filter((x) => x.status === 'NOT ASSESSED').length],
      ['Annex I gaps', Object.values(ev.annex).filter((x) => x.status.startsWith('GAP')).length],
      ['Blocking findings / warnings', `${ev.blockers} / ${ev.warnings}`],
    ]),
    grid(['Rating', 'Inherent', 'Residual'], a.method.thresholds.map((t) => [t.rating, ev.counts.inherent[t.rating] || 0, ev.counts.residual[t.rating] || 0]), [100, 60, 60], { fontSize: 9, ratingCols: [0] }),
    h2('Residual risk heat map (likelihood × impact)'),
    grid(['L \\ I', '1', '2', '3', '4', '5'], heatmap(ev.risks).map((row, i) => [`${5 - i}`, ...row.map((n) => (n ? String(n) : ''))]), [40, 40, 40, 40, 40, 40], { fontSize: 9 }),

    // Product
    h1('Product description, intended purpose and foreseeable use', { pageBreak: 'before' }),
    kv([
      ['Product name', p.name], ['Model / type', p.model], ['Versions in scope', p.versions], ['Manufacturer', p.manufacturer],
      ['Target markets', a.profile.markets.map((m) => MARKETS.find((x) => x.id === m)?.label).join('; ')],
      ['Intended purpose', p.intendedPurpose], ['Reasonably foreseeable use / misuse', p.foreseeableUse], ['Users and roles', p.users],
      ['Operating environment', p.environment], ['Essential / basic functions', p.essentialFunctions], ['Safety-relevant functions', p.safetyFunctions],
      ['Expected lifetime / period of use', p.expectedLifetime], ['Remote data processing in scope', p.rdps], ['Out of scope (and why)', p.outOfScope],
      ['Personal data processed', p.personalData], ['Third-party components & due diligence', p.thirdParty], ['Hardware photos / drawings', p.hardwareDocs],
    ]),

    h1('CRA classification and conformity route'),
    kv([
      ['Matching Annex III / IV categories', ev.classification.hits.map((x) => `${CATEGORY_LABELS[x.category]}: ${x.label}`).join('\n') || 'None – default category'],
      ['Resulting category', CATEGORY_LABELS[ev.classification.category]],
      ['Harmonised standards / EUCC applied in full', a.classification.standardsInFull],
      ['Route (guidance)', CONFORMITY_ROUTES[ev.classification.category]], ['Chosen route', a.classification.route], ['Reasoning', a.classification.notes],
    ]),

    h1('Support period'),
    kv([
      ['Support period', a.supportPeriod.years ? `${a.supportPeriod.years} years` : ''], ['End date', a.supportPeriod.endDate],
      ['Information considered (Annex VII(4))', a.supportPeriod.rationale], ['Security update channel', a.supportPeriod.updateChannel],
      ['Automatic security updates', a.supportPeriod.autoUpdates], ['End-of-support behaviour', a.supportPeriod.endOfSupport],
    ]),

    h1('Related regulation and applied standards'),
    kv([
      ['RED delegated act (EN 18031)', a.regulation.red], ['Machinery Regulation', a.regulation.machinery], ['Product safety', a.regulation.productSafety],
      ['NIS2 / sector context', a.regulation.nis2], ['Customer frameworks', a.regulation.customerFrameworks], ['Ecosystems / schemes', a.regulation.ecosystems],
      ['UK PSTI', a.regulation.psti], ['Other', a.regulation.other],
    ]),
    grid(['Standard / specification', 'Application', 'Parts applied / notes'], a.standardsApplied.map((x) => [x.standard, x.application, x.notes]), [170, 70, '*'], { fontSize: 9 }),

    // Architecture
    h1('Architecture, interfaces and assets', landscape),
    h2('Components / zones'),
    grid(['ID', 'Component / zone', 'Description', 'Location', 'Operated by', 'CRA scope', ...(st.iec62443 ? ['SL-T'] : []), 'Criticality rationale', 'Assumptions'],
      a.components.map((c) => [c.id, c.name, c.description, c.location, c.operatedBy, c.scope, ...(st.iec62443 ? [c.slT] : []), c.rationale, c.assumptions])),
    h2('Interfaces / conduits'),
    grid(['ID', 'Interface', 'From', 'To', 'Protocol / port', 'Exposure', 'Protection', 'Default', 'Needed', 'Remote', 'Notes'],
      a.interfaces.map((i) => [i.id, i.name, i.from, i.to, i.protocol, i.exposure, i.protection, i.defaultState, i.needed, i.remoteAccess, i.notes]),
      [28, 70, 32, 32, 70, 60, '*', 45, 35, 35, 80]),
    h2('Assets'),
    grid(['ID', 'Asset', 'Component', 'Type', 'Description', 'C', 'I', 'A', 'Impact if compromised'],
      a.assets.map((x) => [x.id, x.name, x.component, x.type, x.description, x.c, x.i, x.a, x.impact]), [28, 90, 55, 70, '*', 32, 32, 32, 130]),

    // STRIDE
    h1('Threat identification (STRIDE)', landscape),
    { text: 'Every in-scope component / zone and interface / conduit was examined for the six STRIDE categories. Each cell lists the risk scenarios addressing it, or records why the category is not applicable.', fontSize: 8, color: C.grey, margin: [0, 0, 0, 6] },
    { svg: diagramSvg(a, { stride: ev.stride }), fit: [760, 400], alignment: 'center', margin: [0, 0, 0, 8] },
    { text: 'Data-flow diagram generated from the architecture description. Dashed red outlines mark trust boundaries; arrows are interfaces, coloured by STRIDE status.', fontSize: 7.5, color: C.grey, margin: [0, 0, 0, 8] },
    { text: '', pageBreak: 'before' },
    strideTable(a, ev),
    h2('Justifications for non-applicable categories'),
    grid(['Element', 'Category', 'Justification'], strideTargets(a).flatMap((t) => STRIDE.filter((x) => ['na', 'na-missing'].includes(ev.stride[t.id][x.letter].status))
      .map((x) => [`${t.id} ${s(t.name)}`, x.label, ev.stride[t.id][x.letter].justification || 'MISSING'])), [150, 120, '*']),

    // Method
    h1('Risk method', landscape),
    { text: `Risk score = likelihood × impact (1–25). Preset: ${a.method.label || a.method.preset}. Approved by: ${a.method.approvedBy || '—'} ${a.method.approvedAt || ''}`, margin: [0, 0, 0, 6] },
    h2('Likelihood'),
    grid(['Level', 'Label', ...a.method.likelihoodColumns], a.method.likelihood.map((l) => [l.level, l.label, ...l.criteria]), [30, 60, ...a.method.likelihoodColumns.map(() => '*')]),
    h2('Impact'),
    grid(['Level', 'Label', ...a.method.impactColumns], a.method.impact.map((l) => [l.level, l.label, ...l.criteria]), [30, 60, ...a.method.impactColumns.map(() => '*')]),
    h2('Rating thresholds and acceptance'),
    grid(['Rating', 'Min. score', 'Acceptance rule'], a.method.thresholds.map((t) => [t.rating, t.min, t.rule]), [70, 50, '*'], { ratingCols: [0] }),

    // Risks
    h1('Threat and risk register', landscape),
    grid(['ID', 'Interface / asset', 'Threat scenario', 'STRIDE / actor / vector', 'Consequence', 'Inh.', 'Controls / mitigations', 'Mapping', 'Evidence', 'Res.', 'Treatment / owner / status'],
      ev.risks.map((r) => [
        r.id, `${s(r.interfaces)}\n${s(r.assets)}`, r.scenario, `${s(r.stride)}\n${s(r.actor)}\n${s(r.vector)}`, r.consequence,
        r.inherentScore ? `${r.inherentL}×${r.inherentI}=${r.inherentScore}\n${r.inherentRating}` : '',
        r.controls,
        [`CRA: ${join(r.annex)}`, `EN 18031: ${join(r.en18031)}`, st.en303645 ? `EN 303 645: ${join(r.en303645)}` : '', st.iec62443 ? `IEC 62443: ${s(r.iec62443)}` : ''].filter(Boolean).join('\n'),
        r.evidence,
        r.residualScore ? `${r.residualL}×${r.residualI}=${r.residualScore}\n${r.residualRating}` : '',
        `${s(r.treatment)}${r.acceptance ? ` (${r.acceptance})` : ''}\n${s(r.owner)}\n${s(r.status)} ${s(r.lastReviewed)}`,
      ]), [30, 45, '*', 70, 75, 38, '*', 75, 60, 38, 70], { fontSize: 7 }),

    // Annex I
    h1('Annex I – applicability and implementation', landscape),
    { text: 'Art. 13(3): the assessment indicates whether, and if so how, the security requirements of Annex I Part I(2) are applicable and how they are implemented, how Annex I Part I(1) is applied, and how the vulnerability-handling requirements of Annex I Part II are applied. Art. 13(4): where requirements are not applicable, a clear justification is given.', fontSize: 8, color: C.grey, margin: [0, 0, 0, 6] },
    grid(['ID', 'Requirement (paraphrased)', 'Appl.', 'Justification / implementation', 'Evidence', 'Linked risks', 'Coverage'],
      ANNEX_I.map((r) => {
        const e = a.annexI[r.id];
        return [`${r.id}\n${r.ref}`, r.text, e.applicable || '—', e.applicable === 'No' ? `Not applicable: ${e.justification}` : e.implementation, e.evidence, ev.annex[r.id].linked.join(', '), ev.annex[r.id].status];
      }), [55, '*', 30, '*', 80, 55, 75], { fontSize: 7 }),
  ];

  if (st.en303645) {
    content.push(
      h1('ETSI EN 303 645 checklist', landscape),
      grid(['Clause', 'Topic', 'Applicable', 'Justification / implementation', 'Evidence', 'Coverage'],
        EN303645.map((c) => {
          const e = a.en303645[c.id];
          return [c.id, c.topic, e.applicable || '—', e.applicable === 'No' ? `Not applicable: ${e.justification}` : e.implementation, e.evidence, ev.en303645[c.id].status];
        }), [35, 130, 45, '*', 110, 100], { fontSize: 8 }),
    );
  }

  content.push(
    h1('User information (Annex II)', landscape),
    grid(['ID', 'Requirement', 'Ref', 'Where provided', 'Content / link', 'Owner', 'Status', 'Evidence'],
      userInfoItems(a).map((u) => { const e = a.userInfo[u.id]; return [u.id, u.text, u.ref, e.where, e.content, e.owner, e.status, e.evidence]; }),
      [28, '*', 55, 70, '*', 55, 50, 70], { fontSize: 7.5 }),
    h1('Review log', portrait),
    grid(['Version', 'Date', 'Author', 'Trigger', 'Summary', 'Approved by', 'Approval date'],
      a.reviewLog.map((r) => [r.version, r.date, r.author, r.trigger, r.summary, r.approvedBy, r.approvalDate]), [35, 50, 55, 70, '*', 60, 50]),
    h1('Open findings at export time'),
    grid(['Level', 'Section', 'Finding'], ev.findings.filter((f) => f.level !== 'info').map((f) => [f.level, f.step, f.message]), [50, 70, '*']),
  );

  const doc = {
    pageSize: 'A4', pageMargins: [40, 50, 40, 50], content,
    info: { title: `Cybersecurity risk assessment – ${s(p.name)}`, subject: 'CRA Art. 13 risk assessment', creator: 'CRA Self Assessment Helper' },
    header: (page) => (page === 1 ? null : { text: `${s(p.name)} – Cybersecurity risk assessment v${dc.version}${dc.frozen ? '' : ' (DRAFT)'}`, fontSize: 7, color: C.grey, margin: [40, 25, 40, 0] }),
    footer: (page, pages) => ({ columns: [{ text: `SHA-256 ${dc.sha256.slice(0, 16)}…`, fontSize: 7, color: C.grey }, { text: `Page ${page} / ${pages}`, alignment: 'right', fontSize: 7, color: C.grey }], margin: [40, 20, 40, 0] }),
    defaultStyle: { font: 'Roboto', fontSize: 9, lineHeight: 1.15 },
    styles: {
      title: { fontSize: 26, bold: true, color: C.navy },
      h1: { fontSize: 15, bold: true, color: C.navy, margin: [0, 6, 0, 8] },
      h2: { fontSize: 11, bold: true, color: C.navy, margin: [0, 6, 0, 4] },
      th: { bold: true, color: 'white' },
    },
  };
  return pdfmake.createPdf(doc).getBuffer();
}

// Shared renderer for other reports (technical documentation index).
export const PDF_STYLES = {
  title: { fontSize: 26, bold: true, color: C.navy },
  h1: { fontSize: 15, bold: true, color: C.navy, margin: [0, 6, 0, 8] },
  h2: { fontSize: 11, bold: true, color: C.navy, margin: [0, 6, 0, 4] },
  th: { bold: true, color: 'white' },
};
export function renderPdf(doc) {
  return pdfmake.createPdf({ pageSize: 'A4', pageMargins: [40, 50, 40, 50], defaultStyle: { font: 'Roboto', fontSize: 9, lineHeight: 1.15 }, styles: PDF_STYLES, ...doc }).getBuffer();
}
