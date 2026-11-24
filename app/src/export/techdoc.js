// Technical documentation package (CRA Art. 31, Annex VII): index PDF + ZIP with all evidence and a SHA-256 manifest.
import JSZip from 'jszip';
import { createHash, randomUUID } from 'node:crypto';
import { renderPdf, kv, grid, C } from './pdf.js';
import { toPdf } from './pdf.js';
import { toXlsx } from './xlsx.js';
import { docControl, safeFilename, sha256 as dataHash } from './common.js';
import { evaluateTechDoc, FILE_SECTIONS, COMPONENT_TYPES, VEX_STATES } from '../shared/techdoc.js';
import { diagramSvg } from '../shared/diagram.js';
import { toCycloneDxVex } from '../vuln.js';

const hashBuf = (b) => createHash('sha256').update(b).digest('hex');
const s = (v) => (v == null ? '' : String(v));
const typeLabel = (t) => COMPONENT_TYPES.find((x) => x.id === t)?.label || t;
const stateLabel = (t) => VEX_STATES.find((x) => x.id === t)?.label || t;
const SECTION_DIR = { '1c': '01_general/hardware', '1d': '01_general/user-information', '2a': '02_design', '2b-cvd': '02_vulnerability-handling/cvd-policy',
  '2b-contact': '02_vulnerability-handling/contact-evidence', '2b-update': '02_vulnerability-handling/update-distribution', '2c': '02_production', '5': '05_standards',
  '6': '06_test-reports', '7': '07_declaration-of-conformity', other: '09_other' };

/** ctx: { product, assessmentRecord, components:[{...,sbom,sbomRaw,vulns,findings}], files:[{...,data}], snapshots, release:{version,note,actor,frozen} } */
export async function buildTechDocPackage(ctx) {
  const { product, assessmentRecord, components, files, snapshots, release } = ctx;
  const a = assessmentRecord.data;
  const zip = new JSZip();
  const manifest = [];
  const put = (p, data) => {
    const b = Buffer.isBuffer(data) ? data : Buffer.from(data);
    zip.file(p, b, { date: new Date(release.createdAt) });
    manifest.push({ path: p, sha256: hashBuf(b), size: b.length });
    return p;
  };

  // risk assessment (exports of the state at release time)
  const dc = { ...docControl({ id: assessmentRecord.id, data: a }, null), frozen: release.frozen, version: `${a.meta.version} (documentation ${release.version})`, frozenAt: release.createdAt, frozenBy: release.actor, note: release.note || '' };
  put('03_risk-assessment/risk-assessment.pdf', await toPdf(dc));
  put('03_risk-assessment/risk-assessment.xlsx', await toXlsx(dc));
  put('03_risk-assessment/risk-assessment.json', JSON.stringify({ format: 'cra-risk-assessment', sha256: dc.sha256, data: a }, null, 2));
  put('02_design/threat-model.svg', diagramSvg(a, {}));

  // SBOMs, VEX, vulnerability lists
  const vulnRows = [['component', 'component_version', 'package', 'package_version', 'vulnerability', 'aliases', 'severity', 'score', 'known_exploited', 'epss', 'state', 'justification', 'response', 'analysis']];
  for (const c of components) {
    const dir = `02_vulnerability-handling/sbom/${safeFilename(c.name)}_${safeFilename(c.version || 'unversioned')}`;
    if (c.sbomRaw) put(`${dir}/${safeFilename(c.sbomRaw.filename || `sbom.${c.sbomRaw.format.toLowerCase()}.json`)}`, c.sbomRaw.raw);
    const present = c.findings.filter((f) => f.present);
    if (c.sbom || present.length) {
      put(`${dir}/vex.cdx.json`, JSON.stringify(toCycloneDxVex({ product: { name: product.name }, component: c, findings: present, serial: randomUUID() }), null, 2));
    }
    for (const f of present) vulnRows.push([c.name, c.version, f.pkgName, f.pkgVersion, f.vulnId, f.aliases.join(' '), f.severity, f.score ?? '', f.kev ? 'yes' : '', f.epss ?? '', f.state, f.justification, f.response, f.analysis]);
  }
  put('02_vulnerability-handling/vulnerabilities.csv', vulnRows.map((r) => r.map((v) => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\r\n'));

  // attachments
  const fileRef = new Map();
  for (const f of files) {
    const p = put(`${SECTION_DIR[f.section] || SECTION_DIR.other}/${f.id.slice(0, 8)}_${safeFilename(f.name)}`, f.data);
    fileRef.set(f.id, p);
  }

  // index PDF
  const ev = evaluateTechDoc({ product, assessment: a, components, files, snapshots });
  const indexPdf = await renderPdf(indexDefinition({ product, a, components, files, ev, release, fileRef }));
  put('00_index_annex-VII.pdf', indexPdf);

  const man = {
    format: 'cra-technical-documentation', product: { id: product.id, name: product.name }, version: release.version, note: release.note || '',
    createdAt: release.createdAt, createdBy: release.actor, assessmentSha256: dc.sha256,
    completeness: Object.fromEntries(ev.items.map((i) => [i.id, i.status])), files: manifest,
  };
  zip.file('manifest.json', JSON.stringify(man, null, 2), { date: new Date(release.createdAt) });
  const buffer = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE', compressionOptions: { level: 6 } });
  return { zip: buffer, sha256: hashBuf(buffer), manifest: man, evaluation: ev };
}

function indexDefinition({ product, a, components, files, ev, release, fileRef }) {
  const d = product.docs;
  const statusColor = { complete: '#2E7D32', partial: '#A15C00', missing: '#B71C1C' };
  const filesFor = (sec) => files.filter((f) => f.section === sec).map((f) => [f.meta?.title || f.name, fileRef.get(f.id), f.sha256.slice(0, 16) + '…']);
  const vulnTotals = components.reduce((t, c) => { for (const f of c.findings.filter((x) => x.present)) { t[f.state] = (t[f.state] || 0) + 1; } return t; }, {});
  const content = [
    { text: 'Technical documentation', style: 'title', margin: [0, 80, 0, 6] },
    { text: product.name, fontSize: 18, color: C.navy },
    { text: 'Regulation (EU) 2024/2847 (Cyber Resilience Act) – Article 31 and Annex VII', color: C.grey, margin: [0, 4, 0, 30] },
    kv([
      ['Documentation version', release.version], ['State', release.frozen ? `Frozen release – ${release.createdAt} by ${release.actor}` : 'DRAFT – not a frozen release'],
      ['Note', release.note], ['Manufacturer', a.product.manufacturer], ['Placed on the market', product.placedOnMarket || 'not yet'],
      ['Support period', `${a.supportPeriod.years ? `${a.supportPeriod.years} years` : '—'}${a.supportPeriod.endDate ? `, until ${a.supportPeriod.endDate}` : ''}`],
      ['Keep this documentation until', ev.retention], ['Annex VII items complete', `${ev.complete} of ${ev.items.length}`],
    ]),
    { text: 'All files referenced below are contained in this package; their SHA-256 checksums are listed in manifest.json.', fontSize: 8, color: C.grey },
    { text: 'Completeness overview', style: 'h1', pageBreak: 'before' },
    grid(['Item', 'Annex VII', 'Status', 'Open points'], ev.items.map((i) => [
      `${i.id}. ${i.title}`, i.annex, { text: i.status, color: statusColor[i.status], bold: true },
      i.checks.filter((c) => !c.ok && c.level !== 'info').map((c) => `• ${c.text}`).join('\n') || '—']), [150, 60, 50, '*'], { fontSize: 8 }),

    { text: '1. General description', style: 'h1', pageBreak: 'before' },
    kv([['(a) Intended purpose', a.product.intendedPurpose], ['Reasonably foreseeable use / misuse', a.product.foreseeableUse], ['Operating environment', a.product.environment]]),
    { text: '(b) Components and software versions covered', style: 'h2' },
    grid(['Component', 'Type', 'Version', 'SBOM'], components.map((c) => [c.name, typeLabel(c.type), c.version, c.sbom ? `${c.sbom.format} ${c.sbom.specVersion}, ${c.sbom.summary.packages} packages` : '—']), ['*', 120, 80, 150]),
    { text: '(c) Hardware photos and illustrations', style: 'h2' },
    grid(['Document', 'File in package', 'SHA-256'], filesFor('1c'), ['*', 200, 90]),
    { text: '(d) User information and instructions (Annex II)', style: 'h2' },
    kv([['Online instructions', d.userInfoUrl], ['Status in risk assessment', 'see 03_risk-assessment/risk-assessment.pdf, section "User information"']]),
    grid(['Document', 'File in package', 'SHA-256'], filesFor('1d'), ['*', 200, 90]),

    { text: '2. Design, development, production and vulnerability handling', style: 'h1', pageBreak: 'before' },
    { text: '(a) Design and development; system architecture', style: 'h2' },
    { text: s(d.designDescription) || 'See the architecture description and threat-model diagram (02_design/threat-model.svg) and section "Architecture" of the risk assessment.', margin: [0, 0, 0, 6] },
    grid(['Document', 'File in package', 'SHA-256'], filesFor('2a'), ['*', 200, 90]),
    { text: '(b) Vulnerability handling', style: 'h2' },
    kv([
      ['Coordinated vulnerability disclosure policy', [d.cvdPolicyUrl, d.cvdPolicySummary].filter(Boolean).join('\n')],
      ['Contact for vulnerability reports', [d.contactEmail, d.contactUrl].filter(Boolean).join('\n')],
      ['Secure distribution of updates', d.updateDistribution],
      ['Vulnerability status at this release', Object.entries(vulnTotals).map(([k, v]) => `${stateLabel(k)}: ${v}`).join(', ') || 'no known vulnerabilities'],
    ]),
    grid(['SBOM', 'Format', 'Packages', 'Top-level deps', 'Quality', 'Open vulnerabilities'], components.filter((c) => c.sbom).map((c) => [
      `${c.name} ${c.version}`, `${c.sbom.format} ${c.sbom.specVersion}`, c.sbom.summary.packages, c.sbom.summary.topLevel, `${c.sbom.summary.quality?.score ?? '—'} %`,
      `${c.vulns.open} (exploitable ${c.vulns.exploitable}, actively exploited ${c.vulns.kevOpen})`]), ['*', 70, 50, 55, 45, 120]),
    grid(['Evidence', 'File in package', 'SHA-256'], [...filesFor('2b-cvd'), ...filesFor('2b-contact'), ...filesFor('2b-update')], ['*', 200, 90]),
    { text: '(c) Production and monitoring processes and their validation', style: 'h2' },
    kv([['Processes', d.productionProcesses], ['Validation', d.productionValidation]]),
    grid(['Document', 'File in package', 'SHA-256'], filesFor('2c'), ['*', 200, 90]),

    { text: '3. Cybersecurity risk assessment', style: 'h1', pageBreak: 'before' },
    { text: `Risk assessment version ${a.meta.version}, status ${a.meta.status}. Full report: 03_risk-assessment/risk-assessment.pdf (also as XLSX and JSON). ${ev.assessment ? `${ev.assessment.risks.length} risks; residual critical: ${ev.assessment.counts.residual.Critical || 0}; blocking findings: ${ev.assessment.blockers}.` : ''}` },
    { text: '4. Support period', style: 'h1' },
    kv([['Support period', a.supportPeriod.years ? `${a.supportPeriod.years} years` : ''], ['End date', a.supportPeriod.endDate], ['Information considered', a.supportPeriod.rationale]]),
    { text: '5. Standards and specifications applied', style: 'h1' },
    grid(['Standard / specification', 'Application', 'Parts applied / notes'], a.standardsApplied.map((x) => [x.standard, x.application, x.notes]), [170, 70, '*']),
    ...(d.solutionsWithoutStandards ? [kv([['Solutions where no standard is applied', d.solutionsWithoutStandards]])] : []),
    grid(['Document', 'File in package', 'SHA-256'], filesFor('5'), ['*', 200, 90]),

    { text: '6. Test reports', style: 'h1', pageBreak: 'before' },
    grid(['Report', 'Type', 'Date', 'Result', 'Annex I covered', 'File'], files.filter((f) => f.section === '6').map((f) => [
      f.meta?.title || f.name, s(f.meta?.type), s(f.meta?.date), s(f.meta?.result), (f.meta?.annex || []).join(', '), fileRef.get(f.id)]), ['*', 80, 55, 60, 90, 120], { fontSize: 7.5 }),
    { text: '7. EU declaration of conformity', style: 'h1' },
    kv([['Date / version', [d.docDate, d.docVersion].filter(Boolean).join(' / ')], ['Internet address (Annex II(6))', d.docUrl]]),
    grid(['Document', 'File in package', 'SHA-256'], filesFor('7'), ['*', 200, 90]),
    { text: '8. SBOM for market surveillance authorities', style: 'h1' },
    { text: `The SBOMs of all components are contained in 02_vulnerability-handling/sbom/. ${s(d.sbomOnRequest)}` },
  ];
  return {
    content,
    info: { title: `Technical documentation – ${product.name} ${release.version}`, creator: 'CRA Self Assessment Helper' },
    header: (page) => (page === 1 ? null : { text: `${product.name} – Technical documentation ${release.version}${release.frozen ? '' : ' (DRAFT)'}`, fontSize: 7, color: C.grey, margin: [40, 25, 40, 0] }),
    footer: (page, pages) => ({ text: `Page ${page} / ${pages}`, alignment: 'right', fontSize: 7, color: C.grey, margin: [40, 20, 40, 0] }),
  };
}

export { dataHash };
