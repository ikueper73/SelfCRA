// CRA Annex VII technical documentation: structure and completeness checks (pure).
// Content already captured in the risk assessment is referenced, not duplicated.
import { evaluate, userInfoItems } from './model.js';
import { ANNEX_I } from './catalog.js';

export const COMPONENT_TYPES = [
  { id: 'firmware', label: 'Firmware / embedded software', hardware: true },
  { id: 'hardware', label: 'Hardware (device, PCB)', hardware: true, noSbom: true },
  { id: 'backend', label: 'Backend / cloud service (RDPS)' },
  { id: 'frontend', label: 'Web frontend' },
  { id: 'mobile', label: 'Mobile app' },
  { id: 'desktop', label: 'Desktop / PC software' },
  { id: 'library', label: 'Library / SDK' },
  { id: 'other', label: 'Other' },
];

export const FILE_SECTIONS = [
  { id: '1c', label: 'Photos / illustrations of the hardware (external features, markings, internal layout)', annex: 'VII(1)(c)' },
  { id: '1d', label: 'User information and instructions (manual, quick-start, online help)', annex: 'VII(1)(d), Annex II' },
  { id: '2a', label: 'Design & development: drawings, schemes, architecture documents', annex: 'VII(2)(a)' },
  { id: '2b-cvd', label: 'Coordinated vulnerability disclosure policy', annex: 'VII(2)(b)' },
  { id: '2b-contact', label: 'Evidence of the vulnerability contact address (e.g. screenshot of security.txt / web page)', annex: 'VII(2)(b)' },
  { id: '2b-update', label: 'Secure update distribution: design / specification', annex: 'VII(2)(b)' },
  { id: '2c', label: 'Production and monitoring processes and their validation', annex: 'VII(2)(c)' },
  { id: '5', label: 'Standards, specifications, certificates', annex: 'VII(5)' },
  { id: '6', label: 'Test and audit reports', annex: 'VII(6)' },
  { id: '7', label: 'EU declaration of conformity (signed copy)', annex: 'VII(7)' },
  { id: 'other', label: 'Other supporting documents', annex: '' },
];

export const TEST_TYPES = ['Penetration test', 'Fuzzing', 'Static code analysis (SAST)', 'Dynamic analysis (DAST)', 'Software composition analysis', 'Functional security test', 'Configuration / hardening review', 'Vulnerability-handling process audit', 'Certification / third-party evaluation', 'Other'];
export const TEST_RESULTS = ['Passed', 'Passed with findings', 'Failed', 'In progress'];

// CycloneDX VEX analysis states and justifications
export const VEX_STATES = [
  { id: 'in_triage', label: 'In triage', open: true },
  { id: 'exploitable', label: 'Affected / exploitable', open: true },
  { id: 'not_affected', label: 'Not affected' },
  { id: 'false_positive', label: 'False positive' },
  { id: 'resolved', label: 'Resolved (fixed)' },
  { id: 'resolved_with_pedigree', label: 'Resolved (fix backported)' },
];
export const VEX_JUSTIFICATIONS = ['code_not_present', 'code_not_reachable', 'requires_configuration', 'requires_dependency', 'requires_environment', 'protected_by_compiler', 'protected_at_runtime', 'protected_at_perimeter', 'protected_by_mitigating_control'];
export const VEX_RESPONSES = ['update', 'workaround_available', 'rollback', 'can_not_fix', 'will_not_fix'];

export function newProductData(name = '') {
  return normalizeProduct({ name });
}

export function normalizeProduct(p) {
  p = p || {};
  p.name = p.name || '';
  p.placedOnMarket = p.placedOnMarket || '';       // date of first placing on the market (planned or actual)
  p.sme = p.sme || '';                               // '', 'micro', 'small' (Art. 33(5) simplified form)
  p.docs = {
    hardwareNote: '', userInfoUrl: '', designDescription: '',
    cvdPolicyUrl: '', cvdPolicySummary: '', contactEmail: '', contactUrl: '',
    updateDistribution: '', productionProcesses: '', productionValidation: '',
    solutionsWithoutStandards: '', sbomOnRequest: '', docDate: '', docVersion: '', docUrl: '',
    ...(p.docs || {}),
  };
  return p;
}

const blank = (v) => !String(v ?? '').trim();

/**
 * @param {object} ctx
 *   product: normalized product data
 *   assessment: normalized assessment data (or null)
 *   components: [{id, name, type, version, sbom: {id, components, quality} | null, vulns: {open, exploitable, kev, critical, high, untriaged}}]
 *   files: [{id, section, name, meta}]
 *   snapshots: assessment snapshots [{version, createdAt}]
 */
export function evaluateTechDoc({ product, assessment, components = [], files = [], snapshots = [] }) {
  const d = product.docs;
  const ev = assessment ? evaluate(assessment) : null;
  const filesIn = (s) => files.filter((f) => f.section === s);
  const items = [];
  const item = (id, title, annex, checks, sources = []) => {
    const relevant = checks.filter((c) => c.level !== 'info');
    const okCount = relevant.filter((c) => c.ok).length;
    const status = !relevant.length || okCount === relevant.length ? 'complete' : okCount === 0 ? 'missing' : 'partial';
    items.push({ id, title, annex, checks, status, sources, blockers: relevant.filter((c) => !c.ok && c.level === 'blocker').length });
  };
  const chk = (ok, text, level = 'blocker') => ({ ok: !!ok, text, level });

  const software = components.filter((c) => !COMPONENT_TYPES.find((t) => t.id === c.type)?.noSbom);
  const hasHardware = components.some((c) => COMPONENT_TYPES.find((t) => t.id === c.type)?.hardware);
  const a = assessment;

  // 1 General description
  const uiItems = a ? userInfoItems(a) : [];
  const uiOpen = a ? uiItems.filter((u) => !['Implemented', 'Verified', 'Not applicable'].includes(a.userInfo[u.id].status)).length : null;
  item('1', 'General description of the product', 'VII(1)', [
    chk(a && !blank(a.product.intendedPurpose), '(a) Intended purpose described (risk assessment → Product description).'),
    chk(components.length > 0, '(b) Product components listed (firmware, backend, apps …).'),
    chk(software.length > 0 && software.every((c) => !blank(c.version)), '(b) Every software component has a version that this documentation covers.'),
    ...(hasHardware ? [chk(filesIn('1c').length > 0, '(c) Photos / illustrations of external features, markings and internal layout attached.')] : [chk(true, '(c) No hardware component – photos not required.', 'info')]),
    chk(a && uiOpen === 0, `(d) User information per Annex II implemented${uiOpen ? ` (${uiOpen} item(s) open)` : ''}.`),
    chk(filesIn('1d').length > 0 || !blank(d.userInfoUrl), '(d) User manual / instructions attached or linked.', 'warning'),
  ], ['Risk assessment: product description, user information', 'Components', 'Attachments 1(c), 1(d)']);

  // 2 Design, development, production, vulnerability handling
  const noSbom = software.filter((c) => !c.sbom);
  const weakSbom = software.filter((c) => c.sbom && c.sbom.quality && c.sbom.quality.score < 70);
  const exploitable = components.reduce((n, c) => n + (c.vulns?.exploitable || 0), 0);
  const untriaged = components.reduce((n, c) => n + (c.vulns?.untriaged || 0), 0);
  const kevOpen = components.reduce((n, c) => n + (c.vulns?.kevOpen || 0), 0);
  item('2', 'Design, development, production and vulnerability handling', 'VII(2)', [
    chk(a && a.components.length > 0 && a.interfaces.length > 0, '(a) System architecture described (risk assessment → Architecture & interfaces; diagram generated).'),
    chk(!blank(d.designDescription) || filesIn('2a').length > 0, '(a) Design and development information (description or drawings) provided.', 'warning'),
    chk(software.length > 0 && noSbom.length === 0, `(b) SBOM imported for every software component${noSbom.length ? ` – missing: ${noSbom.map((c) => c.name).join(', ')}` : ''}.`),
    chk(weakSbom.length === 0, `(b) SBOM quality sufficient (top-level dependencies, identifiers, suppliers)${weakSbom.length ? ` – check: ${weakSbom.map((c) => c.name).join(', ')}` : ''}.`, 'warning'),
    chk(!blank(d.cvdPolicyUrl) || filesIn('2b-cvd').length > 0, '(b) Coordinated vulnerability disclosure policy linked or attached.'),
    chk((!blank(d.contactEmail) || !blank(d.contactUrl)) && filesIn('2b-contact').length > 0, '(b) Contact address for vulnerability reports given, with evidence that it is published.'),
    chk(!blank(d.updateDistribution), '(b) Technical solution for secure distribution of updates described.'),
    chk(exploitable === 0, `(b) No known exploitable vulnerabilities open${exploitable ? ` (${exploitable} marked exploitable)` : ''} – Annex I Part I(2)(a).`),
    chk(untriaged === 0, `(b) All found vulnerabilities triaged${untriaged ? ` (${untriaged} in triage)` : ''}.`, 'warning'),
    ...(kevOpen ? [chk(false, `${kevOpen} open vulnerability/ies are known to be actively exploited – check the Art. 14 reporting obligation.`)] : []),
    chk(!blank(d.productionProcesses) || filesIn('2c').length > 0, '(c) Production and monitoring processes described.'),
    chk(!blank(d.productionValidation) || filesIn('2c').length > 0, '(c) Validation of these processes described.', 'warning'),
  ], ['Risk assessment: architecture', 'Components & SBOMs', 'Vulnerabilities', 'Attachments 2(a)–2(c)']);

  // 3 Risk assessment
  const lastLog = a?.reviewLog?.at(-1);
  item('3', 'Cybersecurity risk assessment', 'VII(3), Art. 13', [
    chk(!!a, 'Risk assessment exists.'),
    chk(ev && ev.blockers === 0, `Risk assessment has no blocking findings${ev?.blockers ? ` (${ev.blockers} open)` : ''}.`),
    chk(a && !blank(a.method.approvedBy), 'Risk method approved.', 'warning'),
    chk(lastLog && !blank(lastLog.approvedBy), 'Latest revision approved (review log).', 'warning'),
    chk(snapshots.length > 0, 'A version of the risk assessment has been frozen.', 'warning'),
  ], ['Risk assessment (all steps)']);

  // 4 Support period
  item('4', 'Information used to determine the support period', 'VII(4), Art. 13(8)', [
    chk(a && Number(a.supportPeriod.years) > 0, 'Support period defined.'),
    chk(a && !blank(a.supportPeriod.rationale), 'Information considered is documented.'),
    chk(a && !blank(a.supportPeriod.endDate), 'End date defined (shown at the time of purchase, Art. 13(19)).', 'warning'),
  ], ['Risk assessment → Support period']);

  // 5 Standards
  item('5', 'Harmonised standards, common specifications, certification schemes', 'VII(5)', [
    chk(a && (a.standardsApplied.length > 0 || !blank(d.solutionsWithoutStandards)), 'Applied standards listed – or, where none are applied, the solutions meeting Annex I Parts I and II described.'),
    chk(a && a.standardsApplied.every((s) => s.application === 'Full' || !blank(s.notes)), 'For partially applied standards, the applied parts are named.', 'warning'),
  ], ['Risk assessment → Related regulation & standards', 'Attachments 5']);

  // 6 Test reports
  const reports = filesIn('6');
  const covered = new Set(reports.flatMap((r) => r.meta?.annex || []));
  const applicable = a ? ANNEX_I.filter((r) => a.annexI[r.id]?.applicable === 'Yes').map((r) => r.id) : [];
  const uncovered = applicable.filter((id) => !covered.has(id));
  const failed = reports.filter((r) => r.meta?.result === 'Failed');
  item('6', 'Test reports', 'VII(6)', [
    chk(reports.length > 0, 'Test / audit reports attached.'),
    chk(reports.length > 0 && uncovered.length === 0, `Every applicable Annex I requirement is covered by a report${uncovered.length ? ` – not yet: ${uncovered.join(', ')}` : ''}.`, 'warning'),
    chk(reports.some((r) => (r.meta?.annex || []).some((x) => x.startsWith('P2-'))), 'Vulnerability-handling process (Annex I Part II) verified.', 'warning'),
    chk(failed.length === 0, `No failed test reports${failed.length ? ` (${failed.map((f) => f.meta?.title || f.name).join(', ')})` : ''}.`),
  ], ['Attachments 6 (test reports with Annex I mapping)']);

  // 7 DoC
  item('7', 'EU declaration of conformity', 'VII(7), Art. 28, Annex V', [
    chk(filesIn('7').length > 0, 'Signed EU declaration of conformity attached.'),
    chk(!blank(d.docUrl), 'Internet address of the declaration (Annex II(6)) recorded.', 'warning'),
  ], ['Attachments 7']);

  // 8 SBOM on request
  item('8', 'SBOM for market surveillance authorities (on reasoned request)', 'VII(8)', [
    chk(software.length > 0 && noSbom.length === 0, 'SBOMs available for all software components (exported with every release).'),
    chk(!blank(d.sbomOnRequest), 'Procedure / contact for handing over the SBOM on request described.', 'warning'),
  ], ['Components & SBOMs']);

  const placed = product.placedOnMarket ? new Date(product.placedOnMarket) : null;
  const supportEnd = a?.supportPeriod?.endDate || '';
  const retention = placed && !isNaN(placed) ? `${placed.getFullYear() + 10}-${String(placed.getMonth() + 1).padStart(2, '0')} or end of support period (${supportEnd || 'not set'}), whichever is later` : 'set the placing-on-market date';

  return {
    items,
    complete: items.filter((i) => i.status === 'complete').length,
    blockers: items.reduce((n, i) => n + i.blockers, 0),
    retention,
    assessment: ev,
  };
}

export function fileSectionLabel(id) {
  return FILE_SECTIONS.find((s) => s.id === id)?.label || id;
}
