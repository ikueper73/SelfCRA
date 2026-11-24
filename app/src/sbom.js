// SBOM import: CycloneDX JSON (1.2–1.6) and SPDX 2.x JSON → normalized package list + quality check.
// Quality criteria follow the NTIA minimum elements / BSI TR-03183-2 (author, timestamp, supplier,
// name, version, unique identifier, dependency relationships; licence recommended).
import { createHash } from 'node:crypto';

export class SbomError extends Error {}

const noAssert = (v) => (v == null || v === '' || /^NOASSERTION$|^NONE$/i.test(String(v)) ? '' : String(v));

export function parseSbom(buffer, filename = 'sbom.json') {
  const text = buffer.toString('utf8').replace(/^﻿/, '').trim();
  if (text.startsWith('<')) throw new SbomError('XML SBOMs are not supported yet. Convert to JSON first, e.g. "cyclonedx convert --output-format json".');
  let doc;
  try { doc = JSON.parse(text); } catch { throw new SbomError('The file is not valid JSON.'); }
  let parsed;
  if (doc.bomFormat === 'CycloneDX') parsed = parseCycloneDx(doc);
  else if (typeof doc.spdxVersion === 'string' && /^SPDX-2\./.test(doc.spdxVersion)) parsed = parseSpdx2(doc);
  else if (doc['@context'] && JSON.stringify(doc['@context']).includes('spdx')) throw new SbomError('SPDX 3.0 (JSON-LD) is not supported yet. Export SPDX 2.3 JSON or CycloneDX JSON.');
  else throw new SbomError('Unknown format: expected CycloneDX JSON (bomFormat) or SPDX 2.x JSON (spdxVersion).');
  const sha256 = createHash('sha256').update(buffer).digest('hex');
  return { ...parsed, filename, sha256, raw: buffer, summary: { ...summarize(parsed), quality: quality(parsed) } };
}

// ------------------------------------------------------------------ CycloneDX
function parseCycloneDx(doc) {
  const md = doc.metadata || {};
  const flat = [];
  const walk = (list) => { for (const c of list || []) { flat.push(c); walk(c.components); } };
  walk(doc.components);
  const deps = new Map((doc.dependencies || []).map((d) => [d.ref, d.dependsOn || []]));
  const rootRef = md.component?.['bom-ref'];
  const topLevel = new Set(rootRef ? deps.get(rootRef) || [] : []);
  const licenses = (c) => (c.licenses || []).map((l) => l.expression || l.license?.id || l.license?.name).filter(Boolean);
  const authorTools = [
    ...(md.authors || []).map((a) => a.name || a.email).filter(Boolean),
    ...(Array.isArray(md.tools) ? md.tools : [...(md.tools?.components || []), ...(md.tools?.services || [])]).map((t) => [t.vendor, t.name, t.version].filter(Boolean).join(' ')),
    md.manufacture?.name, md.manufacturer?.name, md.supplier?.name,
  ].filter(Boolean);
  const packages = flat.filter((c) => c.type !== 'file').map((c) => ({
    ref: c['bom-ref'] || '',
    type: c.type || 'library',
    name: c.group ? `${c.group}/${c.name}` : c.name || '',
    version: c.version || '',
    purl: c.purl || '',
    cpe: c.cpe || '',
    supplier: c.supplier?.name || c.publisher || c.author || (c.authors || []).map((a) => a.name).join(', ') || '',
    licenses: licenses(c),
    hashes: (c.hashes || []).length,
    topLevel: topLevel.has(c['bom-ref']),
  }));
  return {
    format: 'CycloneDX', specVersion: String(doc.specVersion || ''),
    meta: {
      timestamp: md.timestamp || '', authors: authorTools,
      primary: md.component ? { name: md.component.name || '', version: md.component.version || '', purl: md.component.purl || '' } : null,
      hasDependencies: deps.size > 0, serial: doc.serialNumber || '',
    },
    packages,
  };
}

// ------------------------------------------------------------------ SPDX 2.x
function parseSpdx2(doc) {
  const ci = doc.creationInfo || {};
  const rel = doc.relationships || [];
  const described = new Set([...(doc.documentDescribes || []), ...rel.filter((r) => r.relationshipType === 'DESCRIBES').map((r) => r.relatedSpdxElement)]);
  const topLevel = new Set();
  for (const r of rel) {
    if (described.has(r.spdxElementId) && ['DEPENDS_ON', 'CONTAINS', 'STATIC_LINK', 'DYNAMIC_LINK'].includes(r.relationshipType)) topLevel.add(r.relatedSpdxElement);
    if (described.has(r.relatedSpdxElement) && ['DEPENDENCY_OF', 'CONTAINED_BY'].includes(r.relationshipType)) topLevel.add(r.spdxElementId);
  }
  const ref = (p, cat, types) => (p.externalRefs || []).find((e) => cat.includes(String(e.referenceCategory).replace('_', '-')) && types.includes(e.referenceType))?.referenceLocator || '';
  const all = doc.packages || [];
  const primaryPkg = all.find((p) => described.has(p.SPDXID));
  const packages = all.filter((p) => !described.has(p.SPDXID)).map((p) => ({
    ref: p.SPDXID || '',
    type: p.primaryPackagePurpose ? p.primaryPackagePurpose.toLowerCase() : 'library',
    name: p.name || '',
    version: noAssert(p.versionInfo),
    purl: ref(p, ['PACKAGE-MANAGER'], ['purl']),
    cpe: ref(p, ['SECURITY'], ['cpe23Type', 'cpe22Type']),
    supplier: noAssert(p.supplier).replace(/^(Organization|Person|Tool):\s*/i, '') || noAssert(p.originator).replace(/^(Organization|Person|Tool):\s*/i, ''),
    licenses: [noAssert(p.licenseConcluded), noAssert(p.licenseDeclared)].filter(Boolean).filter((v, i, arr) => arr.indexOf(v) === i),
    hashes: (p.checksums || []).length,
    topLevel: topLevel.has(p.SPDXID),
  }));
  return {
    format: 'SPDX', specVersion: doc.spdxVersion.replace('SPDX-', ''),
    meta: {
      timestamp: ci.created || '', authors: (ci.creators || []).map((c) => c.replace(/^(Organization|Person|Tool):\s*/i, '')),
      primary: primaryPkg ? { name: primaryPkg.name || '', version: noAssert(primaryPkg.versionInfo), purl: ref(primaryPkg, ['PACKAGE-MANAGER'], ['purl']) } : null,
      hasDependencies: rel.some((r) => !['DESCRIBES', 'DESCRIBED_BY'].includes(r.relationshipType)), serial: doc.documentNamespace || '',
    },
    packages,
  };
}

// ------------------------------------------------------------------ summary & quality
function summarize({ packages, meta, format, specVersion }) {
  const ecosystems = {};
  for (const p of packages) {
    const eco = p.purl ? p.purl.slice(4).split('/')[0] : p.cpe ? 'cpe' : 'unidentified';
    ecosystems[eco] = (ecosystems[eco] || 0) + 1;
  }
  return {
    format, specVersion, packages: packages.length, topLevel: packages.filter((p) => p.topLevel).length,
    withPurl: packages.filter((p) => p.purl).length, withCpe: packages.filter((p) => p.cpe).length,
    ecosystems, timestamp: meta.timestamp, authors: meta.authors.slice(0, 5), primary: meta.primary,
  };
}

export function quality({ packages, meta }) {
  const n = packages.length || 1;
  const share = (fn) => packages.filter(fn).length / n;
  const checks = [
    { id: 'author', label: 'SBOM author / creating tool given', ok: meta.authors.length > 0, weight: 10 },
    { id: 'timestamp', label: 'Creation timestamp given', ok: !!meta.timestamp, weight: 5 },
    { id: 'primary', label: 'Primary component (the product part this SBOM describes) identified', ok: !!meta.primary, weight: 10 },
    { id: 'deps', label: 'Dependency relationships present (needed for "top-level dependencies", Annex I Part II(1))', ok: meta.hasDependencies && packages.some((p) => p.topLevel), weight: 15 },
    { id: 'names', label: 'Every component has name and version', share: share((p) => p.name && p.version), weight: 20 },
    { id: 'ids', label: 'Components have a unique identifier (package URL, CPE or hash)', share: share((p) => p.purl || p.cpe || p.hashes), weight: 20 },
    { id: 'supplier', label: 'Components name their supplier', share: share((p) => p.supplier), weight: 10 },
    { id: 'license', label: 'Components declare a licence', share: share((p) => p.licenses.length), weight: 10 },
  ];
  let score = 0;
  for (const c of checks) {
    const v = 'share' in c ? c.share : c.ok ? 1 : 0;
    c.ok = v >= 0.95;
    c.percent = Math.round(v * 100);
    score += v * c.weight;
  }
  if (!packages.length) checks.push({ id: 'empty', label: 'SBOM lists no components', ok: false, percent: 0, weight: 0 });
  return { score: packages.length ? Math.round(score) : 0, checks };
}

/** Stable key for a package inside one component (used to keep triage decisions across scans). */
export function packageKey(p) {
  if (p.purl) return p.purl.split('?')[0].split('#')[0].toLowerCase();
  return `${p.name}@${p.version}`.toLowerCase();
}
