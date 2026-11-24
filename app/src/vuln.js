// Vulnerability lookup for SBOM packages and import/export of vulnerability data.
//   OSV.dev     – by package URL (batch), details cached 24 h
//   NVD (NIST)  – by CPE, rate-limited (NVD_API_KEY raises the limit)
//   ENISA EUVD  – EUVD ID + EPSS per CVE (cached 7 days); exploited list merged into the KEV flag
//   CISA KEV    – known exploited vulnerabilities (cached 24 h)
// Outbound HTTPS can go through a proxy: set HTTPS_PROXY and NODE_USE_ENV_PROXY=1 (Node ≥ 24).
import { packageKey } from './sbom.js';

export function vulnConfig(env = process.env) {
  const sources = String(env.VULN_SOURCES ?? 'osv,nvd,euvd,kev').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return {
    enabled: (env.VULN_LOOKUP || 'on').toLowerCase() !== 'off',
    sources: new Set(sources),
    nvdKey: env.NVD_API_KEY || '',
    osvApi: env.OSV_API || 'https://api.osv.dev',
    nvdApi: env.NVD_API || 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    euvdApi: env.EUVD_API || 'https://euvdservices.enisa.europa.eu/api',
    kevUrl: env.KEV_URL || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    timeoutMs: Number(env.VULN_TIMEOUT_MS || 30000),
    euvdMax: Number(env.EUVD_MAX_LOOKUPS || 300),
    nvdMax: Number(env.NVD_MAX_LOOKUPS || 200),
  };
}

const DAY = 86_400_000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchJson(url, opts = {}, { timeoutMs = 30000, retries = 2 } = {}) {
  for (let attempt = 0; ; attempt++) {
    let res;
    try {
      res = await fetch(url, { ...opts, headers: { accept: 'application/json', 'user-agent': 'cra-risk-assessment', ...(opts.headers || {}) }, signal: AbortSignal.timeout(timeoutMs) });
    } catch (e) {
      if (attempt >= retries) throw new Error(`${new URL(url).host}: ${e.name === 'TimeoutError' ? 'timeout' : e.message}`);
      await sleep(1000 * (attempt + 1));
      continue;
    }
    if (res.ok) return res.json();
    if (res.status === 404) return null;
    if ((res.status === 429 || res.status >= 500) && attempt < retries) { await sleep(Number(res.headers.get('retry-after')) * 1000 || 2000 * (attempt + 1)); continue; }
    throw new Error(`${new URL(url).host}: HTTP ${res.status}`);
  }
}

async function pool(items, size, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}

// ------------------------------------------------------------------ CVSS
const roundUp = (x) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
export function cvss3Score(vector) {
  const m = Object.fromEntries(String(vector || '').split('/').slice(1).map((p) => p.split(':')));
  if (!/^CVSS:3\.[01]\//.test(vector || '') || !m.AV) return null;
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV], AC = { L: 0.77, H: 0.44 }[m.AC], UI = { N: 0.85, R: 0.62 }[m.UI];
  const changed = m.S === 'C';
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const cia = (v) => ({ H: 0.56, L: 0.22, N: 0 }[v]);
  const [C, I, A] = [cia(m.C), cia(m.I), cia(m.A)];
  if ([AV, AC, UI, PR, C, I, A].some((v) => v === undefined)) return null;
  const iss = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * AV * AC * PR * UI;
  if (impact <= 0) return 0;
  return roundUp(Math.min((changed ? 1.08 : 1) * (impact + expl), 10));
}
export function severityOf(score) {
  if (score == null) return 'unknown';
  if (score === 0) return 'none';
  return score < 4 ? 'low' : score < 7 ? 'medium' : score < 9 ? 'high' : 'critical';
}
const normSeverity = (s) => ({ moderate: 'medium', important: 'high' }[String(s || '').toLowerCase()] || String(s || 'unknown').toLowerCase());

const canonicalId = (id, aliases = []) => [id, ...aliases].find((x) => /^CVE-\d{4}-\d+$/.test(x)) || id;

// ------------------------------------------------------------------ OSV
async function osvLookup(packages, cfg, store, log) {
  const withPurl = packages.filter((p) => p.purl && p.version !== undefined);
  const hits = []; // {pkg, id}
  for (let i = 0; i < withPurl.length; i += 500) {
    const chunk = withPurl.slice(i, i + 500);
    const res = await fetchJson(`${cfg.osvApi}/v1/querybatch`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries: chunk.map((p) => ({ package: { purl: purlWithVersion(p) } })) }) }, { timeoutMs: cfg.timeoutMs });
    (res?.results || []).forEach((r, k) => { for (const v of r.vulns || []) hits.push({ pkg: chunk[k], id: v.id }); });
  }
  const ids = [...new Set(hits.map((h) => h.id))];
  const details = new Map();
  await pool(ids, 8, async (id) => {
    let d = await store.cacheGet(`osv:${id}`, DAY);
    if (!d) {
      try { d = await fetchJson(`${cfg.osvApi}/v1/vulns/${encodeURIComponent(id)}`, {}, { timeoutMs: cfg.timeoutMs }); if (d) await store.cacheSet(`osv:${id}`, d); } catch (e) { log.push(`OSV ${id}: ${e.message}`); }
    }
    if (d) details.set(id, d);
  });
  return hits.map(({ pkg, id }) => {
    const d = details.get(id) || { id, aliases: [] };
    const vector = (d.severity || []).find((s) => /^CVSS_V3/.test(s.type))?.score;
    const score = cvss3Score(vector);
    const fixed = [];
    for (const a of d.affected || []) for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixed.push(e.fixed);
    return {
      pkg, vulnId: canonicalId(d.id || id, d.aliases), aliases: [...new Set([d.id || id, ...(d.aliases || [])])],
      summary: d.summary || (d.details || '').slice(0, 300), score,
      severity: score != null ? severityOf(score) : normSeverity(d.database_specific?.severity),
      info: { vector: vector || '', fixed: [...new Set(fixed)].slice(0, 10), published: d.published || '', cwe: d.database_specific?.cwe_ids || [],
        references: (d.references || []).slice(0, 8).map((r) => r.url), osvId: d.id || id },
      source: 'OSV',
    };
  });
}
function purlWithVersion(p) {
  if (/@[^/]+$/.test(p.purl.split('?')[0])) return p.purl;
  const [base, qs] = p.purl.split('?');
  return `${base}@${encodeURIComponent(p.version)}${qs ? `?${qs}` : ''}`;
}

// ------------------------------------------------------------------ NVD
async function nvdLookup(packages, cfg, store, log) {
  const targets = packages.filter((p) => p.cpe).slice(0, cfg.nvdMax);
  if (packages.filter((p) => p.cpe).length > cfg.nvdMax) log.push(`NVD: only the first ${cfg.nvdMax} packages with CPE were queried (NVD_MAX_LOOKUPS).`);
  const out = [];
  const delay = cfg.nvdKey ? 700 : 6500; // NVD: 50 resp. 5 requests per 30 s
  let first = true;
  for (const p of targets) {
    const cpe = p.cpe.startsWith('cpe:2.3:') ? p.cpe : null;
    if (!cpe) { log.push(`NVD: ${p.name} has a CPE 2.2 identifier – skipped.`); continue; }
    let data = await store.cacheGet(`nvd:${cpe}`, DAY);
    if (!data) {
      if (!first) await sleep(delay);
      first = false;
      try {
        data = await fetchJson(`${cfg.nvdApi}?virtualMatchString=${encodeURIComponent(cpe)}&resultsPerPage=200`, { headers: cfg.nvdKey ? { apiKey: cfg.nvdKey } : {} }, { timeoutMs: cfg.timeoutMs });
        data = (data?.vulnerabilities || []).map((v) => v.cve).map((c) => {
          const m = c.metrics || {};
          const metric = (m.cvssMetricV40 || m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
          return { id: c.id, published: c.published, summary: (c.descriptions || []).find((d) => d.lang === 'en')?.value || '',
            score: metric?.cvssData?.baseScore ?? null, severity: metric?.cvssData?.baseSeverity || metric?.baseSeverity || '', vector: metric?.cvssData?.vectorString || '',
            cwe: (c.weaknesses || []).flatMap((w) => w.description.map((d) => d.value)).filter((x) => x.startsWith('CWE')), refs: (c.references || []).slice(0, 8).map((r) => r.url) };
        });
        await store.cacheSet(`nvd:${cpe}`, data);
      } catch (e) { log.push(`NVD ${p.name}: ${e.message}`); continue; }
    }
    for (const c of data) {
      out.push({ pkg: p, vulnId: c.id, aliases: [c.id], summary: c.summary.slice(0, 300), score: c.score, severity: c.score != null ? severityOf(c.score) : normSeverity(c.severity),
        info: { vector: c.vector, published: c.published, cwe: c.cwe, references: c.refs, fixed: [] }, source: 'NVD' });
    }
  }
  return out;
}

// ------------------------------------------------------------------ KEV & EUVD enrichment
async function exploitedSet(cfg, store, log) {
  const set = new Set();
  if (cfg.sources.has('kev')) {
    let ids = await store.cacheGet('kev:cisa', DAY);
    if (!ids) {
      try { const d = await fetchJson(cfg.kevUrl, {}, { timeoutMs: cfg.timeoutMs }); ids = (d?.vulnerabilities || []).map((v) => v.cveID); await store.cacheSet('kev:cisa', ids); } catch (e) { log.push(`CISA KEV: ${e.message}`); ids = []; }
    }
    ids.forEach((x) => set.add(x));
  }
  if (cfg.sources.has('euvd')) {
    let ids = await store.cacheGet('kev:euvd', DAY);
    if (!ids) {
      try { const d = await fetchJson(`${cfg.euvdApi}/kev/dump`, {}, { timeoutMs: cfg.timeoutMs }); ids = (Array.isArray(d) ? d : []).map((v) => v.cveId).filter(Boolean); await store.cacheSet('kev:euvd', ids); } catch (e) { log.push(`EUVD exploited list: ${e.message}`); ids = []; }
    }
    ids.forEach((x) => set.add(x));
  }
  return set;
}

async function euvdInfo(cves, cfg, store, log) {
  const out = new Map();
  if (!cfg.sources.has('euvd')) return out;
  const list = [...new Set(cves)];
  if (list.length > cfg.euvdMax) log.push(`EUVD: only ${cfg.euvdMax} of ${list.length} CVEs enriched (EUVD_MAX_LOOKUPS).`);
  await pool(list.slice(0, cfg.euvdMax), 4, async (cve) => {
    let d = await store.cacheGet(`euvd:${cve}`, 7 * DAY);
    if (!d) {
      try {
        const r = await fetchJson(`${cfg.euvdApi}/enisaid?id=${encodeURIComponent(cve)}`, {}, { timeoutMs: cfg.timeoutMs });
        d = r ? { id: r.id, epss: typeof r.epss === 'number' ? r.epss : null, baseScore: r.baseScore ?? null } : { id: null };
        await store.cacheSet(`euvd:${cve}`, d);
      } catch (e) { log.push(`EUVD ${cve}: ${e.message}`); return; }
    }
    out.set(cve, d);
  });
  return out;
}

/** Applies the KEV flag and EUVD data to a list of normalized findings (in place). */
export async function enrich(findings, cfg, store, log = []) {
  if (!cfg.enabled) return log;
  const kev = await exploitedSet(cfg, store, log);
  const cves = findings.flatMap((f) => [f.vulnId, ...(f.aliases || [])]).filter((x) => /^CVE-/.test(x));
  const euvd = await euvdInfo(cves, cfg, store, log);
  for (const f of findings) {
    const ids = [f.vulnId, ...(f.aliases || [])];
    f.kev = ids.some((x) => kev.has(x));
    const e = ids.map((x) => euvd.get(x)).find(Boolean);
    if (e?.id) { f.euvdId = e.id; if (!f.aliases.includes(e.id)) f.aliases.push(e.id); }
    if (e?.epss != null) f.epss = e.epss;
    if (f.score == null && e?.baseScore != null) { f.score = e.baseScore; f.severity = severityOf(e.baseScore); }
  }
  return log;
}

// ------------------------------------------------------------------ scan
/** Looks up all packages of one SBOM. Returns normalized findings ready for store.mergeFindings. */
export async function scanPackages(packages, cfg, store) {
  if (!cfg.enabled) throw new Error('Online vulnerability lookup is disabled on this server (VULN_LOOKUP=off). Import scanner results instead.');
  const log = [];
  const raw = [];
  if (cfg.sources.has('osv')) {
    try { raw.push(...await osvLookup(packages, cfg, store, log)); } catch (e) { log.push(`OSV: ${e.message}`); }
  }
  if (cfg.sources.has('nvd')) raw.push(...await nvdLookup(packages, cfg, store, log));
  // merge OSV + NVD hits for the same package and vulnerability
  const merged = new Map();
  for (const h of raw) {
    const key = `${packageKey(h.pkg)}|${h.vulnId}`;
    const cur = merged.get(key);
    if (!cur) {
      merged.set(key, { vulnId: h.vulnId, pkgKey: packageKey(h.pkg), pkgName: h.pkg.name, pkgVersion: h.pkg.version, purl: h.pkg.purl || '',
        aliases: [...h.aliases], summary: h.summary, score: h.score, severity: h.severity, info: h.info, sources: [h.source], kev: false });
    } else {
      cur.aliases = [...new Set([...cur.aliases, ...h.aliases])];
      if (!cur.sources.includes(h.source)) cur.sources.push(h.source);
      if (cur.score == null && h.score != null) { cur.score = h.score; cur.severity = h.severity; }
      if (!cur.summary) cur.summary = h.summary;
      cur.info.fixed = [...new Set([...(cur.info.fixed || []), ...(h.info.fixed || [])])];
    }
  }
  const findings = [...merged.values()];
  await enrich(findings, cfg, store, log);
  return {
    findings,
    summary: { packages: packages.length, queriedOsv: cfg.sources.has('osv') ? packages.filter((p) => p.purl).length : 0, queriedNvd: cfg.sources.has('nvd') ? Math.min(packages.filter((p) => p.cpe).length, cfg.nvdMax) : 0,
      unidentified: packages.filter((p) => !p.purl && !p.cpe).length, findings: findings.length, kev: findings.filter((f) => f.kev).length, messages: log.slice(0, 50) },
  };
}

// ------------------------------------------------------------------ import of scanner output
const CDX_STATE = new Set(['resolved', 'resolved_with_pedigree', 'exploitable', 'in_triage', 'false_positive', 'not_affected']);

export function parseVulnReport(buffer) {
  let doc;
  try { doc = JSON.parse(buffer.toString('utf8').replace(/^﻿/, '')); } catch { throw new Error('The file is not valid JSON.'); }
  const out = [];
  const add = (f) => {
    const score = f.score != null ? Number(f.score) : null;
    out.push({ vulnId: canonicalId(f.id, f.aliases), aliases: [...new Set([f.id, ...(f.aliases || [])])], pkgName: f.name || '', pkgVersion: f.version || '', purl: f.purl || '',
      pkgKey: packageKey({ purl: f.purl, name: f.name || '', version: f.version || '' }), summary: (f.summary || '').slice(0, 300), score,
      severity: score != null ? severityOf(score) : normSeverity(f.severity), info: { fixed: f.fixed || [], vector: f.vector || '', references: f.references || [] },
      sources: [f.source], kev: false, state: f.state, justification: f.justification, response: f.response, analysis: f.analysis });
  };
  if (doc.bomFormat === 'CycloneDX' && Array.isArray(doc.vulnerabilities)) {
    const comps = new Map();
    const walk = (l) => (l || []).forEach((c) => { comps.set(c['bom-ref'], c); walk(c.components); });
    walk(doc.components);
    for (const v of doc.vulnerabilities) {
      const rating = (v.ratings || []).sort((a, b) => (b.score || 0) - (a.score || 0))[0] || {};
      for (const a of v.affects || [{ ref: '' }]) {
        const ref = String(a.ref || '').split('#').pop();
        const c = comps.get(ref) || comps.get(a.ref) || {};
        const purl = c.purl || (String(a.ref).startsWith('pkg:') ? a.ref : '');
        add({ id: v.id, aliases: (v.references || []).map((r) => r.id).filter(Boolean), name: c.group ? `${c.group}/${c.name}` : c.name || ref, version: c.version || '', purl,
          summary: v.description || v.detail || '', score: rating.score ?? null, severity: rating.severity, vector: rating.vector,
          fixed: [], source: v.source?.name ? `Import: ${v.source.name}` : 'Import: CycloneDX',
          state: CDX_STATE.has(v.analysis?.state) ? v.analysis.state : undefined, justification: v.analysis?.justification, response: (v.analysis?.response || [])[0], analysis: v.analysis?.detail });
      }
    }
    return { format: 'CycloneDX VEX / vulnerabilities', findings: out };
  }
  if (Array.isArray(doc.results) && doc.results.some((r) => Array.isArray(r.packages))) {      // OSV-Scanner
    for (const r of doc.results) for (const p of r.packages || []) for (const v of p.vulnerabilities || []) {
      const vector = (v.severity || []).find((s) => /^CVSS_V3/.test(s.type))?.score;
      add({ id: v.id, aliases: v.aliases, name: p.package?.name, version: p.package?.version, purl: p.package?.purl || '', summary: v.summary || v.details,
        score: cvss3Score(vector), severity: v.database_specific?.severity, vector, source: 'Import: OSV-Scanner' });
    }
    return { format: 'OSV-Scanner JSON', findings: out };
  }
  if (Array.isArray(doc.matches)) {                                                             // Grype
    for (const m of doc.matches) {
      const v = m.vulnerability || {};
      const score = (v.cvss || []).map((c) => c.metrics?.baseScore).filter((s) => s != null).sort((a, b) => b - a)[0] ?? null;
      add({ id: v.id, aliases: (m.relatedVulnerabilities || []).map((r) => r.id), name: m.artifact?.name, version: m.artifact?.version, purl: m.artifact?.purl || '',
        summary: v.description, score, severity: v.severity, fixed: v.fix?.versions || [], source: 'Import: Grype' });
    }
    return { format: 'Grype JSON', findings: out };
  }
  if (Array.isArray(doc.Results)) {                                                             // Trivy
    for (const r of doc.Results) for (const v of r.Vulnerabilities || []) {
      const score = v.CVSS ? Math.max(...Object.values(v.CVSS).map((c) => c.V3Score || 0)) || null : null;
      add({ id: v.VulnerabilityID, aliases: [], name: v.PkgName, version: v.InstalledVersion, purl: v.PkgIdentifier?.PURL || '', summary: v.Title || v.Description,
        score, severity: v.Severity, fixed: v.FixedVersion ? [v.FixedVersion] : [], source: 'Import: Trivy' });
    }
    return { format: 'Trivy JSON', findings: out };
  }
  throw new Error('Unknown format. Supported: CycloneDX with vulnerabilities (VEX), OSV-Scanner JSON, Grype JSON, Trivy JSON.');
}

// ------------------------------------------------------------------ CycloneDX VEX export
export function toCycloneDxVex({ product, component, findings, serial }) {
  const refOf = (f) => f.purl || `pkg:generic/${encodeURIComponent(f.pkgName)}@${encodeURIComponent(f.pkgVersion)}`;
  const comps = new Map();
  for (const f of findings) comps.set(refOf(f), { type: 'library', 'bom-ref': refOf(f), name: f.pkgName, version: f.pkgVersion, ...(f.purl ? { purl: f.purl } : {}) });
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${serial}`, version: 1,
    metadata: { timestamp: new Date().toISOString(), tools: { components: [{ type: 'application', name: 'cra-risk-assessment' }] },
      component: { type: 'application', name: `${product.name}${component ? ` – ${component.name}` : ''}`, version: component?.version || '' } },
    components: [...comps.values()],
    vulnerabilities: findings.map((f) => ({
      id: f.vulnId,
      ...(f.vulnId.startsWith('CVE-') ? { source: { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${f.vulnId}` } } : {}),
      references: f.aliases.filter((x) => x !== f.vulnId).map((id) => ({ id, source: { name: id.startsWith('GHSA') ? 'GitHub' : id.startsWith('EUVD') ? 'ENISA EUVD' : 'OSV' } })),
      ...(f.score != null ? { ratings: [{ score: f.score, severity: f.severity, method: f.info?.vector?.startsWith('CVSS:3.1') ? 'CVSSv31' : 'other', ...(f.info?.vector ? { vector: f.info.vector } : {}) }] } : {}),
      description: f.summary || undefined,
      analysis: { state: f.state, ...(f.justification ? { justification: f.justification } : {}), ...(f.response ? { response: [f.response] } : {}), ...(f.analysis ? { detail: f.analysis } : {}) },
      affects: [{ ref: refOf(f) }],
    })),
  };
}
