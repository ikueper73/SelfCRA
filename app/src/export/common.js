import { createHash } from 'node:crypto';

// Deterministic JSON (sorted keys) so a frozen version always hashes the same.
export function canonicalJson(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
  }
  return JSON.stringify(value ?? null);
}

export const sha256 = (data) => createHash('sha256').update(canonicalJson(data)).digest('hex');

export const join = (v) => (Array.isArray(v) ? v.join(', ') : String(v ?? ''));

export function safeFilename(s) {
  return String(s || 'assessment').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 80) || 'assessment';
}

// Describes which document is being exported (live draft vs. frozen snapshot).
export function docControl(record, snapshot) {
  const a = snapshot ? snapshot.data : record.data;
  return {
    data: a,
    frozen: !!snapshot,
    version: snapshot ? snapshot.version : a.meta.version,
    sha256: snapshot ? snapshot.sha256 : sha256(a),
    frozenAt: snapshot?.createdAt || '',
    frozenBy: snapshot?.createdBy || '',
    note: snapshot?.note || '',
    exportedAt: new Date().toISOString(),
    assessmentId: record.id,
  };
}
