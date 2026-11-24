import { test } from 'node:test';
import assert from 'node:assert/strict';
import { newAssessment, evaluate, rate, scoreRisk, newRisk, nextId, classificationResult, presetFor } from '../src/shared/model.js';
import { THREAT_LIBRARY } from '../src/shared/catalog.js';
import { sha256 } from '../src/export/common.js';

test('preset follows markets', () => {
  assert.equal(presetFor(['consumer']), 'consumer');
  assert.equal(presetFor(['professional']), 'professional');
  assert.equal(presetFor(['consumer', 'professional']), 'combined');
  const a = newAssessment({ markets: ['consumer', 'professional'] });
  assert.equal(a.method.preset, 'combined');
  assert.deepEqual(a.profile.standards, { en18031: true, en303645: true, iec62443: true });
});

test('rating thresholds match the template (16/10/5/1)', () => {
  const t = newAssessment().method.thresholds;
  assert.equal(rate(16, t), 'Critical');
  assert.equal(rate(15, t), 'High');
  assert.equal(rate(10, t), 'High');
  assert.equal(rate(9, t), 'Medium');
  assert.equal(rate(5, t), 'Medium');
  assert.equal(rate(4, t), 'Low');
  assert.equal(rate(null, t), '');
});

test('risk scoring ignores out-of-range values', () => {
  const m = newAssessment().method;
  assert.deepEqual(scoreRisk({ inherentL: '4', inherentI: 5, residualL: 2, residualI: 3 }, m),
    { inherentScore: 20, inherentRating: 'Critical', residualScore: 6, residualRating: 'Medium' });
  assert.equal(scoreRisk({ inherentL: 7, inherentI: 1 }, m).inherentScore, null);
});

test('IDs increment', () => {
  assert.equal(nextId('R-', [{ id: 'R-009' }, { id: 'R-002' }]), 'R-010');
  assert.equal(nextId('A-', []), 'A-01');
});

test('new risk from library copies mappings without sharing arrays', () => {
  const a = newAssessment();
  const r = newRisk(a, THREAT_LIBRARY[0]);
  r.annex.push('X');
  assert.ok(!THREAT_LIBRARY[0].annex.includes('X'));
  assert.equal(r.source, THREAT_LIBRARY[0].id);
});

test('residual critical and unjustified "No" are blocking', () => {
  const a = newAssessment();
  a.risks.push({ ...newRisk(a), scenario: 's', inherentL: 5, inherentI: 5, residualL: 4, residualI: 4, annex: ['P1-2d'] });
  a.annexI['P1-2g'].applicable = 'No';
  a.annexI['P1-2d'].applicable = 'Yes';
  const ev = evaluate(a);
  assert.ok(ev.findings.some((f) => f.level === 'blocker' && f.message.includes('Critical')));
  assert.ok(ev.findings.some((f) => f.level === 'blocker' && f.message.startsWith('P1-2g: MISSING JUSTIFICATION')));
  assert.equal(ev.annex['P1-2d'].status, 'Covered by 1 risk(s)');
  a.annexI['P1-2g'].justification = 'No data processed beyond telemetry.';
  assert.equal(evaluate(a).annex['P1-2g'].status, 'Not applicable – justified');
});

test('support period below five years needs a justification', () => {
  const a = newAssessment();
  a.supportPeriod.years = '3';
  assert.ok(evaluate(a).findings.some((f) => f.step === 'support' && f.level === 'blocker' && f.message.includes('below 5 years')));
  a.supportPeriod.rationale = 'Expected use 3 years (consumable product).';
  assert.ok(!evaluate(a).findings.some((f) => f.step === 'support' && f.level === 'blocker'));
});

test('enabled-but-unneeded interface is flagged', () => {
  const a = newAssessment();
  a.interfaces.push({ id: 'I-01', name: 'Debug', exposure: 'Physical access to device', defaultState: 'Enabled', needed: 'No', protection: 'none' });
  assert.ok(evaluate(a).findings.some((f) => f.message.startsWith('I-01: enabled by default but not needed')));
});

test('classification picks the highest category', () => {
  const a = newAssessment();
  a.classification.selected['important1:11'] = true;
  assert.equal(classificationResult(a).category, 'important1');
  a.classification.selected['critical:2'] = true;
  assert.equal(classificationResult(a).category, 'critical');
});

test('EN 303 645 provision references count for their clause', () => {
  const a = newAssessment({ markets: ['consumer'] });
  a.risks.push({ ...newRisk(a), en303645: ['5.1-1'] });
  a.en303645['5.1'].applicable = 'Yes';
  a.en303645['5.10'].applicable = 'Yes';
  assert.equal(evaluate(a).en303645['5.2'].status, 'NOT ASSESSED', 'linked risks do not replace an applicability decision');
  assert.equal(evaluate(a).en303645['5.1'].status, 'Covered by 1 risk(s)');
  assert.equal(evaluate(a).en303645['5.10'].status, 'GAP');
});

test('hash is independent of key order', () => {
  assert.equal(sha256({ a: 1, b: { c: 2, d: [1, 2] } }), sha256({ b: { d: [1, 2], c: 2 }, a: 1 }));
  assert.notEqual(sha256({ a: 1 }), sha256({ a: 2 }));
});

test('STRIDE matrix: derived coverage, manual links and justified N/A', async () => {
  const { strideStatus, strideTargets } = await import('../src/shared/model.js');
  const a = newAssessment();
  a.components.push({ id: 'Z-1', name: 'Gateway', scope: 'Product (hardware/firmware)' }, { id: 'Z-9', name: 'Customer SCADA', scope: 'Out of scope - customer/3rd party' });
  a.interfaces.push({ id: 'C-1', name: 'Cloud link' });
  assert.deepEqual(strideTargets(a).map((t) => t.id), ['Z-1', 'C-1'], 'out-of-scope components are not swept');
  a.risks.push({ ...newRisk(a), id: 'R-001', interfaces: 'Z-1 / C-1', stride: 'T - Tampering' });
  a.risks.push({ ...newRisk(a), id: 'R-002', interfaces: 'C-1', stride: 'I - Information disclosure' });
  a.stride = { 'C-1': { S: { refs: ['R-002'] }, R: { na: true, justification: '' }, D: { na: true, justification: 'Covered by local autonomy.' } } };
  const st = strideStatus(a);
  assert.deepEqual(st['Z-1'].T, { status: 'covered', risks: ['R-001'], justification: '' });
  assert.equal(st['C-1'].S.status, 'covered');
  assert.equal(st['C-1'].R.status, 'na-missing');
  assert.equal(st['C-1'].D.status, 'na');
  assert.equal(st['C-1'].E.status, 'open');
  a.stride['C-1'].S.refs = ['R-999'];
  assert.equal(strideStatus(a)['C-1'].S.status, 'open', 'links to deleted risks do not count');
  const f = evaluate(a).findings.filter((x) => x.step === 'stride');
  assert.ok(f.some((x) => x.message.startsWith('C-1') && x.message.includes('S, E')));
  assert.ok(f.some((x) => x.message.includes('without justification for R')));
});

test('diagram graph: components, external parties and flows', async () => {
  const { threatModelGraph, diagramSvg } = await import('../src/shared/diagram.js');
  const a = newAssessment();
  a.components.push({ id: 'Z-1', name: 'Device <&>', scope: 'Product (hardware/firmware)' }, { id: 'Z-2', name: 'Cloud', scope: 'Remote data processing (RDPS)' });
  a.interfaces.push(
    { id: 'I-01', name: 'Uplink', from: 'Z-1', to: 'Z-2' },
    { id: 'I-02', name: 'Debug', from: 'Z-1', to: '', exposure: 'Physical access to device' },
    { id: 'I-03', name: 'Portal', from: 'Technician laptop', to: 'Z-2' },
    { id: 'I-04', name: 'Nowhere' });
  const g = threatModelGraph(a);
  assert.deepEqual(g.nodes.filter((n) => n.kind === 'ext').map((n) => n.label).sort(), ['Physical access to device', 'Technician laptop']);
  assert.deepEqual(g.edges.find((e) => e.id === 'I-02'), { id: 'I-02', label: 'Debug', src: 'ext:Physical access to device', dst: 'Z-1', status: g.edges.find((e) => e.id === 'I-02').status });
  assert.deepEqual(g.unplaced, ['I-04']);
  const svg = diagramSvg(a);
  assert.ok(svg.startsWith('<svg') && svg.includes('Device &lt;&amp;&gt;'), 'text is escaped');
  assert.ok(!svg.includes('<&>'));
});

test('tutorial: worked interface I-03 is fully decided and consistent', async () => {
  const { tutorialAssessment, WALKTHROUGH } = await import('../src/shared/tutorial.js');
  const a = tutorialAssessment();
  const ev = evaluate(a);
  assert.ok(Object.values(ev.stride['I-03']).every((c) => ['covered', 'na'].includes(c.status)));
  assert.deepEqual(Object.fromEntries(Object.entries(ev.stride['I-03']).map(([k, v]) => [k, v.status === 'na' ? 'na' : 'risk'])),
    Object.fromEntries(WALKTHROUGH.rows.map((r) => [r.letter, r.decision])), 'matrix matches the walkthrough text');
  const r2 = ev.risks.find((r) => r.id === 'R-002');
  assert.equal(r2.inherentScore, 12); assert.equal(r2.inherentRating, 'High'); assert.equal(r2.residualRating, 'Low');
  assert.ok(!ev.findings.some((f) => f.step === 'risks' && f.message.includes('unknown')));
});

test('diagram: hand-placed positions override auto layout and are clamped', async () => {
  const { diagramSvg } = await import('../src/shared/diagram.js');
  const a = newAssessment();
  a.components.push({ id: 'Z-1', name: 'A', scope: 'Product (software/app)' }, { id: 'Z-2', name: 'B', scope: 'Product (software/app)' });
  a.interfaces.push({ id: 'I-01', from: 'Z-1', to: 'Z-2' });
  a.diagram.positions = { 'Z-2': { x: 900, y: 600 }, 'Z-1': { x: -50, y: 10 } };
  const svg = diagramSvg(a, { interactive: true });
  assert.match(svg, /data-node="Z-2" data-x="900" data-y="600"/);
  assert.match(svg, /data-node="Z-1" data-x="34" data-y="34"/, 'clamped to the padding');
  const width = Number(svg.match(/^<svg[^>]* width="(\d+(\.\d+)?)"/)[1]);
  assert.ok(width >= 900 + 176, 'canvas grows to include the moved box');
  assert.ok(!diagramSvg(a).includes('data-node'), 'export SVG carries no editor attributes');
});
