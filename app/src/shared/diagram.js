// Threat-model data-flow diagram generated from the architecture data.
// Pure function returning an SVG string; used in the browser, the PDF export and the SVG download.
// Only presentation attributes are used (no CSS) so pdfmake/svg-to-pdfkit renders it identically.
import { strideStatus } from './model.js';

const W = 176, H = 66, COL = 350, ROW = 140, PAD = 34, LEGEND = 92;
export const DIAGRAM = { W, H, PAD, GRID: 10 };
const COLORS = {   // Fluent 2 palette (webLightTheme)
  navy: '#0F6CBD', text: '#242424', muted: '#616161', boundary: '#C50F1F',
  comp: '#EBF3FC', ext: '#F5F5F5', out: '#FFFFFF', ok: '#0E700E', okBg: '#F1FAF1', warn: '#BC4B09', warnBg: '#FFF9F5',
};

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const cut = (s, n) => (String(s || '').length > n ? String(s).slice(0, n - 1) + '…' : String(s || ''));

function summary(cells) {
  const vals = Object.values(cells || {});
  const open = vals.filter((c) => c.status === 'open' || c.status === 'na-missing').length;
  return { open, done: vals.length - open, total: vals.length };
}

// Build the graph: components, external entities (entry points without a component on the other side) and flows.
export function threatModelGraph(a, stride = strideStatus(a)) {
  const compIds = new Set(a.components.map((c) => c.id));
  const nodes = new Map();
  for (const c of a.components) {
    if (!c.id) continue;
    const out = /^Out of scope/i.test(c.scope || '');
    nodes.set(c.id, { id: c.id, label: c.name || c.id, sub: out ? 'outside scope' : (c.scope || '').replace(/^Product \((.*)\)$/, 'product – $1'), kind: out ? 'out' : 'comp', status: out ? null : summary(stride[c.id]) });
  }
  const external = (name) => {
    const key = `ext:${name}`;
    if (!nodes.has(key)) nodes.set(key, { id: key, label: name, sub: 'external entity', kind: 'ext' });
    return key;
  };
  const edges = [];
  const unplaced = [];
  for (const i of a.interfaces) {
    if (!i.id) continue;
    const from = String(i.from || '').trim(), to = String(i.to || '').trim();
    let src, dst;
    const resolve = (v) => (compIds.has(v) ? v : v ? external(v) : null);
    if (from && to) { src = resolve(from); dst = resolve(to); }
    else if (from || to) {
      const known = resolve(from || to);
      const outside = external(i.exposure || 'External');
      // the outside party connects to the element that exposes the interface
      [src, dst] = [outside, known];
    } else { unplaced.push(i.id); continue; }
    edges.push({ id: i.id, label: i.name || '', src, dst, status: summary(stride[i.id]) });
  }
  return { nodes: [...nodes.values()], edges, unplaced };
}

function layout(graph, manual = {}) {
  const adj = new Map(graph.nodes.map((n) => [n.id, new Set()]));
  for (const e of graph.edges) { adj.get(e.src)?.add(e.dst); adj.get(e.dst)?.add(e.src); }
  const rank = new Map();
  const queue = graph.nodes.filter((n) => n.kind === 'ext').map((n) => n.id);
  if (!queue.length && graph.nodes.length) queue.push(graph.nodes[0].id);
  for (const id of queue) rank.set(id, 0);
  while (queue.length) {
    const id = queue.shift();
    for (const nb of adj.get(id) || []) if (!rank.has(nb)) { rank.set(nb, rank.get(id) + 1); queue.push(nb); }
  }
  const maxRank = Math.max(0, ...rank.values());
  for (const n of graph.nodes) if (!rank.has(n.id)) rank.set(n.id, n.kind === 'ext' ? 0 : maxRank + 1);
  const cols = [];
  for (const n of graph.nodes) (cols[rank.get(n.id)] ||= []).push(n);
  const dense = cols.filter(Boolean);
  // barycenter ordering: sort each column by the mean position of its neighbours in adjacent columns
  const order = new Map();
  dense.forEach((col) => col.forEach((n, i) => order.set(n.id, i)));
  for (let pass = 0; pass < 4; pass++) {
    for (const col of pass % 2 ? [...dense].reverse() : dense) {
      const bary = (n) => {
        const nb = [...(adj.get(n.id) || [])].filter((x) => rank.get(x) !== rank.get(n.id));
        return nb.length ? nb.reduce((sum, x) => sum + order.get(x), 0) / nb.length : order.get(n.id);
      };
      col.sort((x, y) => bary(x) - bary(y) || order.get(x.id) - order.get(y.id));
      col.forEach((n, i) => order.set(n.id, i));
    }
  }
  const rows = Math.max(1, ...dense.map((c) => c.length));
  const pos = new Map();
  dense.forEach((col, ci) => {
    const offset = ((rows - col.length) * ROW) / 2;
    col.forEach((n, ri) => pos.set(n.id, { x: PAD + ci * COL, y: PAD + offset + ri * ROW }));
  });
  // hand-placed boxes override the automatic layout (positions are top-left corners, never above / left of PAD)
  let manualCount = 0;
  for (const n of graph.nodes) {
    const m = manual[n.id];
    if (m && Number.isFinite(m.x) && Number.isFinite(m.y)) { pos.set(n.id, { x: Math.max(PAD, m.x), y: Math.max(PAD, m.y), manual: true }); manualCount++; }
  }
  let maxX = 0, maxY = 0;
  for (const p of pos.values()) { maxX = Math.max(maxX, p.x); maxY = Math.max(maxY, p.y); }
  return { pos, manualCount, width: maxX + W + PAD, height: maxY + H + PAD };
}

// Point where the line from the box centre towards (tx, ty) leaves the (slightly enlarged) box.
function exit(p, tx, ty, grow = 8) {
  const cx = p.x + W / 2, cy = p.y + H / 2;
  const dx = tx - cx, dy = ty - cy;
  if (!dx && !dy) return { x: cx, y: cy };
  const hw = W / 2 + grow, hh = H / 2 + grow;
  const s = Math.min(dx ? hw / Math.abs(dx) : Infinity, dy ? hh / Math.abs(dy) : Infinity);
  return { x: cx + dx * s, y: cy + dy * s };
}

export function diagramSvg(a, { stride, title = 'Threat model – data-flow diagram', interactive = false } = {}) {
  const graph = threatModelGraph(a, stride);
  if (!graph.nodes.length) {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="520" height="60" viewBox="0 0 520 60"><text x="10" y="35" font-family="Roboto, sans-serif" font-size="13" fill="${COLORS.muted}">No components or interfaces defined yet.</text></svg>`;
  }
  const { pos, width: w0, height: h0 } = layout(graph, a.diagram?.positions || {});
  const width = Math.max(w0, 720), height = h0 + LEGEND + 24;
  const out = [];
  const font = 'font-family="Segoe UI, Roboto, Helvetica, Arial, sans-serif"';
  out.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" ${font}>`);
  out.push(`<title>${esc(title)}</title><rect x="0" y="0" width="${width}" height="${height}" fill="#FFFFFF"/>`);

  // edges (drawn first so boxes sit on top)
  const pairCount = new Map();
  for (const e of graph.edges) { const k = [e.src, e.dst].sort().join('|'); pairCount.set(k, (pairCount.get(k) || 0) + 1); }
  const pairIdx = new Map();
  const labels = [];
  for (const e of graph.edges) {
    const A = pos.get(e.src), B = pos.get(e.dst);
    const k = [e.src, e.dst].sort().join('|');
    const n = pairCount.get(k), i = pairIdx.get(k) || 0;
    pairIdx.set(k, i + 1);
    const ax = A.x + W / 2, ay = A.y + H / 2, bx = B.x + W / 2, by = B.y + H / 2;
    const len = Math.hypot(bx - ax, by - ay) || 1;
    const sign = e.src < e.dst ? 1 : -1; // keep offsets stable for flows in opposite directions
    const off = (i - (n - 1) / 2) * 64 * sign;
    const cx = (ax + bx) / 2 + (-(by - ay) / len) * off, cy = (ay + by) / 2 + ((bx - ax) / len) * off;
    const p0 = exit(A, cx, cy), p2 = exit(B, cx, cy);
    const ok = e.status.open === 0;
    const col = ok ? COLORS.ok : COLORS.warn;
    out.push(`<path d="M${p0.x.toFixed(1)},${p0.y.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${p2.x.toFixed(1)},${p2.y.toFixed(1)}" fill="none" stroke="${col}" stroke-width="1.8"/>`);
    // arrow head
    const ang = Math.atan2(p2.y - cy, p2.x - cx);
    const ah = (d) => `${(p2.x - 10 * Math.cos(ang + d)).toFixed(1)},${(p2.y - 10 * Math.sin(ang + d)).toFixed(1)}`;
    out.push(`<polygon points="${p2.x.toFixed(1)},${p2.y.toFixed(1)} ${ah(0.42)} ${ah(-0.42)}" fill="${col}"/>`);
    const lx = 0.25 * p0.x + 0.5 * cx + 0.25 * p2.x, ly = 0.25 * p0.y + 0.5 * cy + 0.25 * p2.y;
    labels.push({ e, lx, ly, ok, col });
  }
  // nodes
  for (const nd of graph.nodes) {
    const p = pos.get(nd.id);
    const attrs = interactive
      ? ` data-node="${esc(nd.id)}" data-x="${p.x}" data-y="${p.y}"${nd.kind === 'comp' ? ` data-target="${esc(nd.id)}"` : ''} cursor="pointer"`
      : '';
    out.push(`<g${attrs}>`);
    if (nd.kind === 'comp') {
      // dashed red outline = trust boundary around the zone / component
      out.push(`<rect x="${p.x - 6}" y="${p.y - 6}" width="${W + 12}" height="${H + 12}" rx="10" fill="none" stroke="${COLORS.boundary}" stroke-width="1.2" stroke-dasharray="5,4"/>`);
      out.push(`<rect x="${p.x}" y="${p.y}" width="${W}" height="${H}" rx="8" fill="${COLORS.comp}" stroke="${COLORS.navy}" stroke-width="1.4"/>`);
    } else if (nd.kind === 'ext') {
      out.push(`<rect x="${p.x}" y="${p.y}" width="${W}" height="${H}" fill="${COLORS.ext}" stroke="${COLORS.muted}" stroke-width="1.4"/>`);
    } else {
      out.push(`<rect x="${p.x}" y="${p.y}" width="${W}" height="${H}" rx="8" fill="${COLORS.out}" stroke="${COLORS.muted}" stroke-width="1.2" stroke-dasharray="3,3"/>`);
    }
    const head = nd.kind === 'ext' ? cut(nd.label, 26) : `${nd.id}  ${cut(nd.label, 20)}`;
    out.push(`<text x="${p.x + W / 2}" y="${p.y + 22}" text-anchor="middle" font-size="12" font-weight="bold" fill="${nd.kind === 'comp' ? COLORS.navy : COLORS.text}">${esc(head)}</text>`);
    out.push(`<text x="${p.x + W / 2}" y="${p.y + 37}" text-anchor="middle" font-size="9.5" fill="${COLORS.muted}">${esc(cut(nd.sub, 32))}</text>`);
    if (nd.status) {
      const ok = nd.status.open === 0;
      out.push(`<text x="${p.x + W / 2}" y="${p.y + 55}" text-anchor="middle" font-size="10" font-weight="bold" fill="${ok ? COLORS.ok : COLORS.warn}">${esc(ok ? `STRIDE ${nd.status.done}/6 decided` : `STRIDE ${nd.status.open} open`)}</text>`);
    }
    out.push('</g>');
  }

  // place labels so they overlap neither boxes nor other labels: try the midpoint, then alternate up / down
  const rects = [...pos.values()].map((p) => ({ x: p.x - 8, y: p.y - 8, w: W + 16, h: H + 16 }));
  const hits = (r) => rects.some((o) => r.x < o.x + o.w && o.x < r.x + r.w && r.y < o.y + o.h && o.y < r.y + r.h);
  for (const L of [...labels].sort((x, y) => x.ly - y.ly)) {
    L.bw = Math.max(`${L.e.id}  00 open`.length * 6.4, cut(L.e.label, 26).length * 5.6) + 12;
    const at = (dy) => ({ x: L.lx - L.bw / 2 - 2, y: L.ly + dy - 17, w: L.bw + 4, h: 34 });
    const tries = [0];
    for (let k = 1; k <= 8; k++) tries.push(k * 18, -k * 18);
    const dy = tries.find((d) => !hits(at(d)));
    L.ly += dy ?? 0;
    rects.push(at(0));
  }
  for (const { e, lx, ly, ok, col } of labels) {
    const t1 = `${e.id}  ${ok ? `${e.status.done}/6` : `${e.status.open} open`}`;
    const t2 = cut(e.label, 26);
    const bw = Math.max(t1.length * 6.4, t2.length * 5.6) + 12;
    out.push(`<g${interactive ? ` data-target="${esc(e.id)}" cursor="pointer"` : ''}>`);
    out.push(`<rect x="${(lx - bw / 2).toFixed(1)}" y="${(ly - 15).toFixed(1)}" width="${bw.toFixed(1)}" height="${t2 ? 30 : 18}" rx="4" fill="${ok ? COLORS.okBg : COLORS.warnBg}" stroke="${col}" stroke-width="0.8"/>`);
    out.push(`<text x="${lx.toFixed(1)}" y="${(ly - 2).toFixed(1)}" text-anchor="middle" font-size="10.5" font-weight="bold" fill="${col}">${esc(t1)}</text>`);
    if (t2) out.push(`<text x="${lx.toFixed(1)}" y="${(ly + 10).toFixed(1)}" text-anchor="middle" font-size="9" fill="${COLORS.text}">${esc(t2)}</text>`);
    out.push('</g>');
  }

  // legend
  const ly = h0 + 14;
  out.push(`<line x1="${PAD}" y1="${ly}" x2="${width - PAD}" y2="${ly}" stroke="#DDE3EA"/>`);
  const item = (x, y, shape, text) => out.push(shape(x, y), `<text x="${x + 46}" y="${y + 13}" font-size="10.5" fill="${COLORS.text}">${esc(text)}</text>`);
  const L = ly + 14;
  item(PAD, L, (x, y) => `<rect x="${x}" y="${y}" width="36" height="20" rx="5" fill="${COLORS.comp}" stroke="${COLORS.navy}"/><rect x="${x - 3}" y="${y - 3}" width="42" height="26" rx="7" fill="none" stroke="${COLORS.boundary}" stroke-dasharray="4,3"/>`, 'Component / zone inside its trust boundary');
  item(PAD, L + 32, (x, y) => `<rect x="${x}" y="${y}" width="36" height="20" fill="${COLORS.ext}" stroke="${COLORS.muted}"/>`, 'External entity (user, attacker side, other system)');
  item(PAD + 330, L, (x, y) => `<line x1="${x}" y1="${y + 10}" x2="${x + 36}" y2="${y + 10}" stroke="${COLORS.ok}" stroke-width="2"/>`, 'Interface / data flow – all 6 STRIDE categories decided');
  item(PAD + 330, L + 32, (x, y) => `<line x1="${x}" y1="${y + 10}" x2="${x + 36}" y2="${y + 10}" stroke="${COLORS.warn}" stroke-width="2"/>`, 'Interface with open STRIDE decisions');
  if (graph.unplaced.length) out.push(`<text x="${PAD}" y="${L + 66}" font-size="10" fill="${COLORS.warn}">${esc(`Not drawn (no from / to component): ${graph.unplaced.join(', ')}`)}</text>`);
  out.push('</svg>');
  return out.join('');
}
