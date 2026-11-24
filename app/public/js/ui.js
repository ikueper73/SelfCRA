// Minimal DOM helpers (no framework, CSP-safe: no inline handlers or styles).

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export function clear(el, ...children) {
  el.replaceChildren();
  append(el, children);
  return el;
}

let uid = 0;
const nextId = () => `f${++uid}`;

// Bound form controls: write straight into `obj[key]` and call onChange.
export function field(obj, key, { label, help, type = 'text', options, rows = 3, placeholder, onChange, wide, required, cls } = {}) {
  const id = nextId();
  let input;
  const fire = () => onChange && onChange(key, obj[key]);
  if (type === 'textarea') {
    input = h('textarea', { id, rows, placeholder, value: obj[key] ?? '' });
    input.addEventListener('input', () => { obj[key] = input.value; fire(); });
  } else if (type === 'select') {
    input = h('select', { id }, options.map((o) => {
      const [v, l] = Array.isArray(o) ? o : [o, o === '' ? '—' : o];
      return h('option', { value: v }, l);
    }));
    input.value = obj[key] ?? '';
    input.addEventListener('change', () => { obj[key] = input.value; fire(); });
  } else if (type === 'checkbox') {
    input = h('input', { id, type: 'checkbox', checked: !!obj[key] });
    input.addEventListener('change', () => { obj[key] = input.checked; fire(); });
    return h('label', { class: 'check' + (cls ? ' ' + cls : '') }, input, ' ', label, help && h('span', { class: 'help' }, help));
  } else {
    input = h('input', { id, type, placeholder, value: obj[key] ?? '' });
    input.addEventListener('input', () => { obj[key] = input.value; fire(); });
  }
  return h('div', { class: 'field' + (wide ? ' wide' : '') + (cls ? ' ' + cls : '') },
    label && h('label', { for: id }, label, required && h('span', { class: 'reqmark', title: 'Required' }, ' *')),
    input,
    help && h('div', { class: 'help' }, help));
}

// Toggle chips for multi-value references (Annex I IDs, EN 18031 mechanisms …)
export function chips(obj, key, options, { onChange, titleOf } = {}) {
  if (!Array.isArray(obj[key])) obj[key] = String(obj[key] || '').split(/[,;]+/).map((s) => s.trim()).filter(Boolean);
  const wrap = h('div', { class: 'chips' });
  const render = () => clear(wrap, options.map((o) => {
    const on = obj[key].includes(o);
    return h('button', {
      type: 'button', class: 'chip' + (on ? ' on' : ''), title: titleOf ? titleOf(o) : null, 'aria-pressed': on ? 'true' : 'false',
      onclick: () => {
        obj[key] = on ? obj[key].filter((x) => x !== o) : [...obj[key], o];
        render(); onChange && onChange(key, obj[key]);
      },
    }, o);
  }));
  render();
  return wrap;
}

// Editable grid for arrays of row objects.
export function grid(list, columns, { onChange, newRow, addLabel = 'Add row', empty = 'Nothing listed yet.' } = {}) {
  const box = h('div', { class: 'grid-wrap' });
  const render = () => {
    const table = h('table', { class: 'grid' },
      h('thead', {}, h('tr', {}, columns.map((c) => h('th', { class: c.width ? `w-${c.width}` : null, title: c.help || null }, c.label)), h('th', { class: 'w-xs' }))),
      h('tbody', {}, list.length ? list.map((row, idx) => h('tr', {},
        columns.map((c) => h('td', {}, cell(row, c))),
        h('td', {}, h('button', { type: 'button', class: 'icon danger', title: 'Remove row', 'aria-label': 'Remove row', onclick: () => {
          if (!confirm(`Remove ${row.id || 'this row'}?`)) return;
          list.splice(idx, 1); render(); onChange && onChange();
        } }, '×')),
      )) : h('tr', {}, h('td', { colspan: columns.length + 1, class: 'muted' }, empty))));
    clear(box, table, newRow && h('button', { type: 'button', class: 'btn small', onclick: () => { list.push(newRow()); render(); onChange && onChange(); } }, '+ ' + addLabel));
  };
  const cell = (row, c) => {
    if (c.render) return c.render(row, list.indexOf(row));
    if (c.readonly) return h('span', { class: 'mono' }, row[c.key]);
    if (c.options) {
      const s = h('select', {}, c.options.map((o) => h('option', { value: o }, o || '—')));
      s.value = row[c.key] ?? '';
      s.addEventListener('change', () => { row[c.key] = s.value; onChange && onChange(); });
      return s;
    }
    const multi = c.multiline;
    const el = multi ? h('textarea', { rows: 2, value: row[c.key] ?? '' }) : h('input', { type: 'text', value: row[c.key] ?? '' });
    el.addEventListener('input', () => { row[c.key] = el.value; onChange && onChange(); });
    return el;
  };
  render();
  return box;
}

export function guidance(title, ...body) {
  return h('details', { class: 'guidance', open: true }, h('summary', {}, title), h('div', {}, body));
}

export function badge(level, text) {
  return h('span', { class: `badge ${level}` }, text);
}

export function ratingBadge(r) {
  return r ? h('span', { class: `rating r-${r.toLowerCase()}` }, r) : h('span', { class: 'muted' }, '—');
}

let toastTimer;
export function toast(msg, kind = 'info') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = 'toast'; }, kind === 'error' ? 8000 : 3500);
}

export function modal(title, body, actions = []) {
  const dlg = h('dialog', { class: 'modal' },
    h('header', {}, h('h2', {}, title), h('button', { type: 'button', class: 'icon', 'aria-label': 'Close', onclick: () => dlg.close() }, '×')),
    h('div', { class: 'modal-body' }, body),
    actions.length ? h('footer', {}, actions) : null);
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  return dlg;
}
