// Relative URLs so the app also works behind a reverse proxy under a sub-path.
async function req(method, url, body, { raw, headers = {} } = {}) {
  // The API never redirects. A redirect therefore means an authenticating proxy (e.g. Azure Easy Auth)
  // wants the user to sign in again: report it as 401 instead of silently following it to the login page.
  const opts = { method, headers: { 'X-Requested-With': 'XMLHttpRequest', ...headers }, credentials: 'same-origin', redirect: 'manual' };
  if (body !== undefined) {
    if (raw) { opts.body = body; opts.headers['Content-Type'] = headers['Content-Type'] || 'application/octet-stream'; }
    else { opts.body = JSON.stringify(body); opts.headers['Content-Type'] = 'application/json'; }
  }
  const res = await fetch(url, opts);
  if (res.type === 'opaqueredirect') {
    const err = new Error('Sign-in session expired');
    err.status = 401;
    throw err;
  }
  if (res.status === 204) return null;
  const data = res.headers.get('content-type')?.includes('json') ? await res.json() : await res.text();
  if (!res.ok) {
    const err = new Error((data && data.error) || `${res.status} ${res.statusText}`);
    err.status = res.status; err.data = data;
    if (res.status === 401 || data?.code === 'must_change') window.dispatchEvent(new CustomEvent('cra-auth', { detail: { status: res.status, code: data?.code } }));
    throw err;
  }
  return data;
}
const b64json = (o) => btoa(unescape(encodeURIComponent(JSON.stringify(o))));
const P = (pid) => `api/products/${encodeURIComponent(pid)}`;

export const api = {
  // session
  authState: () => req('GET', 'api/auth/state'),
  login: (email, password) => req('POST', 'api/auth/login', { email, password }),
  logout: () => req('POST', 'api/auth/logout', {}),
  setup: (body) => req('POST', 'api/auth/setup', body),
  changePassword: (current, password) => req('POST', 'api/auth/password', { current, password }),
  me: () => req('GET', 'api/me'),
  catalog: () => req('GET', 'api/catalog'),
  // users
  users: () => req('GET', 'api/users'),
  directory: () => req('GET', 'api/directory'),
  createUser: (u) => req('POST', 'api/users', u),
  updateUser: (id, patch) => req('PATCH', `api/users/${id}`, patch),
  deleteUser: (id) => req('DELETE', `api/users/${id}`),
  // products
  products: () => req('GET', 'api/products'),
  createProduct: (name, markets) => req('POST', 'api/products', { name, markets }),
  importJson: (doc) => req('POST', 'api/products', { import: doc }),
  importXlsx: (buf) => req('POST', 'api/import/xlsx', buf, { raw: true }),
  examples: () => req('GET', 'api/examples'),
  fromExample: (id) => req('POST', `api/examples/${encodeURIComponent(id)}`),
  product: (pid) => req('GET', P(pid)),
  saveProduct: (pid, revision, data) => req('PUT', P(pid), { revision, data }),
  deleteProduct: (pid) => req('DELETE', P(pid)),
  productEvents: (pid) => req('GET', `${P(pid)}/events`),
  members: (pid) => req('GET', `${P(pid)}/members`),
  setMember: (pid, uid, role) => req('PUT', `${P(pid)}/members/${uid}`, { role }),
  // assessment
  assessment: (pid) => req('GET', `${P(pid)}/assessment`),
  save: (pid, revision, data) => req('PUT', `${P(pid)}/assessment`, { revision, data }),
  approve: (pid, body) => req('POST', `${P(pid)}/assessment/approve`, body),
  snapshots: (pid) => req('GET', `${P(pid)}/assessment/snapshots`),
  freeze: (pid, note) => req('POST', `${P(pid)}/assessment/snapshots`, { note }),
  exportUrl: (pid, fmt, snapshot) => `${P(pid)}/assessment/export.${fmt}${snapshot ? `?snapshot=${encodeURIComponent(snapshot)}` : ''}`,
  // components, SBOMs, vulnerabilities
  components: (pid) => req('GET', `${P(pid)}/components`),
  createComponent: (pid, c) => req('POST', `${P(pid)}/components`, c),
  updateComponent: (pid, cid, c) => req('PUT', `${P(pid)}/components/${cid}`, c),
  deleteComponent: (pid, cid) => req('DELETE', `${P(pid)}/components/${cid}`),
  sboms: (pid, cid) => req('GET', `${P(pid)}/components/${cid}/sboms`),
  uploadSbom: (pid, cid, name, buf) => req('POST', `${P(pid)}/components/${cid}/sbom?name=${encodeURIComponent(name)}`, buf, { raw: true }),
  sbomUrl: (pid, sid) => `${P(pid)}/sboms/${sid}/download`,
  scan: (pid, cid) => req('POST', `${P(pid)}/components/${cid}/scan`, {}),
  scans: (pid) => req('GET', `${P(pid)}/scans`),
  importVulns: (pid, cid, buf) => req('POST', `${P(pid)}/components/${cid}/vulns/import`, buf, { raw: true }),
  vulns: (pid, cid) => req('GET', `${P(pid)}/vulns${cid ? `?component=${cid}` : ''}`),
  triage: (pid, fid, body) => req('PATCH', `${P(pid)}/vulns/${fid}`, body),
  vexUrl: (pid, cid) => `${P(pid)}/vex.json${cid ? `?component=${cid}` : ''}`,
  // files & releases
  files: (pid) => req('GET', `${P(pid)}/files`),
  uploadFile: (pid, section, file, buf, meta) => req('POST', `${P(pid)}/files?section=${encodeURIComponent(section)}&name=${encodeURIComponent(file.name)}`, buf,
    { raw: true, headers: { 'Content-Type': file.type || 'application/octet-stream', 'X-File-Meta': b64json(meta || {}) } }),
  updateFile: (pid, fid, body) => req('PATCH', `${P(pid)}/files/${fid}`, body),
  deleteFile: (pid, fid) => req('DELETE', `${P(pid)}/files/${fid}`),
  fileUrl: (pid, fid) => `${P(pid)}/files/${fid}/download`,
  draftZipUrl: (pid) => `${P(pid)}/techdoc/draft.zip`,
  releases: (pid) => req('GET', `${P(pid)}/releases`),
  release: (pid, version, note) => req('POST', `${P(pid)}/releases`, { version, note }),
  releaseUrl: (pid, rid) => `${P(pid)}/releases/${rid}/download`,
};
