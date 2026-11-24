// Role model (pure; used by the server for enforcement and by the UI to hide actions).
//
// Global roles (per user):
//   admin   – manage users, see and change every product
//   auditor – read-only access to every product (e.g. internal audit, notified-body liaison)
//   creator – may create new products (and becomes their owner)
//   user    – no global rights; access only through product memberships
//
// Product roles (per membership):
//   owner    – everything on the product, incl. members, releases and deletion
//   approver – read + approve (risk method, review log, assessment status) + freeze releases
//   editor   – read + edit content (assessment, components, SBOMs, vulnerability triage, files)
//   viewer   – read + export
// Approval is deliberately not part of "editor": the person who writes the assessment
// should not be the one who approves it (four-eyes principle).

export const GLOBAL_ROLES = [
  { id: 'admin', label: 'Administrator', description: 'Manages users; full access to all products.' },
  { id: 'auditor', label: 'Auditor', description: 'Read-only access to all products.' },
  { id: 'creator', label: 'Product creator', description: 'May create products and becomes their owner.' },
  { id: 'user', label: 'User', description: 'Access only to products they are a member of.' },
];

export const PRODUCT_ROLES = [
  { id: 'owner', label: 'Owner', description: 'Full control incl. members, releases and deletion.' },
  { id: 'approver', label: 'Approver', description: 'Reads, approves and freezes releases. Cannot edit content.' },
  { id: 'editor', label: 'Editor', description: 'Edits assessment, components, SBOMs, triage and documents.' },
  { id: 'viewer', label: 'Viewer', description: 'Reads and exports.' },
];

// action -> product roles that may perform it
const MATRIX = {
  read: ['owner', 'approver', 'editor', 'viewer'],
  export: ['owner', 'approver', 'editor', 'viewer'],
  edit: ['owner', 'editor'],
  approve: ['owner', 'approver'],
  release: ['owner', 'approver'],
  members: ['owner'],
  delete: ['owner'],
};

export const ACTIONS = Object.keys(MATRIX);

/**
 * @param {{globalRole:string}} user
 * @param {string|null} productRole membership role of the user on the product (or null)
 * @param {string} action one of ACTIONS
 */
export function can(user, productRole, action) {
  if (!user) return false;
  if (user.globalRole === 'admin') return true;
  if (user.globalRole === 'auditor' && (action === 'read' || action === 'export')) return true;
  return !!productRole && (MATRIX[action] || []).includes(productRole);
}

export function permissions(user, productRole) {
  return Object.fromEntries(ACTIONS.map((a) => [a, can(user, productRole, a)]));
}

export const canCreateProducts = (user) => !!user && (user.globalRole === 'admin' || user.globalRole === 'creator');
export const canManageUsers = (user) => !!user && user.globalRole === 'admin';
