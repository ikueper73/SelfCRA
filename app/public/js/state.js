// Shared client state (current user, reference data) – avoids circular imports between page modules.
export const state = { me: null, catalog: null, authMode: 'local' };

export const roleLabel = (id) => [...(state.catalog?.PRODUCT_ROLES || []), ...(state.catalog?.GLOBAL_ROLES || [])].find((r) => r.id === id)?.label || id || '';
export const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString() : '');
export const fmtDay = (iso) => (iso ? new Date(iso).toLocaleDateString() : '');
export const bytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1048576).toFixed(1)} MB`);
