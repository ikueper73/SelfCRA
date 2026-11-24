// Administration: users and global roles; own account.
import { h, clear, toast, badge, field } from './ui.js';
import { api } from './api.js';
import { state, roleLabel, fmtDate } from './state.js';

export async function usersPage(root, { crumb }) {
  crumb.textContent = ' › Users';
  if (!state.me.can.manageUsers) return clear(root, h('p', { class: 'pad' }, 'Administrators only.'));
  const users = await api.users();
  const local = state.authMode === 'local';
  const roles = state.catalog.GLOBAL_ROLES;
  const form = { email: '', name: '', globalRole: 'user', password: '' };
  const roleSelect = (u) => {
    const s = h('select', { disabled: u.authSource === 'sso' && state.me.user.roleFromIdp }, roles.map((r) => h('option', { value: r.id }, r.label)));
    s.value = u.globalRole;
    s.addEventListener('change', async () => { try { await api.updateUser(u.id, { globalRole: s.value }); toast('Role changed.'); } catch (e) { toast(e.message, 'error'); s.value = u.globalRole; } });
    return s;
  };
  clear(root, h('div', { class: 'page' },
    h('section', { class: 'card' }, h('h1', {}, 'Users'),
      h('p', { class: 'muted' }, local
        ? 'Users sign in with e-mail and password. When single sign-on is switched on later (AUTH_MODE=header), users are matched by e-mail address and become SSO-managed automatically.'
        : 'Users sign in through single sign-on. Unknown users are registered at their first sign-in without product access; you can also pre-register e-mail addresses here.'),
      h('table', { class: 'list roles' }, h('tbody', {}, roles.map((r) => h('tr', {}, h('td', {}, h('b', {}, r.label)), h('td', { class: 'muted' }, r.description)))))),
    h('section', { class: 'card' }, h('table', { class: 'list' },
      h('thead', {}, h('tr', {}, ['User', 'Sign-in', 'Global role', 'Last sign-in', 'Status', ''].map((t) => h('th', {}, t)))),
      h('tbody', {}, users.filter((u) => u.authSource !== 'none').map((u) => h('tr', {},
        h('td', {}, u.name || '—', h('div', { class: 'small muted' }, u.email)),
        h('td', {}, u.authSource === 'sso' ? badge('info', 'SSO') : badge('muted', 'password'), u.mustChange ? h('div', { class: 'small muted' }, 'must change password') : null),
        h('td', {}, roleSelect(u)),
        h('td', { class: 'small muted' }, fmtDate(u.lastLoginAt) || 'never'),
        h('td', {}, u.disabled ? badge('blocker', 'disabled') : badge('ok', 'active')),
        h('td', { class: 'actions' },
          u.authSource === 'local' ? h('button', { class: 'btn small ghost', onclick: async () => {
            const pw = prompt(`New temporary password for ${u.email} (min. 12 characters). The user must change it at the next sign-in.`);
            if (!pw) return;
            try { await api.updateUser(u.id, { password: pw }); toast('Password reset.'); } catch (e) { toast(e.message, 'error'); }
          } }, 'Reset password') : null,
          h('button', { class: 'btn small ghost', onclick: async () => { try { await api.updateUser(u.id, { disabled: !u.disabled }); usersPage(root, { crumb }); } catch (e) { toast(e.message, 'error'); } } }, u.disabled ? 'Enable' : 'Disable'),
          u.id !== state.me.user.id ? h('button', { class: 'btn small ghost danger', onclick: async () => {
            if (!confirm(`Delete ${u.email}? Their product memberships are removed; the audit trail keeps their e-mail.`)) return;
            try { await api.deleteUser(u.id); usersPage(root, { crumb }); } catch (e) { toast(e.message, 'error'); }
          } }, 'Delete') : null)))))),
    h('section', { class: 'card' }, h('h2', {}, local ? 'Add user' : 'Pre-register SSO user'),
      h('div', { class: 'fields' },
        field(form, 'email', { label: 'E-mail', type: 'email', required: true }),
        field(form, 'name', { label: 'Name' }),
        field(form, 'globalRole', { label: 'Global role', type: 'select', options: roles.map((r) => [r.id, r.label]) }),
        local ? field(form, 'password', { label: 'Temporary password', type: 'password', help: 'Min. 12 characters; must be changed at first sign-in.' }) : null),
      h('button', { class: 'btn primary', onclick: async () => {
        try { await api.createUser(form); toast('User created. Add them to products under Product → Members.'); usersPage(root, { crumb }); } catch (e) { toast(e.message, 'error'); }
      } }, 'Create user'))));
}

export async function accountPage(root, { crumb, forced = false, onDone } = {}) {
  if (crumb) crumb.textContent = ' › Account';
  const u = state.me.user;
  const pw = { current: '', password: '', repeat: '' };
  clear(root, h('div', { class: 'page narrow' },
    h('section', { class: 'card' }, h('h1', {}, 'My account'),
      h('table', { class: 'list' }, h('tbody', {},
        h('tr', {}, h('td', {}, 'E-mail'), h('td', {}, u.email)),
        h('tr', {}, h('td', {}, 'Name'), h('td', {}, u.name || '—')),
        h('tr', {}, h('td', {}, 'Global role'), h('td', {}, roleLabel(u.globalRole), u.roleFromIdp ? h('span', { class: 'muted small' }, ' (from the identity provider)') : null)),
        h('tr', {}, h('td', {}, 'Sign-in'), h('td', {}, u.authSource === 'sso' ? 'Single sign-on' : 'E-mail and password'))))),
    u.authSource === 'local' ? h('form', { class: 'card', onsubmit: async (e) => {
      e.preventDefault();
      if (pw.password !== pw.repeat) return toast('The new passwords do not match.', 'error');
      try { await api.changePassword(pw.current, pw.password); toast('Password changed.'); if (onDone) onDone(); } catch (err) { toast(err.message, 'error'); }
    } }, h('h2', {}, forced ? 'Choose a new password to continue' : 'Change password'),
    forced ? h('p', { class: 'muted' }, 'Your password was set by an administrator and must be changed before you can continue.') : null,
    h('div', { class: 'fields' },
      field(pw, 'current', { label: 'Current password', type: 'password' }),
      field(pw, 'password', { label: 'New password', type: 'password', help: 'At least 12 characters; not containing your e-mail name.' }),
      field(pw, 'repeat', { label: 'Repeat new password', type: 'password' })),
    h('button', { class: 'btn primary', type: 'submit' }, 'Change password')) : null));
}
