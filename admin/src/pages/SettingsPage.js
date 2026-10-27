'use strict';

import * as React from 'react';
import {
  Main,
  Box,
  Flex,
  Typography,
  Button,
  Divider,
  Checkbox,
  SingleSelect,
  SingleSelectOption,
  TextInput,
  Field,
} from '@strapi/design-system';
import { useFetchClient, useNotification } from '@strapi/strapi/admin';

/**
 * Settings page for the OIDC SSO plugin. Written with React.createElement (no
 * JSX) but using the official Strapi Design System form components, so inputs
 * are fully theme-aware (light and dark) and consistent with the admin.
 */

const h = React.createElement;

function Section(title, hint, children) {
  return h(
    Box,
    { paddingTop: 6, key: title },
    h(Typography, { variant: 'delta', tag: 'h2' }, title),
    hint ? h(Box, { paddingTop: 1 }, h(Typography, { variant: 'pi', textColor: 'neutral600' }, hint)) : null,
    h(Box, { paddingTop: 3 }, children)
  );
}

// Checkbox with a DS label (danger variants get a red label).
function Check(label, checked, onChange, danger) {
  return h(
    Checkbox,
    { checked: !!checked, onCheckedChange: (v) => onChange(v === true), key: label },
    danger ? h(Typography, { textColor: 'danger600' }, label) : label
  );
}

// Field.Root + Field.Label + TextInput.
function TextField(label, value, onChange, placeholder, name) {
  return h(
    Box,
    { maxWidth: '32rem', key: label },
    h(
      Field.Root,
      { name: name || label },
      h(Field.Label, null, label),
      h(TextInput, {
        value: value == null ? '' : String(value),
        placeholder: placeholder || '',
        onChange: (e) => onChange(e.target.value),
      })
    )
  );
}

// SingleSelect with a leading empty option; onChange receives the value.
function RoleSelect(label, value, onChange, emptyLabel, options) {
  const select = h(
    SingleSelect,
    {
      value: value == null ? '' : String(value),
      onChange: (v) => onChange(v),
      placeholder: emptyLabel,
    },
    [h(SingleSelectOption, { key: '__empty', value: '' }, emptyLabel)].concat(
      options.map((r) => h(SingleSelectOption, { key: r.id, value: String(r.id) }, `${r.name} (${r.code || r.id})`))
    )
  );
  if (!label) return select;
  return h(
    Box,
    { maxWidth: '32rem' },
    h(Field.Root, { name: label }, h(Field.Label, null, label), select)
  );
}

export default function SettingsPage() {
  const { get, put } = useFetchClient();
  const { toggleNotification } = useNotification();

  const [data, setData] = React.useState(null);
  const [form, setForm] = React.useState(null);
  const [mappingRows, setMappingRows] = React.useState([]);
  const [saving, setSaving] = React.useState(false);
  const [loadError, setLoadError] = React.useState(null);

  const roleOptions = (data && data.adminRoles) || [];

  const applyData = React.useCallback((d) => {
    setData(d);
    const eff = d.effective || {};
    setForm({
      roleSources: eff.roleSources || ['realm'],
      groupsClaim: eff.groupsClaim || 'groups',
      resourceRolesClient: eff.resourceRolesClient || '',
      dynamicRoleMatching: {
        enabled: !!(eff.dynamicRoleMatching && eff.dynamicRoleMatching.enabled),
        groupPrefix:
          eff.dynamicRoleMatching && eff.dynamicRoleMatching.groupPrefix != null
            ? eff.dynamicRoleMatching.groupPrefix
            : 'cms-',
        matchBy: (eff.dynamicRoleMatching && eff.dynamicRoleMatching.matchBy) || ['code', 'name'],
      },
      provisioning: {
        autoCreate: eff.provisioning ? eff.provisioning.autoCreate !== false : true,
        defaultRoleId: (eff.provisioning && eff.provisioning.defaultRoleId) || null,
        syncRolesOnLogin: eff.provisioning ? eff.provisioning.syncRolesOnLogin !== false : true,
        updateProfileOnLogin: eff.provisioning ? eff.provisioning.updateProfileOnLogin !== false : true,
      },
      rememberMe: eff.rememberMe !== false,
      hideLocalLogin: !!eff.hideLocalLogin,
      buttonLabel: eff.buttonLabel || 'Sign in with SSO',
    });
    const rows = Object.entries(eff.roleMapping || {}).map(([group, target]) => {
      let id = '';
      if (typeof target === 'number') id = String(target);
      else if ((d.adminRoles || []).some((r) => String(r.id) === String(target))) id = String(target);
      else {
        const byCode = (d.adminRoles || []).find((r) => r.code === target);
        id = byCode ? String(byCode.id) : '';
      }
      return { group, target: id };
    });
    setMappingRows(rows.length ? rows : [{ group: '', target: '' }]);
  }, []);

  const loadSettings = React.useCallback(() => {
    return get('/oidc-sso/settings')
      .then((res) => applyData(res.data.data))
      .catch((err) => setLoadError((err && err.message) || 'Failed to load settings'));
  }, [get, applyData]);

  React.useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  if (loadError) {
    return h(Main, null, h(Box, { padding: 8 }, h(Typography, { textColor: 'danger600' }, loadError)));
  }
  if (!form) {
    return h(Main, null, h(Box, { padding: 8 }, h(Typography, null, 'Loading…')));
  }

  const set = (key, value) => setForm((f) => ({ ...f, [key]: value }));
  const setDyn = (key, value) =>
    setForm((f) => ({ ...f, dynamicRoleMatching: { ...f.dynamicRoleMatching, [key]: value } }));
  const setProv = (key, value) =>
    setForm((f) => ({ ...f, provisioning: { ...f.provisioning, [key]: value } }));
  const toggleInList = (list, item) =>
    list.includes(item) ? list.filter((x) => x !== item) : [...list, item];

  function buildPayload() {
    const roleMapping = {};
    let dropped = 0;
    mappingRows.forEach((row) => {
      const g = row.group.trim();
      if (g && row.target) roleMapping[g] = Number(row.target);
      else if (g || row.target) dropped += 1; // partially filled row
    });
    // Coerce hidden/optional fields to valid values so the whole save never
    // fails on a field the user cannot currently see.
    const matchBy =
      form.dynamicRoleMatching.matchBy && form.dynamicRoleMatching.matchBy.length
        ? form.dynamicRoleMatching.matchBy
        : ['code', 'name'];
    const payload = {
      roleMapping,
      roleSources: form.roleSources,
      groupsClaim: (form.groupsClaim && form.groupsClaim.trim()) || 'groups',
      resourceRolesClient: form.resourceRolesClient,
      dynamicRoleMatching: {
        enabled: form.dynamicRoleMatching.enabled,
        groupPrefix: form.dynamicRoleMatching.groupPrefix,
        matchBy,
      },
      provisioning: {
        autoCreate: form.provisioning.autoCreate,
        defaultRoleId: form.provisioning.defaultRoleId,
        syncRolesOnLogin: form.provisioning.syncRolesOnLogin,
        updateProfileOnLogin: form.provisioning.updateProfileOnLogin,
      },
      rememberMe: form.rememberMe,
      hideLocalLogin: form.hideLocalLogin,
      buttonLabel: (form.buttonLabel && form.buttonLabel.trim()) || 'Sign in with SSO',
    };
    return { payload, dropped };
  }

  async function save(reset) {
    if (!reset && (!form.roleSources || form.roleSources.length === 0)) {
      toggleNotification({ type: 'danger', message: 'Select at least one role source.' });
      return;
    }
    let body = {};
    let dropped = 0;
    if (!reset) {
      const built = buildPayload();
      body = built.payload;
      dropped = built.dropped;
    }
    setSaving(true);
    try {
      await put('/oidc-sso/settings', body);
      if (reset) {
        await loadSettings();
        toggleNotification({ type: 'success', message: 'Reset to file configuration.' });
      } else {
        if (dropped > 0) {
          toggleNotification({
            type: 'warning',
            message: `Saved. ${dropped} incomplete mapping row(s) were skipped (need both a group and a role).`,
          });
        } else {
          toggleNotification({ type: 'success', message: 'SSO settings saved. They apply from the next login.' });
        }
      }
    } catch (err) {
      const msg =
        (err && err.response && err.response.data && err.response.data.error && err.response.data.error.message) ||
        'Could not save settings';
      toggleNotification({ type: 'danger', message: msg });
    } finally {
      setSaving(false);
    }
  }

  const locked = (data && data.locked) || {};

  return h(
    Main,
    null,
    h(
      Box,
      { padding: 8, paddingTop: 6 },
      h(Typography, { variant: 'alpha', tag: 'h1' }, 'OIDC SSO'),
      h(Box, { paddingTop: 1 },
        h(Typography, { variant: 'epsilon', textColor: 'neutral600' },
          'Runtime policy for single sign-on. Connection settings (issuer, client, secrets) are file/env-only by design.')),

      Section('Role sources', 'Where in the token to read roles/groups from.',
        h(Flex, { gap: 4, wrap: 'wrap' },
          Check('realm roles (Keycloak)', form.roleSources.includes('realm'), () => set('roleSources', toggleInList(form.roleSources, 'realm'))),
          Check('client roles (Keycloak)', form.roleSources.includes('client'), () => set('roleSources', toggleInList(form.roleSources, 'client'))),
          Check('groups claim (generic / FreeIPA)', form.roleSources.includes('groups'), () => set('roleSources', toggleInList(form.roleSources, 'groups'))),
          form.roleSources.includes('groups')
            ? TextField('Groups claim name', form.groupsClaim, (v) => set('groupsClaim', v), 'groups')
            : null
        )
      ),

      Section('Role mapping', 'Explicit allow-list: IdP group or role name → Strapi admin role.',
        h(Box, { maxWidth: '44rem' },
          mappingRows.map((row, i) =>
            h(Flex, { key: i, gap: 2, alignItems: 'flex-end', paddingBottom: 2 },
              h(Box, { style: { flex: 2 } },
                h(Field.Root, { name: `oidc-map-group-${i}` },
                  h(TextInput, {
                    'aria-label': 'IdP group or role',
                    placeholder: 'IdP group or role (e.g. cms-editors or /cms-editors)',
                    value: row.group,
                    onChange: (e) => setMappingRows((rows) => rows.map((r, j) => (j === i ? { ...r, group: e.target.value } : r))),
                  })
                )
              ),
              h(Box, { style: { flex: 2 } },
                RoleSelect(null, row.target, (v) => setMappingRows((rows) => rows.map((r, j) => (j === i ? { ...r, target: v } : r))), ' - Strapi role - ', roleOptions)
              ),
              h(Button, { variant: 'tertiary', onClick: () => setMappingRows((rows) => rows.filter((_, j) => j !== i)) }, 'Remove')
            )
          ),
          h(Box, { paddingTop: 2 },
            h(Button, { variant: 'secondary', onClick: () => setMappingRows((rows) => [...rows, { group: '', target: '' }]) }, 'Add mapping'))
        )
      ),

      Section('Dynamic role matching', 'Convention instead of a table: group "prefix + key" grants the role whose code or name is "key". Super admin can never be granted via SSO unless enabled in file config (allowSuperAdminMapping).',
        h(Flex, { direction: 'column', alignItems: 'flex-start', gap: 3 },
          Check('Enable dynamic matching', form.dynamicRoleMatching.enabled, (v) => setDyn('enabled', v)),
          form.dynamicRoleMatching.enabled
            ? h(Flex, { gap: 4, wrap: 'wrap', alignItems: 'flex-end' },
                TextField('Group prefix', form.dynamicRoleMatching.groupPrefix, (v) => setDyn('groupPrefix', v), 'cms-'),
                Check('match role code', form.dynamicRoleMatching.matchBy.includes('code'), () => setDyn('matchBy', toggleInList(form.dynamicRoleMatching.matchBy, 'code'))),
                Check('match role name', form.dynamicRoleMatching.matchBy.includes('name'), () => setDyn('matchBy', toggleInList(form.dynamicRoleMatching.matchBy, 'name')))
              )
            : null
        )
      ),

      Section('Provisioning', 'How SSO identities become Strapi admin users. Security guards (verified-email, relink, reactivation) are file-only - shown read-only below.',
        h(Flex, { direction: 'column', alignItems: 'flex-start', gap: 2 },
          Check('Auto-create admins on first SSO login', form.provisioning.autoCreate, (v) => setProv('autoCreate', v)),
          Check('Sync roles from IdP on every login (off = manage roles manually in Strapi)', form.provisioning.syncRolesOnLogin, (v) => setProv('syncRolesOnLogin', v)),
          Check('Sync name/email from IdP on every login', form.provisioning.updateProfileOnLogin, (v) => setProv('updateProfileOnLogin', v)),
          h(Box, { paddingTop: 2 },
            RoleSelect('Default role when nothing maps (empty = deny login)', form.provisioning.defaultRoleId, (v) => setProv('defaultRoleId', v === '' ? null : Number(v)), ' - deny login - ', roleOptions))
        )
      ),

      Section('Safety & UI', null,
        h(Flex, { direction: 'column', alignItems: 'flex-start', gap: 2 },
          Check('Persistent session cookie (remember me)', form.rememberMe, (v) => set('rememberMe', v)),
          Check('Visually hide local login (break-glass stays reachable)', form.hideLocalLogin, (v) => set('hideLocalLogin', v)),
          TextField('Login button label', form.buttonLabel, (v) => set('buttonLabel', v), 'Sign in with SSO')
        )
      ),

      h(Box, { paddingTop: 6 },
        h(Flex, { gap: 2 },
          h(Button, { onClick: () => save(false), loading: saving }, 'Save'),
          h(Button, { variant: 'tertiary', onClick: () => save(true), disabled: saving }, 'Reset to file config')
        )
      ),

      h(Box, { paddingTop: 6 }, h(Divider, null)),

      Section('Connection & security guards (read-only, file/env configured)', 'A redacted subset shown for context. Secrets are never returned. Edit these only in config/plugins.js.',
        h(Flex, { direction: 'column', alignItems: 'flex-start', gap: 1 },
          h(Typography, { variant: 'pi' }, `Issuer: ${locked.issuer || '(not set)'}`),
          h(Typography, { variant: 'pi' }, `Client id: ${locked.clientId || '(not set)'}`),
          h(Typography, { variant: 'pi' }, `Redirect URI: ${locked.redirectUri || ''}`),
          h(Typography, { variant: 'pi' }, `Scope: ${locked.scope || 'openid email profile'}`),
          h(Typography, { variant: 'pi' }, `PKCE: ${locked.usePKCE ? 'on' : 'off'} · Token auth: ${locked.tokenEndpointAuthMethod} · RP-initiated logout: ${locked.rpInitiatedLogout ? 'on' : 'off'}`),
          h(Typography, { variant: 'pi' }, `SSO may grant super admin: ${locked.allowSuperAdminMapping ? 'YES' : 'no'} · Protect last super admin: ${locked.protectLastSuperAdmin ? 'on' : 'off'}`),
          h(Typography, { variant: 'pi' }, `Require verified email: ${locked.requireVerifiedEmail ? 'on' : 'off'} · Match existing by email: ${locked.matchExistingByEmail ? 'on' : 'off'} · Allow relink: ${locked.allowEmailRelink ? 'on' : 'off'} · Reactivate disabled: ${locked.reactivateDisabledOnLogin ? 'on' : 'off'}`),
          h(Typography, { variant: 'pi' }, `Audit logging: ${locked.audit ? 'on' : 'off'} (file-only)`)
        )
      )
    )
  );
}
