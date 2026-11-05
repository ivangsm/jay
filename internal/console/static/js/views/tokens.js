// Tokens: list, revoke and create. The secret of a new token is shown once, in
// a dialog, and lives only in that dialog's DOM: it is never written to
// storage and the nodes are emptied when the dialog closes.

import { adminApi, session } from '../api.js';
import { formatDate, formatRelative, tokenState } from '../format.js';
import {
  badge,
  button,
  checkbox,
  confirmDestructive,
  copyButton,
  dataTable,
  errorDetails,
  errorState,
  field,
  h,
  loading,
  openDialog,
  pageHeader,
  select,
  textInput,
  toast,
} from '../ui.js';

const STATUS_OPTIONS = [
  { value: 'active', label: 'Active' },
  { value: 'revoked', label: 'Revoked' },
  { value: 'expired', label: 'Expired' },
  { value: 'all', label: 'All' },
];

export function accountLabel(accounts, id) {
  const a = accounts.find((x) => x.account_id === id);
  return a?.name || id;
}

function actionsCell(token) {
  const actions = token.allowed_actions || [];
  if (actions.includes('*')) return badge('all actions', 'accent');
  if (actions.length === 0) return '—';
  const shown = actions.slice(0, 2).map((a) => badge(a));
  const rest = actions.length - shown.length;
  return h(
    'span',
    { class: 'chip-row', title: actions.join(', ') },
    shown,
    rest > 0 ? badge(`+${rest}`) : null,
  );
}

function scopeCell(token) {
  const buckets = token.bucket_scope || [];
  const prefixes = token.prefix_scope || [];
  if (buckets.length === 0 && prefixes.length === 0) return '—';
  const parts = [];
  if (buckets.length > 0) parts.push(h('div', { title: buckets.join(', ') }, `buckets: ${buckets.join(', ')}`));
  if (prefixes.length > 0) parts.push(h('div', { title: prefixes.join(', ') }, `prefixes: ${prefixes.join(', ')}`));
  return h('span', { class: 'scope-cell' }, parts);
}

function expiryCell(token) {
  if (!token.expires_at) return 'never';
  const exp = new Date(token.expires_at).getTime();
  return h('span', { title: new Date(token.expires_at).toISOString() }, exp > Date.now() ? untilLabel(exp) : formatRelative(token.expires_at));
}

function untilLabel(exp) {
  const seconds = Math.round((exp - Date.now()) / 1000);
  if (seconds < 3600) return `in ${Math.max(1, Math.round(seconds / 60))} min`;
  if (seconds < 86400) return `in ${Math.round(seconds / 3600)} h`;
  if (seconds < 86400 * 30) return `in ${Math.round(seconds / 86400)} d`;
  return formatDate(exp);
}

// revokeToken asks for the token's name (or its id when it has none) and only
// reports success after the server answered 2xx. Resolves true when revoked.
export async function revokeToken(token) {
  const phrase = token.name || token.token_id;
  const result = await confirmDestructive({
    title: `Revoke token ${phrase}`,
    description: 'Revocation is permanent. Every client and every presigned URL signed by this token stops working immediately.',
    confirmPhrase: phrase,
    actionLabel: 'Revoke token',
    run: async () => {
      await adminApi('DELETE', `/tokens/${encodeURIComponent(token.token_id)}`);
      return { revoked: true };
    },
  });
  if (result?.revoked) {
    toast({ tone: 'ok', title: 'Token revoked', message: phrase });
    return true;
  }
  return false;
}

// tokenTable renders tokens. accounts resolves account ids to names; with
// showAccount false the Account column is left out (the account page).
export function tokenTable({ tokens, accounts, showAccount = true, onChanged, empty }) {
  const columns = [
    { key: 'name', label: 'Name', render: (t) => t.name || h('span', { class: 'muted' }, 'unnamed') },
    {
      key: 'token_id',
      label: 'Token ID',
      mono: true,
      render: (t) => h('span', { class: 'id-cell' }, h('span', { title: t.token_id }, `${t.token_id.slice(0, 8)}…`), copyButton(t.token_id, { label: '' })),
    },
  ];
  if (showAccount) {
    columns.push({ key: 'account', label: 'Account', hideBelow: 600, render: (t) => h('span', { title: t.account_id }, accountLabel(accounts, t.account_id)) });
  }
  columns.push(
    { key: 'actions', label: 'Actions', hideBelow: 900, render: actionsCell },
    { key: 'scope', label: 'Scope', hideBelow: 900, render: scopeCell },
    { key: 'expires', label: 'Expires', hideBelow: 600, render: expiryCell },
    {
      key: 'status',
      label: 'Status',
      render: (t) => {
        const s = tokenState(t);
        return badge(s.label, s.tone);
      },
    },
    {
      key: 'ops',
      label: '',
      align: 'right',
      render: (t) =>
        t.status === 'revoked'
          ? ''
          : button({
              label: 'Revoke',
              variant: 'danger',
              size: 'sm',
              onClick: async () => {
                if (await revokeToken(t)) onChanged?.();
              },
            }),
    },
  );
  return dataTable({ columns, rows: tokens, rowKey: 'token_id', empty });
}

// ---------- create ----------

function showSecretDialog(created) {
  const secretEl = h('code', { class: 'secret-value' }, created.secret);
  const idEl = h('code', {}, created.token_id);
  const body = h(
    'div',
    { class: 'secret-body' },
    h('div', { class: 'banner banner-warn', role: 'alert' }, 'Copy the secret now. jay will never show it again.'),
    h(
      'dl',
      { class: 'kv' },
      h('dt', {}, 'Token ID'),
      h('dd', {}, idEl, ' ', copyButton(created.token_id)),
      h('dt', {}, 'Secret'),
      h('dd', {}, secretEl, ' ', copyButton(created.secret)),
    ),
    h('p', { class: 'muted' }, 'S3 clients: access key = token ID, secret key = secret.'),
    checkbox({
      label: 'I have stored the secret',
      checked: false,
      onChange: (on) => dlg.setActions([{ label: 'Done', variant: 'primary', disabled: !on }]),
    }),
  );
  const dlg = openDialog({
    title: 'Token created',
    body,
    dismissible: false,
    actions: [{ label: 'Done', variant: 'primary', disabled: true }],
    // The secret leaves the page with the dialog: empty the nodes that held it.
    onClose: () => {
      secretEl.textContent = '';
      body.replaceChildren();
    },
  });
}

// openNewTokenDialog collects the token's grants and creates it. defaults:
// { accountId, bucket }. onCreated runs after the 201, before the secret is
// shown, so the list behind the dialog already includes the token.
export function openNewTokenDialog({ accounts, defaults = {}, onCreated }) {
  const allActions = session()?.actions || [];
  const accountSel = select({
    options: [{ value: '', label: 'Choose an account…' }, ...accounts.map((a) => ({ value: a.account_id, label: a.name || a.account_id }))],
    value: accounts.some((a) => a.account_id === defaults.accountId) ? defaults.accountId : '',
    onChange: () => loadBuckets(),
  });
  const nameInput = textInput({ placeholder: 'e.g. falco-app', maxlength: '128' });

  // Actions
  const allBox = h('input', { type: 'checkbox' });
  const actionBoxes = allActions.map((a) => ({ action: a, el: h('input', { type: 'checkbox' }) }));
  const syncActions = () => {
    for (const b of actionBoxes) b.el.disabled = allBox.checked;
  };
  allBox.addEventListener('change', syncActions);
  const actionsBox = h(
    'div',
    { class: 'check-list' },
    h('label', { class: 'check' }, allBox, h('span', {}, 'All actions (*)')),
    actionBoxes.map((b) => h('label', { class: 'check' }, b.el, h('span', { class: 'is-mono' }, b.action))),
  );

  // Bucket scope: the buckets the chosen account owns.
  const bucketBox = h('div', { class: 'check-list' });
  const chosenBuckets = new Set(defaults.bucket ? [defaults.bucket] : []);
  let bucketSeq = 0;
  async function loadBuckets() {
    const seq = ++bucketSeq;
    const accountId = accountSel.value;
    if (!accountId) {
      bucketBox.replaceChildren(h('span', { class: 'muted' }, 'Choose an account to see its buckets.'));
      return;
    }
    loading(bucketBox, 'Loading buckets…');
    try {
      const buckets = await adminApi('GET', '/buckets', { query: { owner_account_id: accountId } });
      if (seq !== bucketSeq) return;
      if (buckets.length === 0) {
        bucketBox.replaceChildren(h('span', { class: 'muted' }, 'This account owns no buckets yet.'));
        return;
      }
      bucketBox.replaceChildren(
        ...buckets.map((b) =>
          h(
            'label',
            { class: 'check' },
            h('input', {
              type: 'checkbox',
              checked: chosenBuckets.has(b.name),
              on: {
                change: (e) => {
                  if (e.target.checked) chosenBuckets.add(b.name);
                  else chosenBuckets.delete(b.name);
                },
              },
            }),
            h('span', { class: 'is-mono' }, b.name),
          ),
        ),
      );
    } catch (err) {
      if (seq !== bucketSeq) return;
      bucketBox.replaceChildren(
        h('div', { class: 'banner banner-danger', role: 'alert' }, 'Could not load the account’s buckets.', errorDetails(err), button({ label: 'Retry', size: 'sm', onClick: loadBuckets })),
      );
    }
  }

  // Prefix scope
  const prefixBox = h('div', { class: 'prefix-list' });
  const addPrefix = () => {
    const input = textInput({ placeholder: 'e.g. photos/', 'aria-label': 'Prefix' });
    const row = h('div', { class: 'input-group' }, input, button({ label: 'Remove', size: 'sm', variant: 'ghost', onClick: () => row.remove() }));
    prefixBox.append(row);
    return input;
  };

  // Expiry
  const expiryMode = select({
    options: [
      { value: 'never', label: 'Never' },
      { value: 'custom', label: 'On a date…' },
    ],
    value: 'never',
    onChange: (v) => expiryInput.classList.toggle('is-hidden', v !== 'custom'),
  });
  const expiryInput = h('input', { type: 'datetime-local', class: 'input is-hidden', 'aria-label': 'Expiry date and time (your local time)' });

  const body = h(
    'div',
    { class: 'form-stack' },
    field({ label: 'Account', control: accountSel }),
    field({ label: 'Name', hint: 'Optional, but a name makes the token recognizable in lists.', control: nameInput }),
    field({ label: 'Actions', hint: 'What the token may do. Choose at least one.', control: actionsBox }),
    field({ label: 'Bucket scope', hint: 'Leave all unchecked to cover every bucket of the account.', control: bucketBox }),
    field({
      label: 'Prefix scope',
      hint: 'Optional. Restricts the token to keys under these prefixes.',
      control: h('div', {}, prefixBox, button({ label: 'Add prefix', size: 'sm', onClick: () => addPrefix().focus() })),
    }),
    field({ label: 'Expires', hint: 'Date and time are in your local time zone.', control: h('div', { class: 'input-group' }, expiryMode, expiryInput) }),
  );
  loadBuckets();

  openDialog({
    title: 'New token',
    body,
    size: 'lg',
    actions: [
      { label: 'Cancel' },
      {
        label: 'Create token',
        variant: 'primary',
        onClick: async () => {
          const accountId = accountSel.value;
          if (!accountId) throw new Error('Choose an account.');
          const allowed = allBox.checked ? ['*'] : actionBoxes.filter((b) => b.el.checked).map((b) => b.action);
          if (allowed.length === 0) throw new Error('Choose at least one action.');
          const payload = { account_id: accountId, name: nameInput.value.trim(), allowed_actions: allowed };
          if (chosenBuckets.size > 0) payload.bucket_scope = [...chosenBuckets];
          const prefixes = [...prefixBox.querySelectorAll('input')].map((i) => i.value.trim()).filter(Boolean);
          if (prefixes.length > 0) payload.prefix_scope = prefixes;
          if (expiryMode.value === 'custom') {
            const when = new Date(expiryInput.value);
            if (!expiryInput.value || Number.isNaN(when.getTime())) throw new Error('Choose the expiry date and time.');
            payload.expires_at = when.toISOString();
          }
          const created = await adminApi('POST', '/tokens', { body: payload });
          if (!created?.token_id || !created?.secret) {
            throw new Error('jay answered 201 without a token id and secret. The token may exist: check the list before retrying.');
          }
          onCreated?.(created);
          showSecretDialog(created);
          return true;
        },
      },
    ],
  });
}

// ---------- view ----------

export async function renderTokens(ctx) {
  ctx.setTitle('Tokens');
  const { signal } = ctx;
  const content = h('div');
  let accounts = null;
  let accountFilter = ctx.query.get('account') || '';
  let statusFilter = 'active';
  let deepLink = ctx.query.get('new') === '1';
  const deepBucket = ctx.query.get('bucket') || '';
  const deepAccount = ctx.query.get('account') || '';

  async function openNew(defaults) {
    try {
      if (!accounts) accounts = await adminApi('GET', '/accounts', { signal });
    } catch (err) {
      if (err.name === 'AbortError') return;
      toast({ tone: 'danger', title: 'Could not load accounts', message: err.message, requestId: err.requestId });
      return;
    }
    if (accounts.length === 0) {
      openDialog({
        title: 'No accounts yet',
        body: 'A token belongs to an account. Create an account first.',
        actions: [{ label: 'Cancel' }, { label: 'Go to Accounts', variant: 'primary', onClick: () => ctx.navigate('#/accounts') }],
      });
      return;
    }
    openNewTokenDialog({ accounts, defaults, onCreated: () => load() });
  }

  ctx.root.replaceChildren(
    pageHeader({ title: 'Tokens', actions: [button({ label: 'New token', icon: 'key', variant: 'primary', onClick: () => openNew({ accountId: accountFilter }) })] }),
    content,
  );

  async function load() {
    loading(content);
    let tokens;
    try {
      [accounts, tokens] = await Promise.all([
        adminApi('GET', '/accounts', { signal }),
        adminApi('GET', '/tokens', { signal, query: { account_id: accountFilter || undefined } }),
      ]);
    } catch (err) {
      if (err.name === 'AbortError' || signal.aborted) return;
      errorState(content, err, { title: 'Could not load tokens', retry: load });
      return;
    }
    if (signal.aborted) return;
    render(tokens);
    if (deepLink) {
      deepLink = false;
      // Leave the one-shot parameters behind so a reload does not reopen the
      // dialog. replaceState does not fire hashchange.
      const keep = deepAccount ? `?account=${encodeURIComponent(deepAccount)}` : '';
      history.replaceState(null, '', `${location.pathname}${location.search}#/tokens${keep}`);
      openNew({ accountId: deepAccount, bucket: deepBucket });
    }
  }

  function render(tokens) {
    const rows = tokens
      .filter((t) => statusFilter === 'all' || tokenState(t).state === statusFilter)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    const filters = h(
      'div',
      { class: 'filter-bar' },
      h(
        'div',
        { class: 'filter' },
        h('label', { for: 'tok-account' }, 'Account'),
        select({
          id: 'tok-account',
          options: [{ value: '', label: 'All accounts' }, ...accounts.map((a) => ({ value: a.account_id, label: a.name || a.account_id }))],
          value: accountFilter,
          onChange: (v) => {
            accountFilter = v;
            load();
          },
        }),
      ),
      h(
        'div',
        { class: 'filter' },
        h('label', { for: 'tok-status' }, 'Status'),
        select({
          id: 'tok-status',
          options: STATUS_OPTIONS,
          value: statusFilter,
          onChange: (v) => {
            statusFilter = v;
            render(tokens);
          },
        }),
      ),
    );
    const empty =
      tokens.length === 0
        ? { icon: 'key', title: 'No tokens yet', body: 'A token is the credential an S3 client uses. Create one to give a client access.', action: { label: 'New token', variant: 'primary', onClick: () => openNew({ accountId: accountFilter }) } }
        : { icon: 'key', title: `No ${statusFilter} tokens`, body: 'Change the status filter to see the others.' };
    content.replaceChildren(filters, tokenTable({ tokens: rows, accounts, onChanged: load, empty }));
  }

  await load();
}
