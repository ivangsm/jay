// Accounts: the list, one account's page, and account/bucket creation. An
// account cannot be renamed, suspended or deleted: jay has no such operation.

import { adminApi } from '../api.js';
import { formatCount, formatDate, formatDateTime, bucketNameProblem } from '../format.js';
import {
  badge,
  button,
  copyButton,
  dataTable,
  emptyState,
  errorState,
  field,
  h,
  keyValueList,
  loading,
  openDialog,
  pageHeader,
  textInput,
  toast,
} from '../ui.js';
import { tokenTable } from './tokens.js';

function statusBadge(status) {
  return badge(status || 'unknown', status === 'active' ? 'ok' : 'warn');
}

function idCell(id) {
  return h('span', { class: 'id-cell' }, h('span', { title: id }, `${id.slice(0, 8)}…`), copyButton(id, { label: '' }));
}

function newAccountDialog(ctx) {
  const nameInput = textInput({ placeholder: 'e.g. falco', maxlength: '128' });
  // A single-field dialog submits on Enter, like the confirm dialogs do.
  nameInput.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    nameInput.closest('dialog')?.querySelector('.btn-primary:not(:disabled)')?.click();
  });
  openDialog({
    title: 'New account',
    size: 'sm',
    body: field({ label: 'Name', hint: 'Accounts cannot be renamed later.', control: nameInput }),
    actions: [
      { label: 'Cancel' },
      {
        label: 'Create account',
        variant: 'primary',
        onClick: async () => {
          const name = nameInput.value.trim();
          if (!name) throw new Error('Enter a name.');
          const created = await adminApi('POST', '/accounts', { body: { name } });
          if (!created?.account_id) throw new Error('jay answered 201 without an account id. Check the list before retrying.');
          toast({ tone: 'ok', title: 'Account created', message: name });
          ctx.navigate(`#/accounts/${encodeURIComponent(created.account_id)}`);
          return true;
        },
      },
    ],
  });
}

// newBucketDialog creates a bucket owned by `account` (fixed: the page is
// the account's).
function newBucketDialog(account, onCreated) {
  const nameInput = textInput({ placeholder: 'e.g. assets', maxlength: '63', autocapitalize: 'off', spellcheck: 'false' });
  const problem = h('div', { class: 'field-hint' });
  nameInput.addEventListener('input', () => {
    problem.textContent = nameInput.value ? bucketNameProblem(nameInput.value) : '';
  });
  openDialog({
    title: 'New bucket',
    size: 'sm',
    body: h('div', { class: 'form-stack' }, field({ label: 'Name', control: nameInput }), problem, h('p', { class: 'muted' }, `Owner: ${account.name || account.account_id}`)),
    actions: [
      { label: 'Cancel' },
      {
        label: 'Create bucket',
        variant: 'primary',
        onClick: async () => {
          const name = nameInput.value.trim();
          const bad = bucketNameProblem(name);
          if (bad) throw new Error(bad);
          await adminApi('POST', '/buckets', { body: { name, owner_account_id: account.account_id } });
          toast({ tone: 'ok', title: 'Bucket created', message: name });
          onCreated();
          return true;
        },
      },
    ],
  });
}

export async function renderAccounts(ctx) {
  ctx.setTitle('Accounts');
  const { signal } = ctx;
  const content = h('div');
  ctx.root.replaceChildren(
    pageHeader({ title: 'Accounts', actions: [button({ label: 'New account', icon: 'user', variant: 'primary', onClick: () => newAccountDialog(ctx) })] }),
    content,
  );

  async function load() {
    loading(content);
    let accounts;
    let buckets;
    let tokens;
    try {
      [accounts, buckets, tokens] = await Promise.all([
        adminApi('GET', '/accounts', { signal }),
        adminApi('GET', '/buckets', { signal }),
        adminApi('GET', '/tokens', { signal }),
      ]);
    } catch (err) {
      if (err.name === 'AbortError' || signal.aborted) return;
      errorState(content, err, { title: 'Could not load accounts', retry: load });
      return;
    }
    if (signal.aborted) return;
    const bucketCount = (id) => buckets.filter((b) => b.owner_account_id === id).length;
    const tokenCount = (id) => tokens.filter((t) => t.account_id === id && t.status === 'active').length;
    content.replaceChildren(
      dataTable({
        rows: accounts,
        rowKey: 'account_id',
        onRowClick: (a) => ctx.navigate(`#/accounts/${encodeURIComponent(a.account_id)}`),
        columns: [
          { key: 'name', label: 'Name', render: (a) => h('a', { href: `#/accounts/${encodeURIComponent(a.account_id)}` }, a.name || a.account_id) },
          { key: 'id', label: 'ID', mono: true, hideBelow: 600, render: (a) => idCell(a.account_id) },
          { key: 'status', label: 'Status', render: (a) => statusBadge(a.status) },
          { key: 'buckets', label: 'Buckets', numeric: true, render: (a) => formatCount(bucketCount(a.account_id)) },
          { key: 'tokens', label: 'Active tokens', numeric: true, hideBelow: 600, render: (a) => formatCount(tokenCount(a.account_id)) },
          { key: 'created', label: 'Created', hideBelow: 900, render: (a) => formatDate(a.created_at) },
        ],
        empty: {
          icon: 'user',
          title: 'No accounts yet',
          body: 'An account owns buckets and tokens. Create one to start.',
          action: { label: 'New account', variant: 'primary', onClick: () => newAccountDialog(ctx) },
        },
      }),
    );
  }

  await load();
}

export async function renderAccount(ctx) {
  const id = ctx.params.id;
  ctx.setTitle('Account');
  const { signal } = ctx;
  const content = h('div');
  ctx.root.replaceChildren(pageHeader({ title: 'Account', breadcrumbs: [{ label: 'Accounts', href: '#/accounts' }, { label: id }] }), content);

  async function load() {
    loading(content);
    let accounts;
    let buckets;
    let tokens;
    try {
      [accounts, buckets, tokens] = await Promise.all([
        adminApi('GET', '/accounts', { signal }),
        adminApi('GET', '/buckets', { signal, query: { owner_account_id: id } }),
        adminApi('GET', '/tokens', { signal, query: { account_id: id } }),
      ]);
    } catch (err) {
      if (err.name === 'AbortError' || signal.aborted) return;
      errorState(content, err, { title: 'Could not load the account', retry: load });
      return;
    }
    if (signal.aborted) return;
    const account = accounts.find((a) => a.account_id === id);
    if (!account) {
      emptyState(content, {
        icon: 'alert',
        title: 'Account not found',
        body: `No account has the id ${id}.`,
        action: { label: 'Back to accounts', onClick: () => ctx.navigate('#/accounts') },
      });
      return;
    }
    const name = account.name || account.account_id;
    ctx.setTitle(name);
    ctx.root.replaceChildren(
      pageHeader({ title: name, breadcrumbs: [{ label: 'Accounts', href: '#/accounts' }, { label: name }] }),
      content,
    );

    const bucketsTable = dataTable({
      rows: buckets,
      rowKey: 'id',
      onRowClick: (b) => ctx.navigate(`#/buckets/${encodeURIComponent(b.name)}`),
      columns: [
        { key: 'name', label: 'Name', render: (b) => h('a', { href: `#/buckets/${encodeURIComponent(b.name)}` }, b.name) },
        { key: 'vis', label: 'Visibility', render: (b) => badge(b.visibility, b.visibility === 'public-read' ? 'warn' : 'neutral') },
        { key: 'objects', label: 'Objects', numeric: true, hideBelow: 600, render: (b) => formatCount(b.object_count) },
        { key: 'created', label: 'Created', hideBelow: 900, render: (b) => formatDate(b.created_at) },
      ],
      empty: { icon: 'bucket', title: 'No buckets', body: 'This account owns no buckets yet.' },
    });
    const tokensTable = tokenTable({
      tokens,
      accounts,
      showAccount: false,
      onChanged: load,
      empty: { icon: 'key', title: 'No tokens', body: 'This account has no tokens yet.' },
    });

    content.replaceChildren(
      h(
        'section',
        { class: 'card' },
        keyValueList([
          ['Account ID', h('span', {}, h('code', {}, account.account_id), ' ', copyButton(account.account_id))],
          ['Status', statusBadge(account.status)],
          ['Created', formatDateTime(account.created_at)],
        ]),
        h('p', { class: 'muted' }, 'Accounts cannot be renamed, suspended or deleted yet.'),
      ),
      h('div', { class: 'section-head' }, h('h2', {}, 'Buckets'), button({ label: 'New bucket', icon: 'bucket', onClick: () => newBucketDialog(account, load) })),
      bucketsTable,
      h(
        'div',
        { class: 'section-head' },
        h('h2', {}, 'Tokens'),
        button({ label: 'New token', icon: 'key', onClick: () => ctx.navigate(`#/tokens?new=1&account=${encodeURIComponent(account.account_id)}`) }),
      ),
      tokensTable,
    );
  }

  await load();
}
