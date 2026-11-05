// Buckets: every bucket with its owner, visibility, policy and counters, and
// the dialog that creates one. A failed read is an error with Retry, never an
// empty table.

import { adminApi } from '../api.js';
import { bucketNameProblem, exactBytes, formatBytes, formatCount, formatDate } from '../format.js';
import { badge, button, dataTable, emptyState, errorState, field, h, loading, openDialog, pageHeader, select, textInput, toast } from '../ui.js';

export async function renderBuckets(ctx) {
  ctx.setTitle('Buckets');
  const { signal } = ctx;
  const owner = ctx.query.get('owner') || '';
  const content = h('div');
  const newBtn = button({ label: 'New bucket', icon: 'bucket', variant: 'primary', onClick: () => openCreate() });
  ctx.root.replaceChildren(pageHeader({ title: 'Buckets', actions: [newBtn] }), content);

  let accounts = [];

  async function load() {
    loading(content, 'Loading buckets…');
    let buckets;
    try {
      [buckets, accounts] = await Promise.all([
        adminApi('GET', '/buckets', { query: { owner_account_id: owner }, signal }),
        adminApi('GET', '/accounts', { signal }),
      ]);
    } catch (err) {
      if (err.name === 'AbortError' || signal.aborted) return;
      errorState(content, err, { title: 'Could not load the buckets', retry: load });
      return;
    }
    if (signal.aborted) return;
    paint(buckets);
  }

  function paint(buckets) {
    const names = new Map(accounts.map((a) => [a.account_id, a.name]));
    const ownerSelect = select({
      id: 'owner-filter',
      value: owner,
      options: [{ value: '', label: 'All accounts' }, ...accounts.map((a) => ({ value: a.account_id, label: a.name || a.account_id }))],
      onChange: (v) => ctx.navigate(v ? `/buckets?owner=${encodeURIComponent(v)}` : '/buckets'),
    });
    const filter = h('div', { class: 'toolbar' }, field({ label: 'Owner', control: ownerSelect }));

    let table;
    if (buckets.length === 0) {
      table = h('div');
      emptyState(table, {
        icon: 'bucket',
        title: owner ? 'This account has no buckets' : 'No buckets yet',
        body: accounts.length === 0 ? 'A bucket belongs to an account. Create an account first.' : 'Create a bucket to start storing objects.',
        action: accounts.length === 0 ? h('a', { href: '#/accounts' }, 'Go to accounts') : { label: 'New bucket', icon: 'bucket', variant: 'primary', onClick: () => openCreate() },
      });
    } else {
      table = dataTable({
        rowKey: 'name',
        rows: buckets,
        onRowClick: (b) => ctx.navigate(`/buckets/${encodeURIComponent(b.name)}`),
        columns: [
          { key: 'name', label: 'Name', render: (b) => h('a', { href: `#/buckets/${encodeURIComponent(b.name)}` }, b.name), mono: true },
          { key: 'owner', label: 'Owner', render: (b) => h('span', { title: b.owner_account_id }, names.get(b.owner_account_id) || b.owner_account_id) },
          { key: 'visibility', label: 'Visibility', render: (b) => (b.visibility === 'public-read' ? badge('PUBLIC READ', 'warn') : badge('private')) },
          { key: 'policy', label: 'Policy', render: (b) => (b.has_policy ? 'yes' : '—'), hideBelow: 600 },
          { key: 'object_count', label: 'Objects', numeric: true, render: (b) => formatCount(b.object_count) },
          { key: 'total_size_bytes', label: 'Size', numeric: true, render: (b) => h('span', { title: exactBytes(b.total_size_bytes) }, formatBytes(b.total_size_bytes)) },
          { key: 'created_at', label: 'Created', hideBelow: 900, render: (b) => formatDate(b.created_at) },
        ],
      });
    }
    content.replaceChildren(filter, table);
    content.removeAttribute('aria-busy');
  }

  function openCreate() {
    if (accounts.length === 0) {
      toast({ tone: 'warn', title: 'Create an account first', message: 'A bucket belongs to an account, and there are none yet.' });
      return;
    }
    const nameInput = textInput({ id: 'new-bucket-name', placeholder: 'my-bucket', spellcheck: 'false', autocapitalize: 'off' });
    const problem = h('div', { class: 'field-error', role: 'status' });
    nameInput.addEventListener('input', () => {
      problem.textContent = nameInput.value ? bucketNameProblem(nameInput.value) : '';
    });
    const ownerSel = select({
      id: 'new-bucket-owner',
      value: owner || accounts[0].account_id,
      options: accounts.map((a) => ({ value: a.account_id, label: a.name || a.account_id })),
    });
    const form = h(
      'form',
      { on: { submit: (e) => e.preventDefault() } },
      field({ label: 'Name', control: nameInput, hint: '3 to 63 characters: lowercase letters, digits, "." and "-".' }),
      problem,
      field({ label: 'Owner account', control: ownerSel }),
    );
    openDialog({
      title: 'New bucket',
      body: form,
      actions: [
        { label: 'Cancel' },
        {
          label: 'Create bucket',
          variant: 'primary',
          onClick: async () => {
            const name = nameInput.value.trim();
            const bad = bucketNameProblem(name);
            if (bad) throw new Error(bad);
            const created = await adminApi('POST', '/buckets', { body: { name, owner_account_id: ownerSel.value } });
            toast({ tone: 'ok', title: 'Bucket created', message: created?.name || name });
            ctx.navigate(`/buckets/${encodeURIComponent(created?.name || name)}`);
          },
        },
      ],
    });
  }

  await load();
}
