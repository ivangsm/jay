// Quarantine: objects jay found inconsistent. They are never served and never
// deleted on their own; this page revalidates or purges them, each action
// reported only after the server answered.

import { JayError, adminApi, session } from '../api.js';
import { formatBytes } from '../format.js';
import { button, confirmDestructive, copyButton, dataTable, errorState, h, loading, pageHeader, toast } from '../ui.js';

// purgeAll cannot use adminApi: a partial purge is a 500 whose body carries
// the list of objects that failed, and adminApi keeps only the message.
async function purgeAll() {
  let resp;
  try {
    resp = await fetch('/console/api/admin/quarantine', {
      method: 'DELETE',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-Jay-Console-CSRF': session()?.csrf_token || '' },
      body: JSON.stringify({ mode: 'all' }),
    });
  } catch (e) {
    throw new JayError({ source: 'network', message: `Could not reach jay: ${e.message}` });
  }
  const requestId = resp.headers.get('x-amz-request-id') || '';
  let body = null;
  try {
    body = await resp.json();
  } catch {
    body = null;
  }
  if ((resp.status === 200 || resp.status === 500) && body && typeof body.purged === 'number') {
    return { purged: body.purged, failed: body.failed || [], error: resp.status === 500 ? body.error || 'purge incomplete' : '', requestId };
  }
  throw new JayError({
    status: resp.status,
    message: body?.error || `jay answered ${resp.status} without an error message.`,
    reason: body?.reason || '',
    requestId,
    source: resp.status === 401 ? 'console' : 'admin',
  });
}

function purgeAllResult(result) {
  const failed = result.failed;
  return h(
    'div',
    {},
    h('p', {}, failed.length === 0 ? `Purged ${result.purged} ${result.purged === 1 ? 'object' : 'objects'}.` : `Purged ${result.purged}, failed ${failed.length}.`),
    failed.length > 0
      ? dataTable({
          rows: failed,
          rowKey: (f) => `${f.bucket_id}/${f.key}`,
          columns: [
            { key: 'bucket_id', label: 'Bucket ID', mono: true },
            { key: 'key', label: 'Key', mono: true },
            { key: 'error', label: 'Error' },
          ],
        })
      : null,
  );
}

export async function renderQuarantine(ctx) {
  ctx.setTitle('Quarantine');
  const { signal } = ctx;
  const content = h('div');
  const purgeAllBtn = button({ label: 'Purge all…', variant: 'danger', icon: 'trash', disabled: true, onClick: () => startPurgeAll() });
  ctx.root.replaceChildren(
    pageHeader({
      title: 'Quarantine',
      subtitle: 'Objects jay found inconsistent (checksum mismatch, missing file). They are never served and never deleted on their own.',
      actions: [purgeAllBtn],
    }),
    content,
  );
  let count = 0;

  async function load() {
    purgeAllBtn.disabled = true;
    loading(content);
    let items;
    try {
      items = await adminApi('GET', '/quarantine', { signal });
    } catch (err) {
      if (err.name === 'AbortError' || signal.aborted) return;
      errorState(content, err, { title: 'Could not load the quarantine', retry: load });
      return;
    }
    if (signal.aborted) return;
    count = items.length;
    purgeAllBtn.disabled = count === 0;
    content.replaceChildren(
      dataTable({
        rows: items,
        rowKey: (o) => `${o.bucket_id}/${o.key}`,
        columns: [
          { key: 'bucket', label: 'Bucket', render: (o) => h('span', { title: o.bucket_id }, o.bucket_name || o.bucket_id) },
          { key: 'key', label: 'Key', mono: true },
          { key: 'size', label: 'Size', numeric: true, hideBelow: 600, render: (o) => formatBytes(o.size_bytes) },
          {
            key: 'sum',
            label: 'Expected SHA-256',
            mono: true,
            hideBelow: 900,
            render: (o) => (o.expected_checksum ? h('span', { class: 'id-cell' }, h('span', { title: o.expected_checksum }, `${o.expected_checksum.slice(0, 12)}…`), copyButton(o.expected_checksum, { label: '' })) : ''),
          },
          {
            key: 'ops',
            label: '',
            align: 'right',
            render: (o) =>
              h(
                'span',
                { class: 'row-actions' },
                button({ label: 'Revalidate', size: 'sm', onClick: () => revalidate(o) }),
                button({ label: 'Purge', size: 'sm', variant: 'danger', onClick: () => purge(o) }),
              ),
          },
        ],
        empty: { icon: 'shield', title: 'Nothing in quarantine', body: 'The scrubber verifies stored objects periodically.' },
      }),
    );
  }

  async function revalidate(o) {
    try {
      const r = await adminApi('POST', '/quarantine/revalidate', { body: { bucket_id: o.bucket_id, key: o.key } });
      if (r?.restored === true) toast({ tone: 'ok', title: 'Restored', message: `${o.key}: the bytes match again.` });
      else toast({ tone: 'warn', title: 'Still inconsistent', message: `${o.key} stays in quarantine.` });
    } catch (err) {
      toast({ tone: 'danger', title: 'Revalidate failed', message: err.message, requestId: err.requestId });
      return;
    }
    ctx.refreshShell?.();
    await load();
  }

  async function purge(o) {
    const r = await confirmDestructive({
      title: `Purge ${o.key}`,
      description: `This deletes the quarantined object ${o.key} from ${o.bucket_name || o.bucket_id} for good, bytes included.`,
      confirmPhrase: o.key,
      actionLabel: 'Purge object',
      run: async () => {
        await adminApi('DELETE', '/quarantine', { body: { bucket_id: o.bucket_id, key: o.key } });
        return { purged: true };
      },
    });
    if (!r?.purged) return;
    toast({ tone: 'ok', title: 'Object purged', message: o.key });
    ctx.refreshShell?.();
    await load();
  }

  async function startPurgeAll() {
    const r = await confirmDestructive({
      title: 'Purge all quarantined objects',
      description: `This deletes all ${count} quarantined objects for good, bytes included.`,
      confirmPhrase: 'purge all',
      actionLabel: 'Purge all',
      run: async () => {
        const res = await purgeAll();
        // A partial purge already removed objects: show the outcome instead of
        // an error that hides how many are gone.
        return res;
      },
      renderResult: purgeAllResult,
    });
    if (!r) return;
    ctx.refreshShell?.();
    await load();
  }

  await load();
}
