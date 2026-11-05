// Overview: readiness, durability, storage totals and the counters since
// start. Every card has its own loading and error state, so one failing
// source never blanks the others and never reads as "zero".

import { adminApi, getHealth } from '../api.js';
import { badge, button, clear, emptyState, errorState, h, icon, loading, pageHeader } from '../ui.js';
import { DOCS_URL, formatBytes, formatCount, formatDuration, tokenState } from '../format.js';

const BACKUP_GUIDE = `${DOCS_URL}guides/backup-and-restore/`;
const OBSERVABILITY_GUIDE = `${DOCS_URL}reference/observability/`;

function docsLink(label, href = DOCS_URL) {
  return h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, label, ' ', icon('external', { size: 12 }));
}

function makeCard(title) {
  const body = h('div');
  const el = h('section', { class: 'card', 'aria-label': title }, h('h2', { class: 'card-title' }, title), body);
  return { el, body };
}

// fill runs one card: loading, then data or an error with its own retry.
async function fill(card, fetcher, render, signal, attempt = 0) {
  loading(card.body, 'Loading…');
  try {
    const data = await fetcher(attempt);
    if (signal.aborted) return;
    clear(card.body);
    card.el.classList.remove('card-danger', 'card-warn');
    render(card, data);
  } catch (err) {
    if (err.name === 'AbortError' || signal.aborted) return;
    card.el.classList.remove('card-danger', 'card-warn');
    errorState(card.body, err, { title: 'Could not load', retry: () => fill(card, fetcher, render, signal, attempt + 1) });
  }
}

function line(text) {
  return h('p', { class: 'card-line' }, text);
}

function counterTone(key, value) {
  const alarming = key.endsWith('_failures') || key === 'panics_recovered';
  return alarming && value > 0 ? 'is-danger' : '';
}

function formatCounter(key, value) {
  if (typeof value !== 'number') return String(value);
  return key.startsWith('bytes_') ? formatBytes(value) : formatCount(value);
}

export async function renderOverview(ctx) {
  ctx.setTitle('Overview');
  const { signal } = ctx;
  const content = h('div');
  const refresh = button({ label: 'Refresh', icon: 'refresh', onClick: () => load() });
  ctx.root.replaceChildren(pageHeader({ title: 'Overview', actions: [refresh] }), content);

  async function load() {
    content.replaceChildren();
    // The three health cards share one probe, so a Refresh costs one request;
    // a card's own Retry (attempt > 0) probes again.
    let healthP = null;
    const healthFetch = (attempt) => {
      if (attempt > 0 || !healthP) healthP = getHealth({ signal });
      return healthP;
    };

    const ready = makeCard('Readiness');
    const meta = makeCard('Metadata backup');
    const bytes = makeCard('Object bytes backup');
    const storage = makeCard('Storage');
    const accounts = makeCard('Accounts');
    const tokens = makeCard('Tokens');
    const quarantine = makeCard('Quarantine');

    const countersHead = h('div', { class: 'page-header' });
    const countersBody = h('div');
    content.append(
      h('div', { class: 'grid grid-3' }, ready.el, meta.el, bytes.el),
      h('div', { class: 'grid grid-4' }, storage.el, accounts.el, tokens.el, quarantine.el),
      countersHead,
      countersBody,
      h('p', { class: 'muted' }, 'For time series, scrape GET /metrics with Prometheus (', docsLink('docs', OBSERVABILITY_GUIDE), ').'),
    );

    await Promise.all([
      fill(ready, healthFetch, renderReady, signal),
      fill(meta, healthFetch, renderMetaBackup, signal),
      fill(bytes, healthFetch, renderBytesBackup, signal),
      fill(storage, () => adminApi('GET', '/buckets', { signal }), renderStorage, signal),
      fill(accounts, () => adminApi('GET', '/accounts', { signal }), renderAccounts, signal),
      fill(tokens, () => adminApi('GET', '/tokens', { signal }), renderTokens, signal),
      fill(quarantine, () => adminApi('GET', '/quarantine', { signal }), renderQuarantine, signal),
      loadCounters(),
    ]);

    async function loadCounters() {
      loading(countersBody, 'Loading counters…');
      try {
        const snap = await adminApi('GET', '/metrics', { signal });
        if (signal.aborted) return;
        clear(countersBody);
        renderCounters(countersHead, countersBody, snap, ctx.session);
      } catch (err) {
        if (err.name === 'AbortError' || signal.aborted) return;
        countersHead.replaceChildren(h('h2', {}, 'Counters since start'));
        errorState(countersBody, err, { title: 'Could not load counters', retry: loadCounters });
      }
    }
  }

  function renderReady(card, hlt) {
    const ok = hlt.httpStatus === 200;
    card.el.classList.toggle('card-danger', !ok);
    card.body.append(
      h('div', { class: 'card-value' }, h('span', { class: ['status-dot', ok ? 'ok' : 'danger'] }), ok ? 'Ready' : 'Not ready'),
      line(`/health/ready ${hlt.httpStatus}`),
    );
    if (!ok) card.body.append(line(hlt.reason || hlt.status || 'No reason reported.'));
  }

  function renderMetaBackup(card, hlt) {
    const d = hlt.durability;
    if (!d) {
      card.body.append(line('The readiness probe did not report durability.'));
      card.el.classList.add('card-warn');
      return;
    }
    card.body.append(line(d.metadata_backup || 'No description reported.'));
    if (d.metadata_backup_dir) card.body.append(h('p', { class: 'card-line mono' }, d.metadata_backup_dir));
    if (d.metadata_backup_dir_problem) {
      card.el.classList.add('card-warn');
      card.body.append(h('p', {}, badge('Unchecked', 'warn'), ' ', d.metadata_backup_dir_problem));
    } else if (d.metadata_backup_shares_data_filesystem) {
      card.el.classList.add('card-warn');
      card.body.append(h('p', {}, badge('Same filesystem as data', 'warn'), ' One disk failure takes both.'));
    }
  }

  function renderBytesBackup(card, hlt) {
    const d = hlt.durability;
    card.el.classList.add('card-warn');
    card.body.append(
      h('p', {}, badge('No backup', 'warn')),
      line(d?.object_bytes_backup || 'jay does not back up object bytes.'),
      h('p', {}, docsLink('Backup and restore', BACKUP_GUIDE)),
    );
  }

  function renderStorage(card, buckets) {
    const objects = buckets.reduce((n, b) => n + (b.object_count || 0), 0);
    const size = buckets.reduce((n, b) => n + (b.total_size_bytes || 0), 0);
    card.body.append(
      h('div', { class: 'card-value' }, `${formatCount(buckets.length)} ${buckets.length === 1 ? 'bucket' : 'buckets'}`),
      line(`${formatCount(objects)} ${objects === 1 ? 'object' : 'objects'}`),
      h('p', { class: 'card-line', title: `${formatCount(size)} bytes` }, formatBytes(size)),
      h('p', { class: 'card-link' }, h('a', { href: '#/buckets' }, 'Buckets →')),
    );
  }

  function renderAccounts(card, accounts) {
    card.body.append(
      h('div', { class: 'card-value' }, formatCount(accounts.length)),
      h('p', { class: 'card-link' }, h('a', { href: '#/accounts' }, 'Accounts →')),
    );
  }

  function renderTokens(card, tokens) {
    const states = tokens.map((t) => tokenState(t).state);
    const active = states.filter((s) => s === 'active').length;
    card.body.append(
      h('div', { class: 'card-value' }, `${formatCount(active)} active`),
      line(`${formatCount(tokens.length - active)} revoked or expired`),
      h('p', { class: 'card-link' }, h('a', { href: '#/tokens' }, 'Tokens →')),
    );
  }

  function renderQuarantine(card, items) {
    const n = items.length;
    card.el.classList.toggle('card-danger', n > 0);
    card.body.append(
      h('div', { class: 'card-value' }, `${formatCount(n)} ${n === 1 ? 'object' : 'objects'}`),
      line(n > 0 ? 'Failed an integrity check and was set aside.' : 'Nothing set aside.'),
      h('p', { class: 'card-link' }, h('a', { href: '#/quarantine' }, 'Quarantine →')),
    );
  }

  function renderCounters(head, body, snap, sess) {
    const entries = Object.entries(snap).filter(([k, v]) => k !== 'uptime_seconds' && typeof v === 'number');
    head.replaceChildren(
      h('div', {}, h('h2', {}, 'Counters since start'), h('p', { class: 'subtitle' }, `uptime ${formatDuration(snap.uptime_seconds)}`)),
      sess ? h('p', { class: 'muted mono' }, `Server v${sess.version} (${sess.commit})`) : null,
    );
    if (entries.length === 0) {
      emptyState(body, { title: 'No counters reported' });
      return;
    }
    body.append(
      h(
        'div',
        { class: 'table-wrap' },
        h(
          'table',
          { class: 'table kv-table' },
          h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Counter'), h('th', { scope: 'col', class: 'right' }, 'Value'))),
          h(
            'tbody',
            {},
            entries.map(([k, v]) =>
              h(
                'tr',
                {},
                h('td', { 'data-label': 'Counter' }, k),
                h('td', { 'data-label': 'Value', class: ['numeric', counterTone(k, v)], title: k.startsWith('bytes_') ? `${formatCount(v)} bytes` : undefined }, formatCounter(k, v)),
              ),
            ),
          ),
        ),
      ),
    );
  }

  await load();
}
