// Bucket browser: prefixes as folders, objects, uploads and deletes. The
// console acts as one token ("browse as"), so everything on this screen is what
// that token can see and do. Every failure is shown as a failure.

import { adminApi, s3Api } from '../api.js';
import { dirPrefix, exactBytes, formatBytes, formatCount, formatRelative, splitPrefix, tokenState } from '../format.js';
import { getBrowseAs, setBrowseAs } from '../prefs.js';
import { buildDeleteBody, parseDeleteResult, parseListObjects } from '../s3xml.js';
import { checkOverwrites, startUpload } from '../upload.js';
import { badge, button, checkbox, confirmDestructive, dataTable, emptyState, errorState, field, h, icon, loading, menuButton, openDialog, pageHeader, progressBar, textInput, toast } from '../ui.js';
import { explainRefusal, openObjectDrawer } from './object-drawer.js';

// The object drawer is opened from here.
export { openObjectDrawer };

const BATCH = 1000;
const UPLOAD_PARALLEL_FILES = 3;
const FAILURES_SHOWN = 100;

// ---------- "browse as" tokens (shared with bucket settings) ----------

export function tokenLabel(t) {
  const id = `${t.token_id.slice(0, 8)}…`;
  return t.name ? `${t.name} (${id})` : id;
}

// browseTokens splits the active tokens into those that should be able to
// browse this bucket (owner account, may list, scope allows the bucket) and the
// rest, which jay may refuse.
export function browseTokens(bucket, tokens) {
  const mine = [];
  const others = [];
  for (const t of tokens) {
    if (tokenState(t).state !== 'active') continue;
    const actions = t.allowed_actions || [];
    const scope = t.bucket_scope || [];
    const fits = t.account_id === bucket.owner_account_id && (actions.includes('*') || actions.includes('object:list')) && (scope.length === 0 || scope.includes(bucket.name));
    (fits ? mine : others).push(t);
  }
  return { mine, others };
}

// pickToken resolves the token in use: the URL, then the remembered one, then
// the first token that should work. Never a token that is not usable.
export function pickToken(groups, bucketName, asParam) {
  const all = [...groups.mine, ...groups.others];
  const byId = (id) => (id ? all.find((t) => t.token_id === id) : undefined);
  return byId(asParam) || byId(getBrowseAs(bucketName)) || groups.mine[0] || null;
}

// tokenPicker is the "browse as" select, with the two groups.
export function tokenPicker(groups, current, onChange) {
  const sel = h('select', { class: 'select', id: 'browse-as', 'aria-label': 'Browse as' });
  if (!current) sel.append(h('option', { value: '' }, 'Choose a token…'));
  if (groups.mine.length) sel.append(h('optgroup', { label: 'Tokens that should work' }, groups.mine.map((t) => h('option', { value: t.token_id }, tokenLabel(t)))));
  if (groups.others.length) sel.append(h('optgroup', { label: 'Other tokens (may be refused)' }, groups.others.map((t) => h('option', { value: t.token_id }, tokenLabel(t)))));
  sel.value = current ? current.token_id : '';
  sel.addEventListener('change', () => onChange(sel.value));
  return sel;
}

export function noTokenState(container, bucket, navigate) {
  emptyState(container, {
    icon: 'key',
    title: 'No usable token can browse this bucket',
    body: 'The console acts as a token: it sees and can do exactly what the token can. Create one for this bucket to browse it.',
    action: {
      label: 'Create a token',
      icon: 'key',
      variant: 'primary',
      onClick: () => navigate(`/tokens?new=1&account=${encodeURIComponent(bucket.owner_account_id)}&bucket=${encodeURIComponent(bucket.name)}`),
    },
  });
}

// ---------- uploads: a registry that outlives a render ----------

const uploads = []; // every entry of this page load, newest last
const subscribers = new Set();
let nextEntryId = 0;
let mounted = null; // { bucket, reload } while a browser is on screen
let paintTimer = 0;

const TERMINAL = new Set(['done', 'failed', 'cancelled']);
const isActive = (e) => !TERMINAL.has(e.state);

function notify() {
  if (paintTimer) return;
  paintTimer = setTimeout(() => {
    paintTimer = 0;
    for (const fn of subscribers) fn();
  }, 150);
}

window.addEventListener('beforeunload', (e) => {
  if (uploads.some(isActive)) {
    e.preventDefault();
    e.returnValue = '';
  }
});

function makeEntry(bucket, key, file, tokenName) {
  return { id: ++nextEntryId, bucket, key, file, size: file.size, state: 'queued', detail: '', loaded: 0, part: 0, parts: 0, error: null, handle: null, tokenName };
}

function runEntry(entry, asToken) {
  entry.handle = startUpload({
    bucket: entry.bucket,
    key: entry.key,
    file: entry.file,
    asToken,
    onProgress: (p) => {
      entry.loaded = p.loaded;
      entry.part = p.part;
      entry.parts = p.parts;
      notify();
    },
    onState: (state, detail) => {
      entry.state = state;
      entry.detail = detail || '';
      notify();
    },
  });
  return entry.handle.done.catch((err) => {
    if (err.name !== 'AbortError') entry.error = err;
  });
}

// runBatch uploads the entries 3 files at a time and, when all are over,
// re-lists the bucket if it is still on screen.
async function runBatch(entries, asToken) {
  let i = 0;
  async function worker() {
    while (i < entries.length) {
      const e = entries[i++];
      if (e.state === 'cancelled') continue;
      await runEntry(e, asToken);
    }
  }
  await Promise.all(Array.from({ length: Math.min(UPLOAD_PARALLEL_FILES, entries.length) }, worker));
  const done = entries.filter((e) => e.state === 'done').length;
  if (done === entries.length) toast({ tone: 'ok', title: `Uploaded ${formatCount(done)} ${done === 1 ? 'file' : 'files'}`, message: `${entries[0].bucket}` });
  else toast({ tone: 'warn', title: `Uploaded ${formatCount(done)} of ${formatCount(entries.length)}`, message: 'See the uploads panel for what failed.' });
  if (mounted && mounted.bucket === entries[0].bucket) mounted.reload();
}

function uploadRow(entry) {
  const cancel = isActive(entry) && entry.state !== 'aborting' ? button({ label: 'Cancel', size: 'sm', variant: 'ghost', onClick: () => cancelEntry(entry) }) : null;
  let status;
  if (entry.state === 'done') {
    status = h('span', { class: 'up-ok' }, icon('check'), ` uploaded (ETag ${entry.detail || 'none'})`);
  } else if (entry.state === 'failed') {
    status = h('div', { class: 'up-fail' }, h('span', {}, icon('x'), ` ${entry.detail}`), entry.error ? explainRefusal(entry.error, entry.tokenName) : null);
  } else if (entry.state === 'cancelled') {
    status = h('span', { class: 'muted' }, entry.detail);
  } else if (entry.state === 'queued') {
    status = h('span', { class: 'muted' }, 'Waiting');
  } else if (entry.state === 'checking') {
    status = h('span', { class: 'muted' }, 'Checking whether the key exists…');
  } else if (entry.state === 'aborting') {
    status = h('span', { class: 'muted' }, 'Aborting the incomplete upload…');
  } else {
    const fraction = entry.size > 0 ? entry.loaded / entry.size : null;
    const where = entry.parts > 1 ? ` · part ${entry.part}/${entry.parts}` : '';
    const label = entry.state === 'completing' ? 'Completing…' : `${fraction === null ? '' : `${Math.round(fraction * 100)}%`}${where}`;
    status = h('div', { class: 'up-progress' }, progressBar(entry.state === 'completing' ? null : fraction, { label: `Uploading ${entry.key}` }), h('span', { class: 'muted num' }, label));
  }
  return h('li', { class: 'up-row' }, h('div', { class: 'up-name' }, h('code', {}, entry.key), ' ', h('span', { class: 'muted' }, formatBytes(entry.size))), h('div', { class: 'up-status' }, status), cancel ? h('div', { class: 'up-act' }, cancel) : null);
}

function cancelEntry(entry) {
  if (entry.state === 'queued') {
    entry.state = 'cancelled';
    entry.detail = 'Cancelled before it started.';
    notify();
    return;
  }
  entry.handle?.cancel();
}

// ---------- listing helpers ----------

async function deleteBatch(bucket, asToken, keys) {
  const out = await s3Api('POST', bucket, '', { asToken, query: { delete: true }, headers: { 'Content-Type': 'application/xml' }, body: buildDeleteBody(keys) });
  const r = parseDeleteResult(out.xml);
  // A key that is neither deleted nor reported failed is a failure of ours to
  // know, and it is shown as one.
  const seen = new Set([...r.deleted, ...r.errors.map((e) => e.key)]);
  for (const k of keys) if (!seen.has(k)) r.errors.push({ key: k, code: '', message: 'jay did not report this key' });
  return r;
}

function failureList(failed) {
  if (failed.length === 0) return null;
  const shown = failed.slice(0, FAILURES_SHOWN);
  return h(
    'div',
    {},
    h('p', {}, h('strong', {}, `${formatCount(failed.length)} could not be deleted:`)),
    h('ul', { class: 'fail-list' }, shown.map((f) => h('li', {}, h('code', {}, f.key), ' — ', [f.code, f.message].filter(Boolean).join(': ')))),
    failed.length > shown.length ? h('p', { class: 'muted' }, `…and ${formatCount(failed.length - shown.length)} more.`) : null,
  );
}

// entriesOf walks a dropped DataTransfer, folders included.
async function entriesOf(dt) {
  const out = [];
  const items = Array.from(dt.items || []);
  const roots = items.map((it) => (it.kind === 'file' && it.webkitGetAsEntry ? it.webkitGetAsEntry() : null));
  if (roots.every((r) => r === null)) return Array.from(dt.files || []).map((file) => ({ file, path: file.name }));
  async function walk(entry, base) {
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      out.push({ file, path: `${base}${entry.name}` });
      return;
    }
    const reader = entry.createReader();
    for (;;) {
      const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
      if (batch.length === 0) break;
      for (const child of batch) await walk(child, `${base}${entry.name}/`);
    }
  }
  for (const r of roots) if (r) await walk(r, '');
  return out;
}

// fill replaces the children of `el`, skipping null and false: replaceChildren
// alone would turn them into the text "null".
function fill(el, ...nodes) {
  el.replaceChildren(...nodes.filter(Boolean));
}

function extensionOf(name) {
  const i = name.lastIndexOf('.');
  return i > 0 && i < name.length - 1 ? name.slice(i + 1).toLowerCase() : '';
}

export async function renderBucket(ctx) {
  const name = ctx.params.name;
  const prefix = ctx.query.get('prefix') || '';
  const asParam = ctx.query.get('as') || '';
  const { signal } = ctx;
  ctx.setTitle(name);
  const enc = encodeURIComponent;
  const hashFor = ({ pfx = prefix, as } = {}) => {
    const q = new URLSearchParams();
    if (pfx) q.set('prefix', pfx);
    const token = as ?? asParam;
    if (token) q.set('as', token);
    const s = q.toString();
    return `/buckets/${enc(name)}${s ? `?${s}` : ''}`;
  };

  const content = h('div');
  ctx.root.replaceChildren(content);

  let bucket = null;
  let groups = { mine: [], others: [] };
  let current = null;
  let accountName = '';

  async function load() {
    loading(content, 'Loading the bucket…');
    let buckets;
    let accounts;
    let tokens;
    try {
      [buckets, accounts, tokens] = await Promise.all([adminApi('GET', '/buckets', { signal }), adminApi('GET', '/accounts', { signal }), adminApi('GET', '/tokens', { signal })]);
    } catch (err) {
      if (err.name === 'AbortError' || signal.aborted) return;
      errorState(content, err, { title: 'Could not load the bucket', retry: load });
      return;
    }
    if (signal.aborted) return;
    bucket = buckets.find((b) => b.name === name) || null;
    if (!bucket) {
      emptyState(content, { icon: 'alert', title: 'Bucket not found', body: `There is no bucket named ${name}.`, action: h('a', { href: '#/buckets' }, 'Back to the buckets') });
      return;
    }
    accountName = accounts.find((a) => a.account_id === bucket.owner_account_id)?.name || bucket.owner_account_id;
    groups = browseTokens(bucket, tokens);
    current = pickToken(groups, name, asParam);
    mount();
  }

  // ----- the screen -----

  function mount() {
    const header = pageHeader({
      title: name,
      subtitle: h('span', {}, bucket.visibility === 'public-read' ? badge('PUBLIC READ', 'warn') : badge('private'), ` owner ${accountName}`),
      actions: [button({ label: 'Settings', icon: 'settings', onClick: () => ctx.navigate(`/buckets/${enc(name)}/settings${current ? `?as=${enc(current.token_id)}` : ''}`) })],
    });
    const bar = h(
      'div',
      { class: 'browse-bar' },
      field({
        label: 'Browse as',
        control: tokenPicker(groups, current, (id) => {
          setBrowseAs(name, id);
          ctx.navigate(hashFor({ as: id }));
        }),
        hint: 'The console acts as this token: it sees and can do exactly what the token can.',
      }),
    );
    if (!current) {
      const empty = h('div');
      noTokenState(empty, bucket, ctx.navigate);
      content.replaceChildren(header, bar, empty);
      content.removeAttribute('aria-busy');
      return;
    }

    const asToken = current.token_id;
    const label = tokenLabel(current);
    const selected = new Set();
    let items = { prefixes: [], objects: [] };
    let nextToken = '';
    let truncated = false;
    let filterText = '';
    let listSeq = 0;
    let debounce = 0;

    const crumbs = h(
      'nav',
      { class: 'crumbs', 'aria-label': 'Folder' },
      h('a', { href: `#${hashFor({ pfx: '' })}` }, name),
      splitPrefix(prefix).flatMap((c) => [h('span', { 'aria-hidden': 'true' }, '/'), h('a', { href: `#${hashFor({ pfx: c.prefix })}` }, c.name)]),
      prefix ? h('span', { 'aria-hidden': 'true' }, '/') : null,
    );

    const fileInput = h('input', { type: 'file', multiple: true, class: 'is-hidden', 'aria-hidden': 'true', tabindex: '-1' });
    const dirInput = h('input', { type: 'file', webkitdirectory: true, multiple: true, class: 'is-hidden', 'aria-hidden': 'true', tabindex: '-1' });
    fileInput.addEventListener('change', () => {
      addFiles(Array.from(fileInput.files).map((file) => ({ file, path: file.name })));
      fileInput.value = '';
    });
    dirInput.addEventListener('change', () => {
      addFiles(Array.from(dirInput.files).map((file) => ({ file, path: file.webkitRelativePath || file.name })));
      dirInput.value = '';
    });

    const deleteBtn = button({ label: 'Delete', icon: 'trash', variant: 'danger', onClick: () => askDeleteSelected() });
    const selectAll = checkbox({
      label: 'Select all',
      onChange: (on) => {
        selected.clear();
        if (on) for (const o of items.objects) selected.add(o.key);
        paintList();
      },
    });
    const filterInput = textInput({ id: 'filter', type: 'search', placeholder: 'Names starting with…', 'aria-label': 'Filter by name prefix', spellcheck: 'false' });
    filterInput.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        filterText = filterInput.value;
        fetchList(false);
      }, 300);
    });

    const actionsFull = h(
      'div',
      { class: 'toolbar-full' },
      button({ label: 'Upload files', icon: 'upload', onClick: () => fileInput.click() }),
      button({ label: 'Upload folder', icon: 'upload', onClick: () => dirInput.click() }),
      button({ label: 'New folder', icon: 'folder', onClick: () => askNewFolder() }),
      button({ title: 'Refresh', icon: 'refresh', onClick: () => fetchList(false) }),
    );
    const actionsMore = h(
      'div',
      { class: 'toolbar-more' },
      menuButton({
        items: [
          { label: 'Upload files', icon: 'upload', onClick: () => fileInput.click() },
          { label: 'Upload folder', icon: 'upload', onClick: () => dirInput.click() },
          { label: 'New folder', icon: 'folder', onClick: () => askNewFolder() },
          { label: 'Refresh', icon: 'refresh', onClick: () => fetchList(false) },
        ],
      }),
    );
    const toolbar = h('div', { class: 'toolbar' }, actionsFull, actionsMore, h('div', { class: 'toolbar-spacer' }), selectAll, deleteBtn);
    const listBox = h('div', { class: 'list-box' });
    const more = h('div', { class: 'load-more' });
    const panelBox = h('section', { class: 'card upload-panel', 'aria-label': 'Uploads' });
    const dropZone = h('div', { class: 'drop-zone' }, listBox, more);

    content.replaceChildren(header, bar, crumbs, toolbar, field({ label: 'Filter', control: filterInput }), dropZone, panelBox, fileInput, dirInput);
    content.removeAttribute('aria-busy');

    // ----- uploads panel -----

    const paintPanel = () => {
      if (uploads.length === 0) {
        panelBox.classList.add('is-hidden');
        return;
      }
      panelBox.classList.remove('is-hidden');
      const shown = uploads.slice(-200);
      fill(
        panelBox,
        h('div', { class: 'up-head' }, h('h2', { class: 'card-title' }, 'Uploads'), button({ label: 'Clear finished', size: 'sm', variant: 'ghost', onClick: clearFinished })),
        h('ul', { class: 'up-list' }, shown.map(uploadRow)),
        uploads.length > shown.length ? h('p', { class: 'muted' }, `Showing the last ${shown.length} of ${formatCount(uploads.length)}.`) : null,
      );
    };
    const clearFinished = () => {
      for (let i = uploads.length - 1; i >= 0; i--) if (!isActive(uploads[i])) uploads.splice(i, 1);
      paintPanel();
    };
    subscribers.add(paintPanel);
    paintPanel();

    const me = { bucket: name, reload: () => fetchList(false) };
    mounted = me;
    signal.addEventListener('abort', () => {
      subscribers.delete(paintPanel);
      clearTimeout(debounce);
      if (mounted === me) mounted = null;
    });

    // drag and drop
    dropZone.addEventListener('dragover', (e) => {
      if (!e.dataTransfer?.types?.includes('Files')) return;
      e.preventDefault();
      dropZone.classList.add('is-dragging');
    });
    dropZone.addEventListener('dragleave', (e) => {
      if (e.target === dropZone || !dropZone.contains(e.relatedTarget)) dropZone.classList.remove('is-dragging');
    });
    dropZone.addEventListener('drop', async (e) => {
      e.preventDefault();
      dropZone.classList.remove('is-dragging');
      try {
        addFiles(await entriesOf(e.dataTransfer));
      } catch (err) {
        toast({ tone: 'danger', title: 'Could not read the dropped files', message: err.message });
      }
    });

    // ----- list -----

    async function fetchList(append) {
      const seq = ++listSeq;
      if (!append) {
        selected.clear();
        loading(listBox, 'Loading objects…');
        more.replaceChildren();
      }
      const query = { 'list-type': 2, delimiter: '/', prefix: prefix + filterText, 'max-keys': BATCH };
      if (append) query['continuation-token'] = nextToken;
      let page;
      try {
        const out = await s3Api('GET', name, '', { asToken, query, signal });
        page = parseListObjects(out.xml);
      } catch (err) {
        if (err.name === 'AbortError' || signal.aborted || seq !== listSeq) return;
        errorState(listBox, err, { title: 'Could not list the objects', retry: () => fetchList(false) });
        if (err.status === 403) listBox.append(h('p', { class: 'muted' }, `jay refused this as token ${label}. The token lacks object:list or its scope, or a bucket policy denies it.`));
        more.replaceChildren();
        return;
      }
      if (seq !== listSeq) return;
      items = append ? { prefixes: [...items.prefixes, ...page.prefixes], objects: [...items.objects, ...page.objects] } : { prefixes: page.prefixes, objects: page.objects };
      nextToken = page.nextToken;
      truncated = page.truncated && Boolean(page.nextToken);
      paintList();
    }

    function paintList() {
      deleteBtn.disabled = selected.size === 0;
      deleteBtn.querySelector('span').textContent = selected.size ? `Delete (${formatCount(selected.size)})` : 'Delete';
      const all = selectAll.querySelector('input');
      all.checked = items.objects.length > 0 && selected.size === items.objects.length;
      all.indeterminate = selected.size > 0 && selected.size < items.objects.length;
      all.disabled = items.objects.length === 0;

      const rows = [
        ...items.prefixes.map((p) => ({ kind: 'folder', key: p, name: p.slice(prefix.length) })),
        ...items.objects.map((o) => ({ kind: 'object', key: o.key, name: o.key.slice(prefix.length) || '(folder marker)', size: o.size, lastModified: o.lastModified })),
      ];
      if (rows.length === 0) {
        const where = filterText ? `Nothing here starts with "${filterText}".` : prefix ? 'This folder is empty. jay has no empty folders: a folder exists only while it holds objects, so upload something into it to keep it.' : 'This bucket is empty.';
        const holder = h('div');
        emptyState(holder, {
          icon: 'folder',
          title: filterText ? 'No matches' : prefix ? 'Empty folder' : 'No objects yet',
          body: where,
          action: filterText ? null : { label: 'Upload files', icon: 'upload', variant: 'primary', onClick: () => fileInput.click() },
        });
        listBox.replaceChildren(holder);
        listBox.removeAttribute('aria-busy');
        more.replaceChildren();
        return;
      }
      const table = dataTable({
        rowKey: 'key',
        rows,
        onRowClick: (r) => {
          if (r.kind === 'folder') ctx.navigate(hashFor({ pfx: r.key }));
          else openObjectDrawer(ctx, { bucket: name, key: r.key, asToken, tokenLabel: label, onChanged: () => fetchList(false) });
        },
        columns: [
          {
            key: 'name',
            label: 'Name',
            render: (r) =>
              r.kind === 'folder'
                ? h('span', { class: 'obj-name' }, icon('folder'), h('a', { href: `#${hashFor({ pfx: r.key })}` }, `${r.name}`))
                : h(
                    'span',
                    { class: 'obj-name' },
                    h('input', {
                      type: 'checkbox',
                      checked: selected.has(r.key),
                      'aria-label': `Select ${r.name}`,
                      on: {
                        change: (e) => {
                          if (e.target.checked) selected.add(r.key);
                          else selected.delete(r.key);
                          paintList();
                        },
                      },
                    }),
                    icon('file'),
                    r.name,
                  ),
          },
          { key: 'size', label: 'Size', numeric: true, render: (r) => (r.kind === 'folder' ? '—' : h('span', { title: exactBytes(r.size) }, formatBytes(r.size))) },
          { key: 'type', label: 'Type', hideBelow: 600, render: (r) => (r.kind === 'folder' ? '—' : h('span', { title: 'Guessed from the name; open the object for its content type' }, extensionOf(r.name) || '—')) },
          { key: 'modified', label: 'Modified', hideBelow: 900, render: (r) => (r.kind === 'folder' ? '—' : h('span', { title: r.lastModified }, formatRelative(r.lastModified))) },
          {
            key: 'act',
            label: '',
            render: (r) => (r.kind === 'folder' ? button({ title: `Delete folder ${r.name}`, icon: 'trash', variant: 'ghost', size: 'sm', onClick: () => askDeleteFolder(r.key) }) : ''),
          },
        ],
        caption: `${formatCount(items.prefixes.length)} folders, ${formatCount(items.objects.length)} objects${truncated ? ' loaded so far' : ''}`,
      });
      listBox.replaceChildren(table);
      listBox.removeAttribute('aria-busy');
      fill(more, truncated ? button({ label: 'Load more', onClick: () => fetchList(true) }) : null);
    }

    // ----- actions -----

    function askNewFolder() {
      const input = textInput({ id: 'new-folder', placeholder: 'folder-name', spellcheck: 'false' });
      openDialog({
        title: 'New folder',
        body: h('form', { on: { submit: (e) => e.preventDefault() } }, field({ label: 'Name', control: input, hint: 'No slash. The folder exists only in your browser until you upload something into it; jay has no empty folders.' })),
        actions: [
          { label: 'Cancel' },
          {
            label: 'Open folder',
            variant: 'primary',
            onClick: () => {
              const folder = input.value.trim();
              if (!folder) throw new Error('Enter a name.');
              if (folder.includes('/')) throw new Error('A folder name cannot contain a slash.');
              ctx.navigate(hashFor({ pfx: `${prefix}${folder}/` }));
            },
          },
        ],
      });
    }

    async function addFiles(files) {
      if (files.length === 0) return;
      const max = ctx.session?.max_object_size || 0;
      const entries = files.map(({ file, path }) => makeEntry(name, prefix + path, file, label));
      for (const e of entries) {
        if (max > 0 && e.size > max) {
          e.state = 'failed';
          e.detail = `Larger than this server's JAY_MAX_OBJECT_SIZE (${formatBytes(max)}).`;
        }
        uploads.push(e);
      }
      const sendable = entries.filter((e) => e.state === 'queued');
      notify();
      if (sendable.length === 0) return;

      for (const e of sendable) e.state = 'checking';
      notify();
      const check = await checkOverwrites({ bucket: name, keys: sendable.map((e) => e.key), asToken });
      if (check.skipped) toast({ tone: 'warn', title: 'Overwrite check skipped', message: 'More than 1,000 files: the console did not check which keys already exist. Existing objects with the same key will be replaced.' });
      if (check.existing.length > 0 || check.unknown.length > 0) {
        const go = await confirmReplace(check);
        if (!go) {
          for (const e of sendable) {
            e.state = 'cancelled';
            e.detail = 'Not uploaded: you chose not to replace existing objects.';
          }
          notify();
          return;
        }
      }
      for (const e of sendable) e.state = 'queued';
      notify();
      runBatch(sendable, asToken);
    }

    function confirmReplace({ existing, unknown }) {
      return new Promise((resolve) => {
        let decided = false;
        const list = (keys) => h('ul', { class: 'fail-list' }, keys.slice(0, FAILURES_SHOWN).map((k) => h('li', {}, h('code', {}, k))));
        const body = h(
          'div',
          {},
          existing.length ? h('p', {}, `${formatCount(existing.length)} ${existing.length === 1 ? 'object already exists' : 'objects already exist'} and will be replaced. jay keeps no previous versions.`) : null,
          existing.length ? list(existing) : null,
          unknown.length ? h('p', {}, `${formatCount(unknown.length)} could not be checked (jay refused the check as this token), so they may replace something:`) : null,
          unknown.length ? list(unknown) : null,
        );
        openDialog({
          title: 'Replace existing objects?',
          body,
          size: 'lg',
          onClose: () => {
            if (!decided) resolve(false);
          },
          actions: [
            {
              label: 'Cancel',
              onClick: () => {
                decided = true;
                resolve(false);
              },
            },
            {
              label: 'Replace',
              variant: 'danger',
              onClick: () => {
                decided = true;
                resolve(true);
              },
            },
          ],
        });
      });
    }

    function askDeleteSelected() {
      const keys = Array.from(selected);
      const n = keys.length;
      if (n === 0) return;
      confirmDestructive({
        title: 'Delete objects',
        description: h('p', {}, `This deletes ${formatCount(n)} ${n === 1 ? 'object' : 'objects'} from ${name}. jay keeps no previous versions, so it cannot be undone.`),
        confirmPhrase: `delete ${n} ${n === 1 ? 'object' : 'objects'}`,
        actionLabel: 'Delete',
        run: async () => {
          const result = { requested: n, deleted: 0, failed: [] };
          for (let i = 0; i < n; i += BATCH) {
            const chunk = keys.slice(i, i + BATCH);
            try {
              const r = await deleteBatch(name, asToken, chunk);
              result.deleted += r.deleted.length;
              result.failed.push(...r.errors);
            } catch (err) {
              // Nothing deleted yet: let the dialog show the error. Otherwise
              // report what happened and what did not.
              if (i === 0) throw err;
              for (const k of keys.slice(i)) result.failed.push({ key: k, code: err.code || '', message: err.message });
              break;
            }
          }
          return result;
        },
        renderResult: (r) => h('div', {}, h('p', {}, h('strong', {}, `Deleted ${formatCount(r.deleted)} of ${formatCount(r.requested)}`)), failureList(r.failed)),
      }).then((r) => {
        if (!r) return;
        selected.clear();
        toast(r.failed.length === 0 ? { tone: 'ok', title: `Deleted ${formatCount(r.deleted)} ${r.deleted === 1 ? 'object' : 'objects'}`, message: name } : { tone: 'warn', title: `Deleted ${formatCount(r.deleted)} of ${formatCount(r.requested)}`, message: `${formatCount(r.failed.length)} failed.` });
        fetchList(false);
      });
    }

    function askDeleteFolder(folderKey) {
      const folder = dirPrefix(folderKey);
      confirmDestructive({
        title: 'Delete folder',
        description: h('p', {}, `This deletes every object whose key starts with ${folder} in ${name}, at any depth. jay keeps no previous versions, so it cannot be undone.`),
        confirmPhrase: folder,
        actionLabel: 'Delete folder',
        // run only starts the job; the dialog then shows its live progress.
        run: async () => startFolderDelete(folder),
        renderResult: (job) => job.view(),
      });
    }

    function startFolderDelete(folder) {
      const job = { deleted: 0, failed: [], state: 'running', error: null, cancel: false, node: null, body: h('div', { 'aria-live': 'polite' }) };
      const paint = () => {
        const parts = [];
        if (job.state === 'running') {
          parts.push(h('p', {}, h('strong', {}, `Deleted ${formatCount(job.deleted)} so far`)), progressBar(null, { label: 'Deleting' }), button({ label: 'Stop', size: 'sm', onClick: () => { job.cancel = true; } }));
        } else if (job.state === 'stopped') {
          parts.push(h('p', {}, h('strong', {}, `Stopped after ${formatCount(job.deleted)}; the rest is still there.`)));
        } else if (job.state === 'failed') {
          parts.push(h('p', {}, h('strong', {}, `Deleted ${formatCount(job.deleted)}, then it stopped on an error. The rest is still there.`)), explainRefusal(job.error, label));
        } else {
          parts.push(h('p', {}, h('strong', {}, `Deleted ${formatCount(job.deleted)} ${job.deleted === 1 ? 'object' : 'objects'} under ${folder}`)));
        }
        parts.push(failureList(job.failed));
        job.body.replaceChildren(...parts.filter(Boolean));
      };
      job.view = () => {
        job.node = job.body;
        paint();
        return job.body;
      };
      (async () => {
        let token = '';
        try {
          for (;;) {
            // Closing the dialog, like Stop, ends it between two batches.
            if (job.cancel || (job.node && !job.node.isConnected)) {
              job.state = 'stopped';
              break;
            }
            const query = { 'list-type': 2, prefix: folder, 'max-keys': BATCH };
            if (token) query['continuation-token'] = token;
            const page = parseListObjects((await s3Api('GET', name, '', { asToken, query })).xml);
            if (page.objects.length > 0) {
              const r = await deleteBatch(name, asToken, page.objects.map((o) => o.key));
              job.deleted += r.deleted.length;
              job.failed.push(...r.errors);
            }
            paint();
            if (!page.truncated || !page.nextToken) break;
            token = page.nextToken;
          }
        } catch (err) {
          job.state = 'failed';
          job.error = err;
        }
        if (job.state === 'running') job.state = 'done';
        paint();
        const tone = job.state === 'done' && job.failed.length === 0 ? 'ok' : 'warn';
        toast({ tone, title: job.state === 'done' ? `Deleted ${formatCount(job.deleted)} under ${folder}` : `Folder delete ${job.state}`, message: job.failed.length ? `${formatCount(job.failed.length)} failed.` : name });
        if (mounted === me) fetchList(false);
      })();
      return job;
    }

    fetchList(false);
  }

  await load();
}
