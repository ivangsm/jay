// Bucket settings: what the bucket is, who can reach it (visibility and
// policy), the multipart uploads left unfinished, and deleting it. jay is the
// authority on every change: a policy that does not validate is shown with
// jay's own words, and a section only says "saved" after a 2xx and a re-read.

import { adminApi, s3Api } from '../api.js';
import { exactBytes, formatBytes, formatCount, formatDateTime, formatRelative } from '../format.js';
import { setBrowseAs } from '../prefs.js';
import { parseUploads } from '../s3xml.js';
import { button, confirmDestructive, copyButton, dataTable, emptyState, errorDetails, errorState, field, h, keyValueList, loading, openDialog, pageHeader, textArea, toast } from '../ui.js';
import { browseTokens, noTokenState, pickToken, tokenLabel, tokenPicker } from './bucket.js';

const EXAMPLE_POLICY = {
  version: '1',
  statements: [{ effect: 'deny', actions: ['object:delete'], prefixes: [], subjects: ['*'] }],
};

// fill replaces the children of `el`, skipping null and false: replaceChildren
// alone would turn them into the text "null".
function fill(el, ...nodes) {
  el.replaceChildren(...nodes.filter(Boolean));
}

function card(title, ...children) {
  return h('section', { class: 'card settings-card', 'aria-label': title }, h('h2', { class: 'card-title' }, title), ...children);
}

export async function renderBucketSettings(ctx) {
  const name = ctx.params.name;
  const asParam = ctx.query.get('as') || '';
  const { signal } = ctx;
  const enc = encodeURIComponent;
  ctx.setTitle(`${name} settings`);
  const content = h('div');
  ctx.root.replaceChildren(content);

  let detail = null; // GET /buckets/{name}
  let summary = null; // its row of GET /buckets
  let accounts = [];
  let groups = { mine: [], others: [] };
  let current = null;

  async function fetchBucket() {
    const [d, list] = await Promise.all([adminApi('GET', `/buckets/${enc(name)}`, { signal }), adminApi('GET', '/buckets', { signal })]);
    detail = d;
    summary = list.find((b) => b.name === name) || null;
    if (!summary) throw new Error(`Bucket ${name} is not in the bucket list.`);
  }

  async function load() {
    loading(content, 'Loading the bucket…');
    try {
      await fetchBucket();
      let tokens;
      [accounts, tokens] = await Promise.all([adminApi('GET', '/accounts', { signal }), adminApi('GET', '/tokens', { signal })]);
      groups = browseTokens(summary, tokens);
      current = pickToken(groups, name, asParam);
    } catch (err) {
      if (err.name === 'AbortError' || signal.aborted) return;
      errorState(content, err, { title: 'Could not load the bucket settings', retry: load });
      return;
    }
    if (signal.aborted) return;
    mount();
  }

  function mount() {
    const back = `/buckets/${enc(name)}${current ? `?as=${enc(current.token_id)}` : ''}`;
    const header = pageHeader({
      title: `${name} · settings`,
      breadcrumbs: [{ label: 'Buckets', href: '#/buckets' }, { label: name, href: `#${back}` }],
      actions: [button({ label: 'Back to objects', onClick: () => ctx.navigate(back) })],
    });
    const overview = h('div');
    const visibility = h('div');
    const policy = h('div');
    const uploadsBox = h('div');
    const danger = h('div');
    content.replaceChildren(header, overview, visibility, policy, uploadsBox, danger);
    content.removeAttribute('aria-busy');

    const ownerName = () => accounts.find((a) => a.account_id === summary.owner_account_id)?.name || summary.owner_account_id;

    // ----- overview -----

    function paintOverview() {
      overview.replaceChildren(
        card(
          'Overview',
          keyValueList([
            ['ID', h('span', {}, h('code', {}, summary.id), ' ', copyButton(summary.id))],
            ['Owner', h('span', {}, `${ownerName()} `, h('code', {}, summary.owner_account_id))],
            ['Created', formatDateTime(summary.created_at)],
            ['Objects', formatCount(summary.object_count)],
            ['Size', h('span', { title: exactBytes(summary.total_size_bytes) }, formatBytes(summary.total_size_bytes))],
          ]),
        ),
      );
    }

    // ----- visibility -----

    function paintVisibility() {
      const radio = (value, label, text) =>
        h('label', { class: 'radio-row' }, h('input', { type: 'radio', name: 'visibility', value, checked: summary.visibility === value }), h('span', {}, h('strong', {}, label), ' — ', text));
      const priv = radio('private', 'Private', 'only tokens that are granted access');
      const pub = radio('public-read', 'Public read', 'anyone can GET and LIST objects, no credentials');
      const status = h('div', { role: 'status' });
      const save = button({
        label: 'Save',
        variant: 'primary',
        onClick: async () => {
          const want = pub.querySelector('input').checked ? 'public-read' : 'private';
          status.replaceChildren();
          if (want === summary.visibility) {
            status.append(h('p', { class: 'muted' }, `The bucket is already ${want}.`));
            return;
          }
          const apply = async () => {
            await adminApi('PUT', `/buckets/${enc(name)}/visibility`, { body: { visibility: want } });
            await fetchBucket();
            paintOverview();
            paintVisibility();
            toast({ tone: 'ok', title: `${name} is now ${summary.visibility}` });
            return true;
          };
          try {
            if (want === 'public-read') {
              await confirmDestructive({
                title: 'Make the bucket public',
                description: h('p', {}, `Anyone on the network can read and list every object in ${name} without credentials.`),
                confirmPhrase: name,
                actionLabel: 'Make public',
                run: apply,
              });
            } else {
              await new Promise((resolve) => {
                openDialog({
                  title: 'Make the bucket private',
                  body: h('p', {}, `Only tokens that are granted access will be able to read ${name}.`),
                  onClose: () => resolve(),
                  actions: [{ label: 'Cancel' }, { label: 'Make private', variant: 'primary', onClick: apply }],
                });
              });
            }
          } catch (err) {
            status.replaceChildren(h('div', { class: 'banner banner-danger', role: 'alert' }, errorDetails(err)));
          }
        },
      });
      visibility.replaceChildren(card('Visibility', priv, pub, status, h('div', { class: 'card-actions' }, save)));
    }

    // ----- policy -----

    function paintPolicy() {
      const doc = detail.policy;
      const count = Array.isArray(doc?.statements) ? doc.statements.length : 0;
      const area = textArea({ id: 'policy-text', rows: 14, spellcheck: 'false', 'aria-label': 'Bucket policy JSON', value: doc ? JSON.stringify(doc, null, 2) : '' });
      const status = h('div', { role: 'status' });
      const save = button({
        label: 'Validate & save',
        variant: 'primary',
        onClick: async () => {
          status.replaceChildren();
          const notes = [];
          try {
            JSON.parse(area.value);
          } catch (e) {
            notes.push(h('p', { class: 'muted' }, `This does not parse as JSON here (${e.message}). jay has the final say, so it is sent anyway.`));
          }
          save.disabled = true;
          try {
            const res = await adminApi('PUT', `/buckets/${enc(name)}/policy`, { body: area.value });
            await fetchBucket();
            paintOverview();
            paintVisibility();
            paintPolicy();
            toast({ tone: 'ok', title: `Policy installed: ${res.statements} ${res.statements === 1 ? 'statement' : 'statements'}`, message: name });
          } catch (err) {
            save.disabled = false;
            status.replaceChildren(...notes, h('div', { class: 'banner banner-danger', role: 'alert' }, errorDetails(err)));
          }
        },
      });
      const example = button({ label: 'Insert example', variant: 'ghost', onClick: () => { area.value = JSON.stringify(EXAMPLE_POLICY, null, 2); } });
      const remove = button({
        label: 'Remove policy',
        variant: 'danger',
        disabled: !doc,
        onClick: () => {
          confirmDestructive({
            title: 'Remove the policy',
            description: h('p', {}, 'Removing a policy closes the bucket to anyone who reached it only through the policy.'),
            confirmPhrase: name,
            actionLabel: 'Remove policy',
            run: async () => {
              await adminApi('DELETE', `/buckets/${enc(name)}/policy`);
              await fetchBucket();
              return true;
            },
          }).then((ok) => {
            if (!ok) return;
            paintOverview();
            paintVisibility();
            paintPolicy();
            toast({ tone: 'ok', title: 'Policy removed', message: name });
          });
        },
      });
      policy.replaceChildren(
        card(
          'Policy',
          h('p', { class: 'muted' }, doc ? `${count} ${count === 1 ? 'statement' : 'statements'}` : 'No policy installed.'),
          area,
          status,
          h('div', { class: 'card-actions' }, example, remove, save),
        ),
      );
    }

    // ----- incomplete multipart uploads -----

    async function paintUploads() {
      const head = [h('h2', { class: 'card-title' }, current ? `Incomplete multipart uploads (as ${tokenLabel(current)})` : 'Incomplete multipart uploads')];
      const body = h('div');
      const picker = tokenPicker(groups, current, (id) => {
        setBrowseAs(name, id);
        ctx.navigate(`/buckets/${enc(name)}/settings?as=${enc(id)}`);
      });
      uploadsBox.replaceChildren(h('section', { class: 'card settings-card', 'aria-label': 'Incomplete multipart uploads' }, ...head, field({ label: 'Browse as', control: picker }), body));
      if (!current) {
        noTokenState(body, summary, ctx.navigate);
        return;
      }
      const asToken = current.token_id;
      async function list() {
        loading(body, 'Loading incomplete uploads…');
        let result;
        try {
          result = parseUploads((await s3Api('GET', name, '', { asToken, query: { uploads: true }, signal })).xml);
        } catch (err) {
          if (err.name === 'AbortError' || signal.aborted) return;
          errorState(body, err, { title: 'Could not list the incomplete uploads', retry: list });
          if (err.status === 403) body.append(h('p', { class: 'muted' }, `jay refused this as token ${tokenLabel(current)}.`));
          return;
        }
        const note = h('p', { class: 'muted' }, 'GC reclaims uploads inactive for more than 24 h.');
        if (result.uploads.length === 0) {
          const holder = h('div');
          emptyState(holder, { icon: 'upload', title: 'No incomplete uploads', body: 'Nothing is waiting to be completed or aborted.' });
          body.replaceChildren(holder, note);
          body.removeAttribute('aria-busy');
          return;
        }
        fill(
          body,
          dataTable({
            rowKey: 'uploadId',
            rows: result.uploads,
            columns: [
              { key: 'key', label: 'Key', mono: true, render: (u) => u.key },
              { key: 'uploadId', label: 'Upload id', mono: true, hideBelow: 600, render: (u) => u.uploadId },
              { key: 'initiated', label: 'Started', render: (u) => h('span', { title: u.initiated }, formatRelative(u.initiated)) },
              { key: 'act', label: '', render: (u) => button({ label: 'Abort', size: 'sm', variant: 'danger', onClick: () => askAbort(u) }) },
            ],
          }),
          result.truncated ? h('p', { class: 'muted' }, 'Showing the first page only; more incomplete uploads exist.') : null,
          note,
        );
        body.removeAttribute('aria-busy');
      }
      function askAbort(u) {
        confirmDestructive({
          title: 'Abort the upload',
          description: h('p', {}, `This discards the parts already uploaded for ${u.key} (upload id ${u.uploadId}).`),
          confirmPhrase: u.key,
          actionLabel: 'Abort upload',
          run: async () => {
            await s3Api('DELETE', name, u.key, { asToken, query: { uploadId: u.uploadId }, responseType: 'none' });
            return true;
          },
        }).then((ok) => {
          if (!ok) return;
          toast({ tone: 'ok', title: 'Upload aborted', message: u.key });
          list();
        });
      }
      await list();
    }

    // ----- danger zone -----

    function paintDanger() {
      danger.replaceChildren(
        card(
          'Danger zone',
          h('p', {}, 'Delete this bucket. Only an empty bucket can be deleted, quarantined objects included. ', h('a', { href: `#${back}` }, 'Browse objects')),
          h('div', { class: 'card-actions' }, button({ label: 'Delete bucket…', icon: 'trash', variant: 'danger', onClick: askDeleteBucket })),
        ),
      );
    }

    function askDeleteBucket() {
      confirmDestructive({
        title: 'Delete bucket',
        description: h('p', {}, 'Only an empty bucket can be deleted. If jay refuses because it is not empty, delete its objects first.'),
        confirmPhrase: name,
        actionLabel: 'Delete bucket',
        run: async () => {
          await adminApi('DELETE', `/buckets/${enc(name)}`);
          return true;
        },
      }).then((ok) => {
        if (!ok) return;
        toast({ tone: 'ok', title: 'Bucket deleted', message: name });
        ctx.navigate('/buckets');
      });
    }

    paintOverview();
    paintVisibility();
    paintPolicy();
    paintDanger();
    paintUploads();
  }

  await load();
}
