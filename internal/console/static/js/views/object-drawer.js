// Object drawer: what jay knows about one object, a preview that cannot run
// code, and the actions on it (download, share link, copy, delete). Every call
// is made as the "browse as" token, so what the drawer can do is exactly what
// that token can do.

import { JayError, adminApi, encodeKey, s3Api, s3Href } from '../api.js';
import { basename, exactBytes, formatBytes, formatDateTime } from '../format.js';
import { getPresignHost, setPresignHost } from '../prefs.js';
import { checkCopyResult } from '../s3xml.js';
import { badge, button, confirmDestructive, copyButton, errorDetails, errorState, field, h, icon, keyValueList, loading, openDialog, openDrawer, select, textInput, toast } from '../ui.js';

const MiB = 1024 * 1024;
const PREVIEW_IMAGE_MAX = 10 * MiB;
const PREVIEW_TEXT_BYTES = 64 * 1024;
const BIG_DOWNLOAD = 1024 * MiB;
const IMAGE_TYPE = /^image\/(png|jpeg|gif|webp|avif)$/i;
const TEXT_TYPE = /^(text\/.+|application\/(json|xml))$/i;

const EXPIRES = [
  { value: '900', label: '15 minutes' },
  { value: '3600', label: '1 hour' },
  { value: '86400', label: '24 hours' },
  { value: '604800', label: '7 days' },
];

// explainRefusal renders an error and, for a 403, says what it usually means
// when the console is acting as a token.
export function explainRefusal(err, tokenLabel) {
  const note =
    err instanceof JayError && err.status === 403
      ? h('p', {}, `jay refused this as token ${tokenLabel || 'the selected token'} (AccessDenied). The token lacks the action or the scope, or a bucket policy denies it.`)
      : null;
  return h('div', {}, note, errorDetails(err));
}

// fill replaces the children of `el`, skipping null and false: replaceChildren
// alone would turn them into the text "null".
function fill(el, ...nodes) {
  el.replaceChildren(...nodes.filter(Boolean));
}

function mediaType(contentType) {
  return (contentType || '').split(';')[0].trim();
}

// openObjectDrawer({ bucket, key, asToken, tokenLabel, onChanged }) returns the
// drawer controller. onChanged() tells the caller the object was replaced or
// deleted so it can list again.
export function openObjectDrawer(ctx, { bucket, key, asToken, tokenLabel, onChanged } = {}) {
  const body = h('div', { class: 'obj-drawer' });
  const abort = new AbortController();
  let blobUrl = '';
  const ctl = openDrawer({
    title: basename(key) || key,
    body,
    onClose: () => {
      abort.abort();
      if (blobUrl) URL.revokeObjectURL(blobUrl);
      blobUrl = '';
    },
  });

  const href = s3Href(bucket, key, { asToken });

  async function load() {
    loading(body, 'Reading the object…');
    let head;
    try {
      head = await s3Api('HEAD', bucket, key, { asToken, responseType: 'none', signal: abort.signal });
    } catch (err) {
      if (err.name === 'AbortError') return;
      errorState(body, err, { title: 'Could not read this object', retry: load });
      if (err.status === 403) body.append(h('p', { class: 'muted' }, `jay refused this as token ${tokenLabel || 'the selected token'}. It lacks the action or the scope, or a bucket policy denies it.`));
      return;
    }
    render(head.headers);
  }

  function render(headers) {
    const size = Number(headers.get('content-length'));
    const type = headers.get('content-type') || 'application/octet-stream';
    const etag = headers.get('etag') || '';
    const sha = headers.get('x-amz-checksum-sha256') || '';
    const modified = headers.get('last-modified') || '';
    const meta = [];
    headers.forEach((value, name) => {
      if (name.startsWith('x-amz-meta-')) meta.push([name, value]);
    });

    const previewBox = h('div', { class: 'obj-preview' });
    const pairs = [
      ['Key', h('span', {}, h('code', {}, key), ' ', copyButton(key))],
      ['Size', h('span', { title: exactBytes(size) }, `${formatBytes(size)} (${exactBytes(size)})`)],
      ['Type', type],
      ['ETag', etag ? h('span', {}, h('code', {}, etag), ' ', copyButton(etag)) : '—'],
    ];
    if (sha) pairs.push(['SHA-256', h('span', {}, h('code', {}, sha), ' ', badge('base64'))]);
    pairs.push(['Modified', modified ? formatDateTime(modified) : '—']);
    pairs.push(['Metadata', meta.length ? h('div', {}, meta.map(([k, v]) => h('div', {}, h('code', {}, `${k}: ${v}`)))) : '—']);

    const actions = h(
      'div',
      { class: 'obj-actions' },
      h('a', { class: 'btn btn-secondary', href, download: basename(key) || 'download' }, icon('download'), h('span', {}, 'Download')),
      button({ label: 'Share link', icon: 'link', onClick: openShare }),
      button({ label: 'Copy to…', icon: 'copy', onClick: openCopy }),
      button({ label: 'Delete', icon: 'trash', variant: 'danger', onClick: askDelete }),
    );
    fill(
      body,
      previewBox,
      keyValueList(pairs),
      actions,
      size > BIG_DOWNLOAD
        ? h('p', { class: 'muted' }, "Large downloads through the console can hit the admin listener's 5-minute write timeout; a share link downloads straight from the S3 port.")
        : null,
    );
    body.removeAttribute('aria-busy');
    preview(previewBox, type, size);
  }

  async function preview(box, type, size) {
    const kind = mediaType(type);
    if (size === 0) {
      box.append(h('p', { class: 'muted' }, 'The object is empty.'));
      return;
    }
    if (IMAGE_TYPE.test(kind)) {
      if (size > PREVIEW_IMAGE_MAX) {
        box.append(h('p', { class: 'muted' }, `Too large to preview (limit ${formatBytes(PREVIEW_IMAGE_MAX)}).`));
        return;
      }
      loading(box, 'Loading the preview…');
      try {
        const out = await s3Api('GET', bucket, key, { asToken, responseType: 'blob', signal: abort.signal });
        if (abort.signal.aborted) return;
        blobUrl = URL.createObjectURL(out.blob);
        box.replaceChildren(h('img', { class: 'obj-preview-img', src: blobUrl, alt: `Preview of ${basename(key)}` }));
        box.removeAttribute('aria-busy');
      } catch (err) {
        if (err.name === 'AbortError') return;
        box.replaceChildren(h('div', { class: 'banner banner-warn' }, 'The preview could not be loaded.'), explainRefusal(err, tokenLabel));
        box.removeAttribute('aria-busy');
      }
      return;
    }
    if (TEXT_TYPE.test(kind)) {
      loading(box, 'Loading the preview…');
      try {
        const out = await s3Api('GET', bucket, key, { asToken, responseType: 'text', headers: { Range: `bytes=0-${PREVIEW_TEXT_BYTES - 1}` }, signal: abort.signal });
        if (abort.signal.aborted) return;
        fill(
          box,
          size > PREVIEW_TEXT_BYTES ? h('p', { class: 'muted' }, 'First 64 KiB') : null,
          h('pre', { class: 'obj-preview-text' }, out.text),
        );
        box.removeAttribute('aria-busy');
      } catch (err) {
        if (err.name === 'AbortError') return;
        box.replaceChildren(h('div', { class: 'banner banner-warn' }, 'The preview could not be loaded.'), explainRefusal(err, tokenLabel));
        box.removeAttribute('aria-busy');
      }
      return;
    }
    box.append(h('p', { class: 'muted' }, 'No preview for this type. The console only previews images and text.'));
  }

  function askDelete() {
    confirmDestructive({
      title: 'Delete object',
      description: h('p', {}, `This deletes ${key} from ${bucket}. jay keeps no previous versions, so it cannot be undone.`),
      confirmPhrase: basename(key) || key,
      run: async () => {
        await s3Api('DELETE', bucket, key, { asToken, responseType: 'none' });
        return true;
      },
    }).then((done) => {
      if (!done) return;
      toast({ tone: 'ok', title: 'Object deleted', message: `${bucket}/${key}` });
      ctl.close();
      onChanged?.();
    });
  }

  function openShare() {
    const port = (ctx.session?.s3_listen_addr || '').split(':').pop();
    const host = location.hostname.includes(':') ? `[${location.hostname}]` : location.hostname;
    const method = select({ id: 'share-method', options: [{ value: 'GET', label: 'GET (download)' }, { value: 'PUT', label: 'PUT (upload)' }], value: 'GET' });
    const expires = select({ id: 'share-expires', options: EXPIRES, value: '3600' });
    const style = select({ id: 'share-style', options: [{ value: 'jay', label: 'jay (default)' }, { value: 'aws', label: 'aws (SigV4 query string)' }], value: 'jay' });
    const hostInput = textInput({ id: 'share-host', value: getPresignHost() || `${host}${port ? `:${port}` : ''}`, spellcheck: 'false' });
    const form = h(
      'div',
      {},
      field({ label: 'Method', control: method }),
      field({ label: 'Expires', control: expires }),
      field({ label: 'Style', control: style }),
      field({ label: 'Host', control: hostInput, hint: 'The S3 host the link points at. The aws style signs it, so it must be the host clients will use.' }),
    );
    openDialog({
      title: 'Share link',
      body: form,
      actions: [
        { label: 'Cancel' },
        {
          label: 'Create link',
          variant: 'primary',
          autofocus: true,
          onClick: async (c) => {
            const chosenHost = hostInput.value.trim();
            if (!chosenHost) throw new Error('Enter the S3 host the link should point at.');
            const seconds = Number(expires.value);
            const res = await adminApi('POST', '/presign', {
              body: { token_id: asToken, method: method.value, bucket, key, expires_seconds: seconds, style: style.value, host: chosenHost },
            });
            if (!res?.url) throw new Error('jay answered without a URL.');
            setPresignHost(chosenHost);
            const url = h('input', { class: 'input mono', readOnly: true, value: res.url, 'aria-label': 'Share link' });
            c.setBody(
              h(
                'div',
                {},
                h('div', { class: 'input-group' }, url, copyButton(res.url)),
                h('p', { class: 'muted' }, `Expires at ${formatDateTime(new Date(Date.now() + seconds * 1000))}.`),
                h('p', {}, 'Anyone with this link can use it until it expires; revoking the token kills it.'),
              ),
            );
            c.setActions([{ label: 'Done' }]);
            return false;
          },
        },
      ],
    });
  }

  function openCopy() {
    const bucketSel = h('select', { class: 'select', id: 'copy-bucket', disabled: true }, h('option', { value: bucket }, bucket));
    const keyInput = textInput({ id: 'copy-key', value: key, spellcheck: 'false' });
    const note = h('div', { class: 'banner banner-warn is-hidden', role: 'alert' });
    let replaceConfirmed = false;

    adminApi('GET', '/buckets', { signal: abort.signal })
      .then((list) => {
        bucketSel.replaceChildren(...list.map((b) => h('option', { value: b.name }, b.name)));
        bucketSel.value = bucket;
        bucketSel.disabled = false;
      })
      .catch((err) => {
        if (err.name === 'AbortError') return;
        note.textContent = `The bucket list could not be read (${err.message}); copying within ${bucket} only.`;
        note.classList.remove('is-hidden');
      });

    const form = h('div', {}, field({ label: 'Destination bucket', control: bucketSel }), field({ label: 'Destination key', control: keyInput }), note);
    openDialog({
      title: 'Copy object',
      body: form,
      actions: [
        { label: 'Cancel' },
        {
          label: 'Copy',
          variant: 'primary',
          autofocus: true,
          onClick: async (c) => {
            const dBucket = bucketSel.value;
            const dKey = keyInput.value;
            if (!dKey) throw new Error('Enter the destination key.');
            if (dBucket === bucket && dKey === key) throw new Error('The destination is the object itself. Choose another key or bucket.');
            if (!replaceConfirmed) {
              let exists = false;
              try {
                await s3Api('HEAD', dBucket, dKey, { asToken, responseType: 'none' });
                exists = true;
              } catch {
                // 404 means free to write. Any other answer says nothing about
                // the destination, and the copy itself will report what happens.
                exists = false;
              }
              if (exists) {
                note.textContent = `${dBucket}/${dKey} already exists. Copying replaces it, and jay keeps no previous versions.`;
                note.classList.remove('is-hidden');
                replaceConfirmed = true;
                c.setActions([{ label: 'Cancel' }, { label: 'Replace and copy', variant: 'danger', onClick: (cc) => runCopy(cc, dBucket, dKey) }]);
                return false;
              }
            }
            return runCopy(c, dBucket, dKey);
          },
        },
      ],
    });
  }

  async function runCopy(_c, dBucket, dKey) {
    const out = await s3Api('PUT', dBucket, dKey, {
      asToken,
      headers: { 'x-amz-copy-source': `/${encodeURIComponent(bucket)}/${encodeKey(key)}` },
    });
    checkCopyResult(out.xml);
    toast({ tone: 'ok', title: 'Object copied', message: `${dBucket}/${dKey}` });
    onChanged?.();
    return true;
  }

  load();
  return ctl;
}
