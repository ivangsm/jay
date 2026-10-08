// Uploads from the browser. XHR rather than fetch because only XHR reports
// upload progress. A file up to 64 MiB goes in one PUT; a larger one goes as a
// multipart upload (parts of at least 16 MiB, 3 in flight, one retry per part)
// and is aborted on the server when it fails or is cancelled, so an
// interrupted upload never leaves parts behind without saying so.

import { JayError, adminApi, s3Api, s3Href, session } from './api.js';
import { buildCompleteBody, parseComplete, parseInitiate } from './s3xml.js';

const MiB = 1024 * 1024;
export const SIMPLE_MAX = 64 * MiB;
export const MIN_PART = 16 * MiB;
const MAX_PARTS = 10000;
const PART_CONCURRENCY = 3;
const RETRY_DELAY_MS = 1000;
const REQUEST_ID_HEADER = 'x-jay-s3-request-id';

// planParts decides how a file of `size` bytes is sent. Parts are the larger of
// 16 MiB and size/10000 rounded up to a whole MiB, so no file needs more than
// 10,000 parts.
export function planParts(size) {
  if (size <= SIMPLE_MAX) return { multipart: false, partSize: size, count: 1 };
  const partSize = Math.max(MIN_PART, Math.ceil(size / MAX_PARTS / MiB) * MiB);
  return { multipart: true, partSize, count: Math.ceil(size / partSize) };
}

// errorFromXhr builds a JayError from a finished XHR the same way api.js does
// for fetch: S3's <Error> XML or the console's JSON.
function errorFromXhr(xhr) {
  const text = xhr.responseText || '';
  let message = '';
  let code = '';
  let reason = '';
  let s3Id = xhr.getResponseHeader(REQUEST_ID_HEADER) || '';
  if (text.trimStart().startsWith('{')) {
    try {
      const parsed = JSON.parse(text);
      message = String(parsed.error ?? '');
      reason = String(parsed.reason ?? '');
    } catch {
      message = '';
    }
  } else if (text.trimStart().startsWith('<')) {
    const doc = new DOMParser().parseFromString(text, 'application/xml');
    if (!doc.getElementsByTagName('parsererror').length) {
      code = doc.getElementsByTagName('Code')[0]?.textContent || '';
      message = doc.getElementsByTagName('Message')[0]?.textContent || '';
      s3Id = doc.getElementsByTagName('RequestId')[0]?.textContent || s3Id;
    }
  }
  if (!message) message = `jay answered ${xhr.status} without an error message.`;
  return new JayError({ status: xhr.status, code, message, requestId: xhr.getResponseHeader('x-amz-request-id') || '', s3RequestId: s3Id, source: 's3', reason });
}

// A console 401 means the session is gone. api.js owns the sign-out signal and
// only fires it from its own requests, so one cheap admin call is enough to
// make it tell the app.
function noticeSignedOut(err) {
  if (err.status === 401 && err.reason) adminApi('GET', '/metrics').catch(() => {});
}

// xhrSend sends one request. It resolves with the XHR on a 2xx and rejects with
// a JayError otherwise. While it runs the XHR sits in `inflight`, so the caller
// can abort everything that is still going.
function xhrSend({ method, url, body, contentType, onProgress, inflight }) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, url);
    xhr.withCredentials = true;
    const csrf = session()?.csrf_token;
    if (csrf) xhr.setRequestHeader('X-Jay-Console-CSRF', csrf);
    if (contentType) xhr.setRequestHeader('Content-Type', contentType);
    if (onProgress) xhr.upload.onprogress = (e) => onProgress(e.loaded);
    const settle = () => inflight.delete(xhr);
    xhr.onload = () => {
      settle();
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr);
        return;
      }
      const err = errorFromXhr(xhr);
      noticeSignedOut(err);
      reject(err);
    };
    xhr.onerror = () => {
      settle();
      reject(new JayError({ source: 'network', message: 'Could not reach jay: the connection failed.' }));
    };
    xhr.onabort = () => {
      settle();
      reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
    };
    inflight.add(xhr);
    xhr.send(body);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const isAbort = (e) => e?.name === 'AbortError';
const retryable = (e) => e instanceof JayError && (e.status === 0 || e.status >= 500);

// startUpload uploads `file` as `key`. It returns { cancel(), done } where done
// resolves with { etag } only after the server's 2xx for the PUT or for
// CompleteMultipartUpload, and rejects with a JayError otherwise. onState gets
// 'uploading' | 'completing' | 'aborting' | 'done' | 'failed' | 'cancelled'
// and a detail string; onProgress gets { loaded, total, part, parts }.
export function startUpload({ bucket, key, file, asToken, contentType, onProgress, onState }) {
  const plan = planParts(file.size);
  const type = contentType || file.type || 'application/octet-stream';
  const inflight = new Set();
  let cancelled = false;
  let uploadId = '';

  const abortInflight = () => {
    for (const x of inflight) x.abort();
  };
  const emit = (state, detail = '') => onState?.(state, detail);

  const send = (opts) => xhrSend({ ...opts, inflight });

  async function putSimple() {
    emit('uploading');
    const xhr = await send({
      method: 'PUT',
      url: s3Href(bucket, key, { asToken }),
      body: file,
      contentType: type,
      onProgress: (loaded) => onProgress?.({ loaded, total: file.size, part: 1, parts: 1 }),
    });
    return xhr.getResponseHeader('ETag') || '';
  }

  async function putMultipart() {
    const init = await s3Api('POST', bucket, key, { asToken, query: { uploads: true }, headers: { 'Content-Type': type } });
    uploadId = parseInitiate(init.xml);
    emit('uploading');

    const progress = new Array(plan.count).fill(0);
    const parts = [];
    let next = 0;
    let failure = null;
    const report = (part) =>
      onProgress?.({ loaded: progress.reduce((a, b) => a + b, 0), total: file.size, part, parts: plan.count });

    async function sendPart(n) {
      const start = (n - 1) * plan.partSize;
      const blob = file.slice(start, Math.min(file.size, start + plan.partSize));
      const attempt = () =>
        send({
          method: 'PUT',
          url: s3Href(bucket, key, { asToken, query: { uploadId, partNumber: n } }),
          body: blob,
          onProgress: (loaded) => {
            progress[n - 1] = loaded;
            report(n);
          },
        });
      let xhr;
      try {
        xhr = await attempt();
      } catch (e) {
        if (cancelled || isAbort(e) || !retryable(e)) throw e;
        progress[n - 1] = 0;
        await sleep(RETRY_DELAY_MS);
        if (cancelled) throw e;
        xhr = await attempt();
      }
      const etag = xhr.getResponseHeader('ETag');
      if (!etag) throw new JayError({ source: 's3', message: `jay accepted part ${n} but sent no ETag.` });
      progress[n - 1] = blob.size;
      report(n);
      parts.push({ number: n, etag });
    }

    async function worker() {
      while (!failure && !cancelled) {
        const n = ++next;
        if (n > plan.count) return;
        try {
          await sendPart(n);
        } catch (e) {
          if (!failure) failure = { error: e, part: n };
          abortInflight();
          return;
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(PART_CONCURRENCY, plan.count) }, worker));
    if (cancelled) throw Object.assign(new Error('cancelled'), { name: 'AbortError' });
    if (failure) throw Object.assign(failure.error, { failedPart: failure.part });

    emit('completing');
    const done = await s3Api('POST', bucket, key, { asToken, query: { uploadId }, headers: { 'Content-Type': 'application/xml' }, body: buildCompleteBody(parts) });
    return parseComplete(done.xml);
  }

  // abortRemote tells jay to drop the parts. Its outcome is part of the final
  // message: "aborted" and "abort failed" are different facts.
  async function abortRemote() {
    if (!uploadId) return 'There was no incomplete upload to clean up.';
    emit('aborting');
    try {
      await s3Api('DELETE', bucket, key, { asToken, query: { uploadId }, responseType: 'none' });
      return 'The incomplete upload was aborted.';
    } catch (e) {
      return `The abort also failed (${e.message}); jay's GC reclaims it after 24 h of inactivity (upload id ${uploadId}).`;
    }
  }

  const done = (async () => {
    try {
      const etag = plan.multipart ? await putMultipart() : await putSimple();
      emit('done', etag);
      return { etag };
    } catch (e) {
      if (cancelled || isAbort(e)) {
        const note = plan.multipart ? await abortRemote() : 'Nothing was stored.';
        emit('cancelled', `Upload cancelled. ${note}`);
        throw Object.assign(new Error('cancelled'), { name: 'AbortError' });
      }
      const where = e.failedPart ? ` at part ${e.failedPart}` : '';
      const what = [e.code, e.message].filter(Boolean).join(': ');
      const note = plan.multipart ? ` ${await abortRemote()}` : '';
      emit('failed', `Upload failed${where}: ${what}.${note}`);
      throw e;
    }
  })();
  // Callers observe the outcome through onState; this keeps a rejection nobody
  // awaited from surfacing as an unhandled one.
  done.catch(() => {});

  return {
    cancel() {
      cancelled = true;
      abortInflight();
    },
    done,
  };
}

// checkOverwrites HEADs each destination key (4 at a time, at most 1000 keys)
// and sorts them into those that exist, those whose state is unknown (a 403 says
// nothing either way) and whether the check was skipped for being too many.
export async function checkOverwrites({ bucket, keys, asToken, signal }) {
  if (keys.length > 1000) return { existing: [], unknown: [], skipped: true };
  const existing = [];
  const unknown = [];
  let i = 0;
  async function worker() {
    while (i < keys.length) {
      const key = keys[i++];
      try {
        await s3Api('HEAD', bucket, key, { asToken, responseType: 'none', signal });
        existing.push(key);
      } catch (e) {
        if (isAbort(e)) throw e;
        if (e instanceof JayError && e.status === 404) continue;
        unknown.push(key);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(4, keys.length) }, worker));
  return { existing, unknown, skipped: false };
}
