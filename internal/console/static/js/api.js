// Every network call the console makes goes through this module. It owns the
// CSRF token (a module variable, never storage), turns every failure into a
// JayError, and never reports success for a response that was not 2xx.

const API = '/console/api';
const REQUEST_ID_HEADER = 'x-amz-request-id';
const S3_REQUEST_ID_HEADER = 'x-jay-s3-request-id';

let csrfToken = '';
let currentSession = null;
const signedOutHandlers = [];

export class JayError extends Error {
  // source: 'network' | 'console' | 'admin' | 's3'
  constructor({ status = 0, code = '', message, requestId = '', s3RequestId = '', source, reason = '' }) {
    super(message);
    this.name = 'JayError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.s3RequestId = s3RequestId;
    this.source = source;
    this.reason = reason;
  }
}

export function onSignedOut(fn) {
  signedOutHandlers.push(fn);
  return () => {
    const i = signedOutHandlers.indexOf(fn);
    if (i >= 0) signedOutHandlers.splice(i, 1);
  };
}

function dropSession() {
  csrfToken = '';
  currentSession = null;
}

function notifySignedOut(reason) {
  dropSession();
  for (const fn of signedOutHandlers.slice()) fn(reason);
}

export function session() {
  return currentSession;
}

function isSafe(method) {
  return method === 'GET' || method === 'HEAD';
}

function isAbort(err) {
  return err?.name === 'AbortError';
}

// send performs the fetch and maps a thrown fetch (offline, refused, DNS) to a
// network JayError. An abort is rethrown untouched: callers use it to ignore
// work that a navigation made irrelevant.
async function send(url, { method = 'GET', headers = {}, body, signal } = {}) {
  const h = new Headers(headers);
  if (!isSafe(method) && csrfToken) h.set('X-Jay-Console-CSRF', csrfToken);
  try {
    return await fetch(url, { method, headers: h, body, signal, credentials: 'same-origin', cache: 'no-store' });
  } catch (e) {
    if (isAbort(e)) throw e;
    throw new JayError({ source: 'network', message: `Could not reach jay: ${e.message}` });
  }
}

function idsFrom(resp) {
  return {
    requestId: resp.headers.get(REQUEST_ID_HEADER) || '',
    s3RequestId: resp.headers.get(S3_REQUEST_ID_HEADER) || '',
  };
}

function parseXmlDoc(text) {
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length > 0) return null;
  return doc;
}

function xmlText(doc, tag) {
  const el = doc.getElementsByTagName(tag)[0];
  return el ? el.textContent : '';
}

// errorFromResponse builds a JayError from a non-2xx response: the console's
// JSON ({error, reason}) or S3's XML <Error>. A body in neither shape still
// yields an error carrying the status, never a silent success.
async function errorFromResponse(resp, source) {
  const ids = idsFrom(resp);
  let text = '';
  try {
    text = await resp.text();
  } catch {
    text = '';
  }
  const ctype = resp.headers.get('content-type') || '';
  let message = '';
  let code = '';
  let reason = '';
  let s3Id = ids.s3RequestId;
  if (ctype.includes('json') || text.trimStart().startsWith('{')) {
    try {
      const parsed = JSON.parse(text);
      message = String(parsed.error ?? '');
      reason = String(parsed.reason ?? '');
    } catch {
      message = '';
    }
  } else if (text.trimStart().startsWith('<')) {
    const doc = parseXmlDoc(text);
    if (doc) {
      code = xmlText(doc, 'Code');
      message = xmlText(doc, 'Message');
      s3Id = xmlText(doc, 'RequestId') || s3Id;
    }
  }
  if (!message) message = `jay answered ${resp.status}${resp.statusText ? ` ${resp.statusText}` : ''} without an error message.`;
  return new JayError({ status: resp.status, code, message, requestId: ids.requestId, s3RequestId: s3Id, source, reason });
}

// failure converts a non-2xx response into the thrown error and, when it is
// the console saying "not signed in", tells the app to show the login.
async function failure(resp, source) {
  const err = await errorFromResponse(resp, source);
  if (resp.status === 401 && err.reason) {
    notifySignedOut(err.reason);
    err.source = 'console';
  }
  return err;
}

function setSession(info) {
  currentSession = info;
  csrfToken = info.csrf_token || '';
  return info;
}

async function readJSON(resp, source) {
  const ids = idsFrom(resp);
  try {
    return await resp.json();
  } catch {
    throw new JayError({
      status: resp.status,
      message: 'jay answered with a body that is not valid JSON.',
      source,
      ...ids,
    });
  }
}

export async function getSession() {
  const resp = await send(`${API}/session`);
  if (resp.status === 401) {
    dropSession();
    return null;
  }
  if (!resp.ok) throw await errorFromResponse(resp, 'console');
  return setSession(await readJSON(resp, 'console'));
}

export async function login(token) {
  const resp = await send(`${API}/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  });
  // A 401 here means "wrong token", not "session expired": it must not be
  // routed through failure(), which would announce a sign-out.
  if (!resp.ok) throw await errorFromResponse(resp, 'console');
  return setSession(await readJSON(resp, 'console'));
}

export async function logout() {
  const resp = await send(`${API}/session`, { method: 'DELETE' });
  if (resp.status === 401) {
    dropSession();
    return;
  }
  if (!resp.ok) throw await errorFromResponse(resp, 'console');
  dropSession();
}

function withQuery(base, query) {
  if (!query) return base;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === false) continue;
    qs.set(k, v === true ? '' : String(v));
  }
  const s = qs.toString();
  return s ? `${base}?${s}` : base;
}

export async function adminApi(method, path, { query, body, signal } = {}) {
  const headers = {};
  let payload;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const resp = await send(withQuery(`${API}/admin${path}`, query), { method, headers, body: payload, signal });
  if (!resp.ok) throw await failure(resp, 'admin');
  if (resp.status === 204) return null;
  return readJSON(resp, 'admin');
}

export function encodeKey(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

function s3Url(bucket, key, asToken, query) {
  const path = key ? `/${encodeURIComponent(bucket)}/${encodeKey(key)}` : `/${encodeURIComponent(bucket)}`;
  return withQuery(`${API}/s3${path}`, { ...query, as_token: asToken });
}

export function s3Href(bucket, key, { asToken, query } = {}) {
  return s3Url(bucket, key, asToken, query);
}

export async function s3Api(method, bucket, key, { asToken, query, headers, body, signal, responseType = 'xml' } = {}) {
  const resp = await send(s3Url(bucket, key, asToken, query), { method, headers, body, signal });
  if (!resp.ok) throw await failure(resp, 's3');
  const out = { status: resp.status, headers: resp.headers };
  if (responseType === 'none') {
    // Drain so the connection is released; the body is not wanted.
    await resp.arrayBuffer();
  } else if (responseType === 'blob') {
    out.blob = await resp.blob();
  } else if (responseType === 'text') {
    out.text = await resp.text();
  } else {
    const text = await resp.text();
    if (text) {
      const doc = parseXmlDoc(text);
      if (!doc) {
        throw new JayError({ status: resp.status, message: 'jay answered with a body that is not valid XML.', source: 's3', ...idsFrom(resp) });
      }
      out.xml = doc;
    }
  }
  return out;
}

// getHealth reads the unauthenticated readiness probe. A 503 is a result (jay
// says it is not ready and why), not an exception; anything that is not a
// readiness document is an error.
export async function getHealth({ signal } = {}) {
  const resp = await send('/health/ready', { signal });
  const ids = idsFrom(resp);
  if (resp.status !== 200 && resp.status !== 503) {
    throw new JayError({ status: resp.status, message: `GET /health/ready answered ${resp.status}.`, source: 'admin', ...ids });
  }
  const body = await readJSON(resp, 'admin');
  return {
    httpStatus: resp.status,
    status: body.status || '',
    reason: body.reason || '',
    durability: body.durability || null,
  };
}
