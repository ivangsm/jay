// Pure formatting and validation helpers. Nothing here touches the DOM.

export const DOCS_URL = 'https://ivangsm.github.io/jay/';

const BYTE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];

// formatBytes renders a binary size with one decimal. The exact byte count is
// meant for a title attribute, see exactBytes.
export function formatBytes(n) {
  if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) return '—';
  if (n < 1024) return `${n} B`;
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${BYTE_UNITS[unit]}`;
}

export function exactBytes(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return '';
  return `${n.toLocaleString('en-US')} bytes`;
}

export function formatCount(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return '—';
  return n.toLocaleString('en-US');
}

const dateFmt = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric' });
const dateYearFmt = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
const dateTimeFmt = new Intl.DateTimeFormat('en-US', {
  month: 'short',
  day: 'numeric',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
});

function toDate(value) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

// formatDate: "Oct 7" within the current year, "Oct 7, 2025" otherwise.
export function formatDate(value) {
  const d = toDate(value);
  if (!d) return '—';
  return d.getFullYear() === new Date().getFullYear() ? dateFmt.format(d) : dateYearFmt.format(d);
}

export function formatDateTime(value) {
  const d = toDate(value);
  return d ? dateTimeFmt.format(d) : '—';
}

// formatRelative: "just now", "5 min ago", "2 h ago", "3 d ago", then a date.
export function formatRelative(value, now = Date.now()) {
  const d = toDate(value);
  if (!d) return '—';
  const seconds = Math.round((now - d.getTime()) / 1000);
  if (seconds < -60) return formatDate(d);
  if (seconds < 45) return 'just now';
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  if (seconds < 86400 * 30) return `${Math.round(seconds / 86400)} d ago`;
  return formatDate(d);
}

// formatDuration: "3 d 4 h", "2 h 5 min", "45 s".
export function formatDuration(totalSeconds) {
  if (typeof totalSeconds !== 'number' || !Number.isFinite(totalSeconds) || totalSeconds < 0) return '—';
  const s = Math.floor(totalSeconds);
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  if (days > 0) return `${days} d ${hours} h`;
  if (hours > 0) return `${hours} h ${minutes} min`;
  if (minutes > 0) return `${minutes} min`;
  return `${s} s`;
}

// dirPrefix normalises a prefix so it ends in exactly one slash ('' stays '').
// The trailing slash is not cosmetic: recursive operations on "assets" would
// also match "assets2/".
export function dirPrefix(prefix) {
  if (!prefix) return '';
  return prefix.endsWith('/') ? prefix : `${prefix}/`;
}

// parentPrefix: "a/b/c/" -> "a/b/", "a/" -> "", "" -> "".
export function parentPrefix(prefix) {
  const trimmed = (prefix || '').replace(/\/+$/, '');
  const i = trimmed.lastIndexOf('/');
  return i < 0 ? '' : trimmed.slice(0, i + 1);
}

// basename: last path segment of a key or prefix, without a trailing slash.
export function basename(key) {
  const trimmed = (key || '').replace(/\/+$/, '');
  return trimmed.slice(trimmed.lastIndexOf('/') + 1);
}

// splitPrefix: "a/b/" -> [{ name: 'a', prefix: 'a/' }, { name: 'b', prefix: 'a/b/' }].
export function splitPrefix(prefix) {
  const parts = (prefix || '').split('/').filter(Boolean);
  const out = [];
  let acc = '';
  for (const name of parts) {
    acc += `${name}/`;
    out.push({ name, prefix: acc });
  }
  return out;
}

// tokenState folds status and expiry into one label.
export function tokenState(token, now = Date.now()) {
  if (token?.status === 'revoked') return { state: 'revoked', label: 'Revoked', tone: 'danger' };
  if (token?.status && token.status !== 'active') return { state: token.status, label: token.status, tone: 'warn' };
  const exp = toDate(token?.expires_at);
  if (exp && exp.getTime() <= now) return { state: 'expired', label: 'Expired', tone: 'warn' };
  return { state: 'active', label: 'Active', tone: 'ok' };
}

// bucketNameProblem mirrors meta.ValidBucketName. It returns '' for a valid
// name and a sentence otherwise. The server stays the authority; this only
// gives feedback while typing.
export function bucketNameProblem(name) {
  if (!name) return 'Enter a name.';
  if (name.length < 3 || name.length > 63) return 'Use 3 to 63 characters.';
  if (!/^[a-z0-9.-]+$/.test(name)) return "Use lowercase letters, digits, '.' and '-' only.";
  if (!/^[a-z0-9]/.test(name) || !/[a-z0-9]$/.test(name)) return 'Start and end with a letter or digit.';
  if (name.includes('..')) return "Do not use '..'.";
  if (name.includes('--')) return "Do not use '--'.";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(name)) return 'Do not use an IP address.';
  return '';
}
