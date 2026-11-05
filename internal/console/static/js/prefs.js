// The only module allowed to touch localStorage. It holds preferences and
// nothing else: the theme, the last "browse as" token id per bucket (an id, not
// a secret) and the last presign host. Never the CSRF token, never a secret,
// never a list of data. Every access is guarded: storage can be blocked.

const KEY = 'jay-console.prefs';

function read() {
  try {
    const raw = localStorage.getItem(KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function write(prefs) {
  try {
    localStorage.setItem(KEY, JSON.stringify(prefs));
  } catch {
    // Storage is a convenience; losing it must not break the console.
  }
}

export function getTheme() {
  const t = read().theme;
  return t === 'light' || t === 'dark' ? t : 'system';
}

export function setTheme(theme) {
  const prefs = read();
  if (theme === 'light' || theme === 'dark') prefs.theme = theme;
  else delete prefs.theme;
  write(prefs);
}

export function getBrowseAs(bucket) {
  const map = read().browseAs;
  return map && typeof map[bucket] === 'string' ? map[bucket] : '';
}

export function setBrowseAs(bucket, tokenId) {
  const prefs = read();
  const map = prefs.browseAs && typeof prefs.browseAs === 'object' ? prefs.browseAs : {};
  if (tokenId) map[bucket] = tokenId;
  else delete map[bucket];
  prefs.browseAs = map;
  write(prefs);
}

export function getPresignHost() {
  const v = read().presignHost;
  return typeof v === 'string' ? v : '';
}

export function setPresignHost(host) {
  const prefs = read();
  if (host) prefs.presignHost = host;
  else delete prefs.presignHost;
  write(prefs);
}
