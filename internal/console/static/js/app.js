// Boot, session, hash router and the shell (sidebar, topbar, theme).

import { adminApi, getSession, logout, onSignedOut, session } from './api.js';
import { DOCS_URL, formatCount } from './format.js';
import { getTheme, setTheme } from './prefs.js';
import { assetUrl, emptyState, errorState, h, icon, loading, toast } from './ui.js';
import { renderAccount, renderAccounts } from './views/accounts.js';
import { renderBucket } from './views/bucket.js';
import { renderBucketSettings } from './views/bucket-settings.js';
import { renderBuckets } from './views/buckets.js';
import { renderLogin } from './views/login.js';
import { renderOverview } from './views/overview.js';
import { renderQuarantine } from './views/quarantine.js';
import { renderTokens } from './views/tokens.js';

const app = document.getElementById('app');

// ---------- theme ----------

const THEMES = ['system', 'light', 'dark'];
const THEME_LABEL = { system: 'System', light: 'Light', dark: 'Dark' };
const THEME_ICON = { system: 'monitor', light: 'sun', dark: 'moon' };

function applyTheme(theme) {
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}

applyTheme(getTheme());

// ---------- routes ----------

const NAV = [
  { href: '#/', label: 'Overview', icon: 'overview', match: (p) => p === '/' },
  { href: '#/buckets', label: 'Buckets', icon: 'bucket', match: (p) => p.startsWith('/buckets') },
  { href: '#/accounts', label: 'Accounts', icon: 'user', match: (p) => p.startsWith('/accounts') },
  { href: '#/tokens', label: 'Tokens', icon: 'key', match: (p) => p === '/tokens' },
  { href: '#/quarantine', label: 'Quarantine', icon: 'shield', match: (p) => p === '/quarantine', id: 'quarantine' },
];

const ROUTES = [
  { re: /^\/$/, view: renderOverview, title: 'Overview' },
  { re: /^\/buckets$/, view: renderBuckets, title: 'Buckets' },
  { re: /^\/buckets\/([^/]+)\/settings$/, names: ['name'], view: renderBucketSettings, title: 'Bucket settings' },
  { re: /^\/buckets\/([^/]+)$/, names: ['name'], view: renderBucket, title: 'Bucket' },
  { re: /^\/accounts$/, view: renderAccounts, title: 'Accounts' },
  { re: /^\/accounts\/([^/]+)$/, names: ['id'], view: renderAccount, title: 'Account' },
  { re: /^\/tokens$/, view: renderTokens, title: 'Tokens' },
  { re: /^\/quarantine$/, view: renderQuarantine, title: 'Quarantine' },
];

// parseHash splits "#/buckets/x?prefix=a%2F" into a decoded path and its query.
function parseHash() {
  const raw = location.hash.replace(/^#/, '') || '/';
  const q = raw.indexOf('?');
  const path = q < 0 ? raw : raw.slice(0, q);
  const query = new URLSearchParams(q < 0 ? '' : raw.slice(q + 1));
  return { path: path.startsWith('/') ? path : `/${path}`, query };
}

function matchRoute(path) {
  for (const r of ROUTES) {
    const m = r.re.exec(path);
    if (!m) continue;
    const params = {};
    (r.names || []).forEach((n, i) => {
      try {
        params[n] = decodeURIComponent(m[i + 1]);
      } catch {
        params[n] = m[i + 1];
      }
    });
    return { route: r, params };
  }
  return null;
}

// ---------- shell ----------

let shell = null; // { el, view, nav, quarantineBadge, ... } while signed in
let routeCtl = null; // AbortController of the current view
let navSeq = 0;

function sessionNotice(reason) {
  const idleMin = Math.round((session()?.idle_timeout_seconds || 1800) / 60);
  switch (reason) {
    case 'expired_idle':
      return `Your session expired (idle ${idleMin} min). Sign in again.`;
    case 'expired_absolute':
      return 'Your session expired (8 h limit). Sign in again.';
    case 'signed_out':
      return 'You signed out.';
    default:
      return 'Your session is no longer valid. Sign in again.';
  }
}

function showLogin(notice) {
  if (routeCtl) routeCtl.abort();
  routeCtl = null;
  shell = null;
  document.title = 'Sign in · jay console';
  app.removeAttribute('aria-busy');
  renderLogin(app, {
    notice,
    onSignedIn: () => {
      // replaceState, not location.hash: no hashchange, so no second route().
      history.replaceState(null, '', `${location.pathname}${location.search}#/`);
      showShell();
    },
  });
}

function themeButton() {
  const label = h('span', {});
  const iconSlot = h('span', {});
  const btn = h('button', { type: 'button', class: 'side-btn' }, iconSlot, label);
  const sync = () => {
    const t = getTheme();
    label.textContent = `Theme: ${THEME_LABEL[t]}`;
    iconSlot.replaceChildren(icon(THEME_ICON[t]));
  };
  btn.addEventListener('click', () => {
    const next = THEMES[(THEMES.indexOf(getTheme()) + 1) % THEMES.length];
    setTheme(next);
    applyTheme(next);
    sync();
  });
  sync();
  return btn;
}

async function doLogout() {
  try {
    await logout();
  } catch (err) {
    toast({ tone: 'danger', title: 'Could not sign out', message: err.message, requestId: err.requestId });
    return;
  }
  showLogin(sessionNotice('signed_out'));
}

function buildShell(info) {
  const quarantineBadge = h('span', { class: 'is-hidden' });
  const navLinks = NAV.map((n) =>
    h('a', { class: 'nav-link', href: n.href, 'data-nav': n.href }, icon(n.icon), h('span', {}, n.label), n.id === 'quarantine' ? quarantineBadge : null),
  );
  const view = h('div', { class: 'content-inner' });
  const main = h('main', { class: 'content', id: 'main', tabindex: '-1' }, view);
  const scrim = h('div', { class: 'scrim' });
  const menuBtn = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Open navigation', 'aria-expanded': 'false', 'aria-controls': 'sidebar' }, icon('menu', { size: 20 }));
  const sidebar = h(
    'aside',
    { class: 'sidebar', id: 'sidebar' },
    h('a', { class: 'brand', href: '#/' }, h('img', { src: assetUrl('favicon.svg'), alt: '', width: '24', height: '24' }), h('span', { class: 'brand-name' }, 'jay'), h('span', { class: 'brand-sub' }, 'console')),
    h('nav', { class: 'nav', 'aria-label': 'Main' }, navLinks),
    h(
      'div',
      { class: 'sidebar-foot' },
      h('div', { class: 'sidebar-version' }, `v${info.version} · ${info.commit}`),
      h('a', { class: 'side-btn', href: DOCS_URL, target: '_blank', rel: 'noopener noreferrer' }, icon('external'), 'Docs'),
      themeButton(),
      h('button', { type: 'button', class: 'side-btn', on: { click: doLogout } }, icon('logout'), 'Sign out'),
    ),
  );
  const topbar = h('header', { class: 'topbar' }, menuBtn, h('a', { class: 'brand', href: '#/' }, h('img', { src: assetUrl('favicon.svg'), alt: '', width: '24', height: '24' }), h('span', { class: 'brand-name' }, 'jay'), h('span', { class: 'brand-sub' }, 'console')));
  const el = h('div', { class: 'shell' }, topbar, sidebar, scrim, main);

  const narrow = window.matchMedia('(max-width: 899px)');
  const setNav = (open) => {
    el.classList.toggle('nav-open', open);
    menuBtn.setAttribute('aria-expanded', String(open));
    // Off-canvas links must not be reachable by keyboard while hidden.
    sidebar.inert = narrow.matches && !open;
  };
  menuBtn.addEventListener('click', () => setNav(!el.classList.contains('nav-open')));
  scrim.addEventListener('click', () => setNav(false));
  narrow.addEventListener('change', () => setNav(false));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && el.classList.contains('nav-open') && el.isConnected) setNav(false);
  });
  setNav(false);

  return { el, view, main, navLinks, quarantineBadge, setNav };
}

async function refreshShell() {
  if (!shell) return;
  const b = shell.quarantineBadge;
  try {
    const items = await adminApi('GET', '/quarantine');
    b.className = items.length > 0 ? 'badge badge-danger' : 'is-hidden';
    b.textContent = items.length > 0 ? formatCount(items.length) : '';
    b.removeAttribute('title');
  } catch (err) {
    if (err.name === 'AbortError') return;
    // Unknown is not zero: say the count could not be read.
    b.className = 'badge badge-warn';
    b.textContent = '?';
    b.title = `Could not read the quarantine count: ${err.message}`;
  }
}

function ctxFor(root, params, query, signal) {
  return {
    root,
    params,
    query,
    session: session(),
    signal,
    navigate(hash) {
      location.hash = hash.startsWith('#') ? hash : `#${hash}`;
    },
    setTitle(text) {
      document.title = `${text} · jay console`;
    },
    refreshShell,
  };
}

async function route() {
  if (!shell) return;
  const mySeq = ++navSeq;
  if (routeCtl) routeCtl.abort();
  routeCtl = new AbortController();
  const { path, query } = parseHash();
  for (const a of shell.navLinks) {
    const item = NAV.find((n) => n.href === a.dataset.nav);
    if (item.match(path)) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  shell.setNav(false);

  // Each navigation renders into a fresh node, so a view that is still
  // awaiting data when the person moves on writes into a detached tree.
  const root = h('div');
  shell.view.replaceChildren(root);
  shell.main.focus({ preventScroll: true });
  window.scrollTo(0, 0);

  const found = matchRoute(path);
  if (!found) {
    document.title = 'Not found · jay console';
    emptyState(root, { icon: 'alert', title: 'Page not found', body: `There is no page at ${path}.`, action: h('a', { href: '#/' }, 'Go to the overview') });
    return;
  }
  const ctx = ctxFor(root, found.params, query, routeCtl.signal);
  ctx.setTitle(found.route.title);
  try {
    await found.route.view(ctx);
  } catch (err) {
    if (err.name === 'AbortError' || mySeq !== navSeq) return;
    errorState(root, err, { title: `Could not open ${found.route.title}`, retry: route });
  }
}

function showShell() {
  const info = session();
  shell = buildShell(info);
  app.removeAttribute('aria-busy');
  app.replaceChildren(shell.el);
  refreshShell();
  route();
}

onSignedOut((reason) => {
  if (!shell) return;
  showLogin(sessionNotice(reason));
});

window.addEventListener('hashchange', route);

// ---------- boot ----------

async function boot() {
  loading(app, 'Loading…');
  try {
    const info = await getSession();
    if (info) showShell();
    else showLogin();
  } catch (err) {
    // The console could not be reached: that is an error screen, not a login.
    errorState(app, err, { title: 'Could not reach the console', retry: boot });
  }
}

boot();
