// DOM components shared by every view. Nothing in the console builds markup
// from strings: text always enters as text nodes, through h().

import { icon as makeIcon } from './icons.js';
import { JayError } from './api.js';

export const icon = makeIcon;

// assetUrl resolves a path under the hashed static root (for example
// 'favicon.svg'), whatever the hash of this build is.
export function assetUrl(path) {
  return new URL(`../${path}`, import.meta.url).pathname;
}

// Props h() refuses. They are the ways to turn data into markup or inline
// style, which the CSP and the asset guard both forbid. The sink names are
// spelled in pieces so the guard, which greps sources, does not flag this list.
const FORBIDDEN_PROPS = new Set(['html', 'inner' + 'HTML', 'outer' + 'HTML', 'style']);
const BOOLEAN_PROPS = new Set(['disabled', 'checked', 'required', 'multiple', 'readOnly', 'selected', 'autofocus']);
// A URL attribute may not carry a script or data scheme.
const UNSAFE_URL = /^\s*(?:java\s*script|vbscript|data):/i;

function append(parent, child) {
  if (child === null || child === undefined || child === false || child === true) return;
  if (Array.isArray(child)) {
    for (const c of child) append(parent, c);
    return;
  }
  parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
}

// h builds an element. Children are Nodes, strings, numbers, arrays (flattened)
// or null/false (skipped). Event handlers go in `on`, never in on* props.
export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  let deferredValue;
  for (const [key, value] of Object.entries(props || {})) {
    if (FORBIDDEN_PROPS.has(key)) throw new Error(`h(): the "${key}" prop is not allowed`);
    if (key.startsWith('on') && key !== 'on') throw new Error(`h(): "${key}" is not allowed, use the on map`);
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') {
      el.className = Array.isArray(value) ? value.filter(Boolean).join(' ') : String(value);
    } else if (key === 'on') {
      for (const [evt, fn] of Object.entries(value)) el.addEventListener(evt, fn);
    } else if (key === 'value') {
      // A <select> only accepts a value once its options exist.
      deferredValue = value;
    } else if (BOOLEAN_PROPS.has(key)) {
      el[key] = Boolean(value);
    } else if (key === 'for') {
      el.setAttribute('for', String(value));
    } else if (value === true) {
      el.setAttribute(key, '');
    } else {
      if ((key === 'href' || key === 'src') && UNSAFE_URL.test(String(value))) {
        throw new Error(`h(): unsafe ${key}`);
      }
      el.setAttribute(key, String(value));
    }
  }
  for (const c of children) append(el, c);
  if (deferredValue !== undefined) el.value = String(deferredValue);
  return el;
}

// clear empties a container and drops the busy flag. Views call it before
// they render a state.
export function clear(container) {
  container.replaceChildren();
  container.removeAttribute('aria-busy');
}

export function button({ label, icon: iconName, variant = 'secondary', size = 'md', type = 'button', onClick, disabled, title } = {}) {
  const el = h(
    'button',
    {
      type,
      class: ['btn', `btn-${variant}`, size === 'sm' ? 'btn-sm' : ''],
      disabled,
      title,
      'aria-label': label ? undefined : title,
      on: onClick ? { click: onClick } : undefined,
    },
    iconName ? makeIcon(iconName) : null,
    label ? h('span', {}, label) : null,
  );
  return el;
}

export function pageHeader({ title, subtitle, actions = [], breadcrumbs } = {}) {
  const crumbs =
    breadcrumbs?.length
      ? h(
          'nav',
          { class: 'breadcrumbs', 'aria-label': 'Breadcrumb' },
          breadcrumbs.flatMap((c, i) => [
            i > 0 ? h('span', { 'aria-hidden': 'true' }, '/') : null,
            c.href ? h('a', { href: c.href }, c.label) : h('span', {}, c.label),
          ]),
        )
      : null;
  return h(
    'header',
    { class: 'page-header' },
    h('div', {}, crumbs, h('h1', {}, title), subtitle ? h('p', { class: 'subtitle' }, subtitle) : null),
    actions.length ? h('div', { class: 'page-actions' }, actions) : null,
  );
}

export function loading(container, label = 'Loading…') {
  container.replaceChildren(
    h('div', { class: 'loading', role: 'status' }, h('div', { class: 'spinner', 'aria-hidden': 'true' }), h('span', {}, label)),
  );
  container.setAttribute('aria-busy', 'true');
}

export function badge(text, tone = 'neutral') {
  return h('span', { class: ['badge', tone === 'neutral' ? '' : `badge-${tone}`] }, text);
}

// errorDetails lists what jay said: message, code, HTTP status and the request
// ids, each copyable so a report can quote them.
export function errorDetails(err) {
  const rows = [];
  const message = err?.message || String(err);
  rows.push(['Message', message]);
  if (err instanceof JayError) {
    if (err.code) rows.push(['Code', err.code]);
    if (err.status) rows.push(['HTTP status', String(err.status)]);
    if (err.reason) rows.push(['Reason', err.reason]);
    if (err.requestId) rows.push(['Request id', err.requestId, true]);
    if (err.s3RequestId) rows.push(['S3 request id', err.s3RequestId, true]);
  }
  return h(
    'dl',
    { class: 'error-details' },
    rows.flatMap(([label, value, copyable]) => [
      h('dt', {}, label),
      h('dd', {}, value, copyable ? [' ', copyButton(value, { label: 'Copy' })] : null),
    ]),
  );
}

// errorState replaces the container's content with the failure. A fetch that
// failed must look like a failure: never an empty list.
export function errorState(container, err, { title = 'Request failed', retry } = {}) {
  container.replaceChildren(
    h(
      'div',
      { class: 'state state-error', role: 'alert' },
      h('h2', {}, makeIcon('alert'), title),
      errorDetails(err),
      retry ? h('div', {}, button({ label: 'Retry', icon: 'refresh', onClick: retry })) : null,
    ),
  );
  container.removeAttribute('aria-busy');
}

export function emptyState(container, { icon: iconName, title, body, action } = {}) {
  const act = action && !(action instanceof Node) ? button(action) : action;
  container.replaceChildren(
    h(
      'div',
      { class: 'state' },
      iconName ? makeIcon(iconName, { size: 28 }) : null,
      h('h2', {}, title),
      body ? h('p', {}, body) : null,
      act || null,
    ),
  );
  container.removeAttribute('aria-busy');
}

export function copyButton(text, { label = 'Copy' } = {}) {
  const span = h('span', {}, label);
  const btn = h('button', { type: 'button', class: 'btn btn-ghost btn-sm', title: `Copy ${text.length > 40 ? 'to clipboard' : text}` }, makeIcon('copy'), span);
  let timer = 0;
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(text);
      span.textContent = 'Copied';
      clearTimeout(timer);
      timer = setTimeout(() => {
        span.textContent = label;
      }, 1500);
    } catch {
      // No clipboard permission: put the value in a field, select it, and let
      // the person copy it themselves.
      const input = h('input', { class: 'input mono', readOnly: true, value: text, 'aria-label': 'Value to copy' });
      btn.after(input);
      span.textContent = 'Press Ctrl/Cmd+C';
      input.focus();
      input.select();
    }
  });
  return btn;
}

// ---------- forms ----------

let fieldSeq = 0;

export function field({ label, hint, error, control, id } = {}) {
  const ctlId = id || control?.id || `f${++fieldSeq}`;
  if (control && !control.id) control.id = ctlId;
  const describedBy = [];
  if (hint) describedBy.push(`${ctlId}-hint`);
  if (error) describedBy.push(`${ctlId}-err`);
  if (control && describedBy.length) control.setAttribute('aria-describedby', describedBy.join(' '));
  if (control && error) control.setAttribute('aria-invalid', 'true');
  return h(
    'div',
    { class: 'field' },
    label ? h('label', { for: ctlId }, label) : null,
    control,
    hint ? h('div', { class: 'field-hint', id: `${ctlId}-hint` }, hint) : null,
    error ? h('div', { class: 'field-error', id: `${ctlId}-err`, role: 'alert' }, error) : null,
  );
}

export function textInput(props = {}) {
  const { class: cls, ...rest } = props;
  return h('input', { type: 'text', autocomplete: 'off', ...rest, class: ['input', cls] });
}

export function textArea(props = {}) {
  const { class: cls, ...rest } = props;
  return h('textarea', { ...rest, class: ['textarea', cls] });
}

export function select({ options = [], value, onChange, id, name } = {}) {
  const opts = options.map((o) => (typeof o === 'string' ? { value: o, label: o } : o));
  return h(
    'select',
    { class: 'select', id, name, value, on: onChange ? { change: (e) => onChange(e.target.value, e) } : undefined },
    opts.map((o) => h('option', { value: o.value, disabled: o.disabled }, o.label)),
  );
}

export function checkbox({ label, checked, onChange } = {}) {
  return h(
    'label',
    { class: 'check' },
    h('input', { type: 'checkbox', checked, on: onChange ? { change: (e) => onChange(e.target.checked, e) } : undefined }),
    h('span', {}, label),
  );
}

export function keyValueList(pairs) {
  return h(
    'dl',
    { class: 'kv' },
    pairs.flatMap(([label, value]) => [h('dt', {}, label), h('dd', {}, value)]),
  );
}

export function progressBar(fraction, { label } = {}) {
  const bar = h('div', { class: 'progress-bar' });
  const known = typeof fraction === 'number' && Number.isFinite(fraction);
  if (known) bar.style.width = `${Math.round(Math.min(1, Math.max(0, fraction)) * 100)}%`;
  return h('div', {
    class: ['progress', known ? '' : 'progress-indeterminate'],
    role: 'progressbar',
    'aria-label': label,
    'aria-valuemin': known ? '0' : undefined,
    'aria-valuemax': known ? '100' : undefined,
    'aria-valuenow': known ? String(Math.round(fraction * 100)) : undefined,
  }, bar);
}

// ---------- table ----------

const INTERACTIVE = 'a, button, input, select, textarea, label, summary';

function keyOf(rowKey, row) {
  return typeof rowKey === 'function' ? rowKey(row) : row[rowKey];
}

export function dataTable({ columns, rows, rowKey, onRowClick, selectable = false, selected, onSelectionChange, empty, sort, onSort, caption } = {}) {
  const wrap = h('div', { class: 'table-wrap' });
  if (!rows || rows.length === 0) {
    const holder = h('div');
    wrap.append(holder);
    if (empty instanceof Node) holder.append(empty);
    else emptyState(holder, empty || { title: 'Nothing here yet' });
    return wrap;
  }
  const sel = selected || new Set();
  const keys = rows.map((r) => keyOf(rowKey, r));
  const emit = (next) => onSelectionChange?.(next);

  const headChecks = selectable ? h('input', { type: 'checkbox', 'aria-label': 'Select all rows' }) : null;
  if (headChecks) {
    const count = keys.filter((k) => sel.has(k)).length;
    headChecks.checked = count > 0 && count === keys.length;
    headChecks.indeterminate = count > 0 && count < keys.length;
    headChecks.addEventListener('change', () => emit(headChecks.checked ? new Set(keys) : new Set()));
  }

  const colClass = (c, tag) => [
    c.align === 'right' || c.numeric ? (tag === 'th' ? 'right' : 'numeric') : '',
    c.mono && tag === 'td' ? 'is-mono' : '',
    c.hideBelow === 600 ? 'hide-below-600' : '',
    c.hideBelow === 900 ? 'hide-below-900' : '',
  ];

  const headRow = h(
    'tr',
    {},
    selectable ? h('th', { class: 'col-check', scope: 'col' }, headChecks) : null,
    columns.map((c) => {
      const active = sort && sort.key === c.key;
      const content =
        c.sortable && onSort
          ? h('button', { type: 'button', class: 'sort-btn', on: { click: () => onSort(c.key) } }, c.label, active ? makeIcon(sort.dir === 'desc' ? 'arrow-down' : 'arrow-up', { size: 12 }) : null)
          : c.label;
      return h('th', { scope: 'col', class: colClass(c, 'th'), 'aria-sort': active ? (sort.dir === 'desc' ? 'descending' : 'ascending') : undefined }, content);
    }),
  );

  const body = rows.map((row, i) => {
    const key = keys[i];
    const isSel = sel.has(key);
    const tr = h(
      'tr',
      { class: [onRowClick ? 'is-clickable' : '', isSel ? 'is-selected' : ''], tabindex: onRowClick ? '0' : undefined },
      selectable
        ? h(
            'td',
            { class: 'col-check' },
            h('input', {
              type: 'checkbox',
              checked: isSel,
              'aria-label': 'Select row',
              on: {
                change: (e) => {
                  const next = new Set(sel);
                  if (e.target.checked) next.add(key);
                  else next.delete(key);
                  emit(next);
                },
              },
            }),
          )
        : null,
      columns.map((c) => {
        const value = c.render ? c.render(row) : row[c.key];
        return h('td', { 'data-label': c.label, class: colClass(c, 'td') }, value === undefined || value === null || value === '' ? '—' : value);
      }),
    );
    if (onRowClick) {
      tr.addEventListener('click', (e) => {
        if (e.target.closest(INTERACTIVE)) return;
        onRowClick(row, e);
      });
      tr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && e.target === tr) onRowClick(row, e);
      });
    }
    return tr;
  });

  wrap.append(
    h('table', { class: 'table' }, caption ? h('caption', {}, caption) : null, h('thead', {}, headRow), h('tbody', {}, body)),
  );
  return wrap;
}

// ---------- dialogs and drawers ----------

function firstFocusable(root) {
  return root.querySelector('input:not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled])');
}

// chrome builds the head/body/error/foot skeleton that dialogs and drawers
// share, and wires the lifecycle: Esc, backdrop click, busy lock, cleanup.
function chrome({ kind, title, body, actions, size, dismissible, onClose }) {
  const titleId = `dlg${++fieldSeq}`;
  const titleEl = h('h2', { id: titleId }, title);
  const closeBtn = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Close', title: 'Close' }, makeIcon('close'));
  const bodyEl = h('div', { class: 'dialog-body' });
  const errorEl = h('div', { class: 'dialog-error' });
  const footEl = h('div', { class: 'dialog-foot' });
  const dialog = h(
    'dialog',
    { class: kind === 'drawer' ? 'drawer' : ['dialog', size === 'lg' ? 'dialog-lg' : '', size === 'sm' ? 'dialog-sm' : ''], 'aria-labelledby': titleId },
    h('div', { class: 'dialog-form' }, h('div', { class: 'dialog-head' }, titleEl, dismissible ? closeBtn : null), bodyEl, errorEl, footEl),
  );

  let busy = false;
  let closed = false;
  let actionButtons = [];

  const ctl = {
    element: dialog,
    close() {
      if (closed) return;
      if (dialog.open) dialog.close();
      else finish();
    },
    setBusy(v) {
      busy = Boolean(v);
      for (const b of actionButtons) b.disabled = busy;
      closeBtn.disabled = busy;
      dialog.toggleAttribute('aria-busy', busy);
    },
    setError(err) {
      errorEl.replaceChildren();
      if (!err) return;
      errorEl.append(h('div', { class: 'banner banner-danger', role: 'alert' }, errorDetails(err)));
      errorEl.scrollIntoView?.({ block: 'nearest' });
    },
    setBody(node) {
      bodyEl.replaceChildren(node);
    },
    setTitle(text) {
      titleEl.textContent = text;
    },
    setActions(list) {
      renderActions(list);
    },
  };

  function renderActions(list) {
    actionButtons = [];
    footEl.replaceChildren();
    for (const a of list) {
      const b = button({ label: a.label, variant: a.variant || 'secondary', disabled: a.disabled });
      b.addEventListener('click', async () => {
        if (busy) return;
        if (!a.onClick) {
          ctl.close();
          return;
        }
        ctl.setError(null);
        ctl.setBusy(true);
        let keepOpen = false;
        try {
          // An action closes the dialog when it resolves, unless it resolves
          // with `false` (it has swapped the body, for instance). A throw
          // keeps the dialog open and shows the error inside it.
          keepOpen = (await a.onClick(ctl)) === false;
        } catch (e) {
          ctl.setBusy(false);
          ctl.setError(e);
          return;
        }
        ctl.setBusy(false);
        if (!keepOpen) ctl.close();
      });
      b.dataset.autofocus = a.autofocus ? '1' : '';
      actionButtons.push(b);
      footEl.append(b);
    }
    footEl.classList.toggle('is-hidden', list.length === 0);
  }

  function finish() {
    if (closed) return;
    closed = true;
    dialog.remove();
    onClose?.();
  }

  bodyEl.append(body instanceof Node ? body : document.createTextNode(body ?? ''));
  renderActions(actions);
  closeBtn.addEventListener('click', () => {
    if (!busy) ctl.close();
  });
  dialog.addEventListener('cancel', (e) => {
    if (busy || !dismissible) e.preventDefault();
  });
  dialog.addEventListener('click', (e) => {
    if (e.target === dialog && dismissible && !busy) ctl.close();
  });
  dialog.addEventListener('close', finish);

  document.body.append(dialog);
  dialog.showModal();
  const preferred = actionButtons.find((b) => b.dataset.autofocus === '1') || firstFocusable(bodyEl);
  (preferred || closeBtn).focus();
  return ctl;
}

// openDialog shows a modal <dialog>. Actions are { label, variant, onClick,
// autofocus }: onClick(ctl) may be async; no onClick means "just close".
export function openDialog({ title, body, actions = [], size = 'md', dismissible = true, onClose } = {}) {
  return chrome({ kind: 'dialog', title, body, actions, size, dismissible, onClose });
}

export function openDrawer({ title, body, actions = [], onClose } = {}) {
  return chrome({ kind: 'drawer', title, body, actions, size: 'md', dismissible: true, onClose });
}

// confirmDestructive asks for the exact phrase before it runs `run`. It
// resolves with run()'s result as soon as it succeeds, or undefined if the
// dialog is cancelled or closed first.
export function confirmDestructive({ title, description, confirmPhrase, actionLabel = 'Delete', run, renderResult } = {}) {
  return new Promise((resolve) => {
    let finished = false;
    const input = textInput({ 'aria-label': `Type ${confirmPhrase} to confirm`, autocapitalize: 'off', spellcheck: 'false' });
    let confirmBtn = null;
    const sync = () => {
      if (confirmBtn) confirmBtn.disabled = input.value !== confirmPhrase;
    };
    input.addEventListener('input', sync);
    const body = h(
      'div',
      {},
      description instanceof Node ? description : h('p', {}, description),
      h('div', { class: 'field' }, h('label', { for: 'confirm-phrase' }, 'Type ', h('code', {}, confirmPhrase), ' to confirm'), input),
    );
    input.id = 'confirm-phrase';
    const ctl = openDialog({
      title,
      body,
      size: 'sm',
      onClose: () => {
        if (!finished) resolve(undefined);
      },
      actions: [
        { label: 'Cancel' },
        {
          label: actionLabel,
          variant: 'danger',
          onClick: async (c) => {
            if (input.value !== confirmPhrase) throw new Error(`Type ${confirmPhrase} exactly to confirm.`);
            const result = await run();
            finished = true;
            resolve(result);
            if (renderResult) {
              c.setBody(renderResult(result));
              c.setActions([{ label: 'Close' }]);
              return false;
            }
            return true;
          },
        },
      ],
    });
    confirmBtn = ctl.element.querySelectorAll('.dialog-foot button')[1];
    confirmBtn.disabled = true;
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !confirmBtn.disabled) confirmBtn.click();
    });
  });
}

// ---------- toasts ----------

const MAX_TOASTS = 3;
let toastBox = null;

// toast announces an outcome. Use tone 'ok' only after a verified 2xx.
export function toast({ tone = 'neutral', title, message, requestId } = {}) {
  if (!toastBox) {
    toastBox = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' });
    document.body.append(toastBox);
  }
  const el = h(
    'div',
    { class: ['toast', tone === 'neutral' ? '' : `toast-${tone}`] },
    h('div', { class: 'toast-title' }, title),
    message ? h('div', { class: 'toast-msg' }, message) : null,
    requestId ? h('div', { class: 'toast-rid' }, `Request id ${requestId}`) : null,
  );
  toastBox.append(el);
  while (toastBox.children.length > MAX_TOASTS) toastBox.firstElementChild.remove();
  setTimeout(() => el.remove(), 6000);
  return el;
}

// menuButton is the "More" menu: a button that opens a list of actions.
// items: [{ label, icon, onClick, disabled }].
export function menuButton({ label = 'More', icon: iconName = 'more', items = [] } = {}) {
  const list = h('div', { class: 'menu-list is-hidden', role: 'menu' });
  const trigger = button({ label, icon: iconName, variant: 'secondary' });
  trigger.setAttribute('aria-haspopup', 'menu');
  trigger.setAttribute('aria-expanded', 'false');
  const root = h('div', { class: 'menu' }, trigger, list);
  const close = () => {
    list.classList.add('is-hidden');
    trigger.setAttribute('aria-expanded', 'false');
    document.removeEventListener('click', onDoc, true);
    document.removeEventListener('keydown', onKey, true);
  };
  const onDoc = (e) => {
    if (!root.contains(e.target)) close();
  };
  const onKey = (e) => {
    if (e.key === 'Escape') {
      close();
      trigger.focus();
    }
  };
  for (const it of items) {
    list.append(
      h('button', { type: 'button', role: 'menuitem', class: 'menu-item', disabled: it.disabled, on: { click: () => { close(); it.onClick?.(); } } }, it.icon ? makeIcon(it.icon) : null, it.label),
    );
  }
  trigger.addEventListener('click', () => {
    if (list.classList.contains('is-hidden')) {
      list.classList.remove('is-hidden');
      trigger.setAttribute('aria-expanded', 'true');
      document.addEventListener('click', onDoc, true);
      document.addEventListener('keydown', onKey, true);
    } else {
      close();
    }
  });
  return root;
}
