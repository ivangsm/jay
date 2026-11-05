// Login screen. It is rendered without the shell, straight into #app.

import { login } from '../api.js';
import { assetUrl, button, errorDetails, h, icon, textInput } from '../ui.js';

// renderLogin draws the form. `notice` is an optional banner (why the person
// is back here); onSignedIn(session) runs after a verified 201.
export function renderLogin(root, { notice, onSignedIn } = {}) {
  const input = textInput({ id: 'admin-token', type: 'password', autocomplete: 'current-password', 'aria-describedby': 'admin-token-hint' });
  const reveal = h(
    'button',
    { type: 'button', class: 'btn btn-secondary', 'aria-label': 'Show token', 'aria-pressed': 'false' },
    icon('eye'),
  );
  reveal.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    reveal.setAttribute('aria-pressed', String(show));
    reveal.setAttribute('aria-label', show ? 'Hide token' : 'Show token');
    reveal.replaceChildren(icon(show ? 'eye-off' : 'eye'));
  });

  const errorBox = h('div', { class: 'login-error' });
  const submit = button({ label: 'Sign in', variant: 'primary', type: 'submit' });

  const form = h(
    'form',
    { novalidate: true, autocomplete: 'on' },
    h(
      'div',
      { class: 'field' },
      h('label', { for: 'admin-token' }, 'Admin token'),
      h('div', { class: 'input-group' }, input, reveal),
      h('div', { class: 'field-hint', id: 'admin-token-hint' }, 'The value of JAY_ADMIN_TOKEN. It is sent once; the browser keeps a session cookie, never the token.'),
    ),
    submit,
    errorBox,
  );

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const token = input.value;
    errorBox.replaceChildren();
    if (!token) {
      errorBox.append(h('div', { class: 'banner banner-danger', role: 'alert' }, 'Enter the admin token.'));
      input.focus();
      return;
    }
    submit.disabled = true;
    try {
      const info = await login(token);
      // The token has done its job: empty the field before anything else runs.
      input.value = '';
      onSignedIn?.(info);
    } catch (err) {
      submit.disabled = false;
      const lead =
        err.status === 401
          ? 'Invalid admin token. (401)'
          : err.status === 429
            ? 'Too many failed attempts from this address. Try again in 15 minutes. (429)'
            : 'Sign in failed.';
      errorBox.append(
        h('div', { class: 'banner banner-danger', role: 'alert' }, h('div', {}, h('strong', {}, lead), errorDetails(err))),
      );
      input.focus();
      input.select();
    }
  });

  root.replaceChildren(
    h(
      'div',
      { class: 'login-wrap' },
      h(
        'div',
        { class: 'login-card' },
        h('div', { class: 'login-brand' }, h('img', { src: assetUrl('favicon.svg'), alt: '', width: '28', height: '28' }), h('strong', {}, 'jay'), h('span', {}, 'console')),
        notice ? h('div', { class: 'banner banner-warn', role: 'status' }, icon('alert'), h('span', {}, notice)) : null,
        form,
      ),
    ),
  );
  input.focus();
}
