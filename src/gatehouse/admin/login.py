"""Fixed browser bootstrap: remove a fragment capability before a deliberate POST."""

from __future__ import annotations

LOGIN_SCRIPT = """(() => {
  'use strict';
  let fragment = window.location.hash;
  try {
    window.history.replaceState(null, '', '/login');
  } catch (_) {
    return;
  }
  const form = document.getElementById('admin-login');
  const input = document.getElementById('login-code');
  const button = document.getElementById('login-submit');
  const message = document.getElementById('login-message');
  let match = fragment.length === 49 && /^#code=([A-Za-z0-9_-]{43})$/.exec(fragment);
  fragment = '';
  if (!match) return;
  input.value = match[1];
  match = null;
  button.disabled = false;
  message.textContent = 'Continue only if you requested this local administrative session.';
  let submitted = false;
  const clear = () => {
    input.value = '';
    button.disabled = true;
    message.textContent = 'Open a new sign-in link using the Gatehouse dashboard command.';
  };
  form.addEventListener('submit', event => {
    if (submitted || button.disabled || !input.value) {
      event.preventDefault();
      return;
    }
    submitted = true;
    button.disabled = true;
  });
  window.addEventListener('pagehide', clear);
  window.addEventListener('pageshow', event => {
    if (event.persisted) clear();
  });
})();"""


def render_login_page() -> str:
    """Return identical HTML for every visitor, without server-supplied capability data."""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Gatehouse admin sign in</title></head><body><main>"
        "<h1>Gatehouse admin sign in</h1>"
        '<p id="login-message">Open a new sign-in link using the Gatehouse dashboard command.</p>'
        '<form id="admin-login" method="post" action="/login" autocomplete="off">'
        '<input id="login-code" type="hidden" name="code" value="">'
        '<button id="login-submit" type="submit" disabled>Continue to dashboard</button>'
        "</form><noscript>JavaScript is required to use this sign-in link.</noscript>"
        f"</main><script>{LOGIN_SCRIPT}</script></body></html>"
    )
