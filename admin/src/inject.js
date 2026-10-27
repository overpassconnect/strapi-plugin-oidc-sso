'use strict';

/**
 * Framework-agnostic login-page enhancer. No React imports on purpose: it must
 * survive the login component being re-rendered/unmounted, so it works at the
 * DOM level and re-injects idempotently via a MutationObserver.
 */

const CONTAINER_ID = 'oidc-sso-container';
const ERROR_ID = 'oidc-sso-error';

const ERROR_MESSAGES = {
  sso_disabled: 'Single sign-on is currently disabled.',
  provider_unreachable: 'Could not reach the identity provider. Please try again shortly.',
  state_invalid: 'Your sign-in session was invalid. Please try again.',
  state_expired: 'Your sign-in session expired. Please try again.',
  code_exchange_failed: 'Sign-in could not be completed with the identity provider.',
  id_token_invalid: 'The identity provider returned an invalid token.',
  nonce_mismatch: 'Sign-in validation failed. Please try again.',
  access_token_invalid: 'The identity provider returned an invalid token.',
  no_email: 'Your identity-provider account has no email address; an administrator must add one.',
  email_unverified: 'Your identity-provider email is not verified; an administrator must verify it before you can sign in.',
  no_mapped_role: 'Your identity-provider roles or groups do not grant access to this admin panel.',
  email_relink_refused: 'This email is already linked to a different identity. Contact an administrator.',
  user_inactive: 'This admin account is deactivated.',
  provisioning_failed: 'Your admin account could not be provisioned. Contact an administrator.',
  session_failed: 'Could not establish an admin session. Contact an administrator.',
  provider_error: 'Sign-in was cancelled or failed at the identity provider.',
};

let statusCache = null;

async function fetchStatus() {
  if (statusCache) return statusCache;
  try {
    const res = await fetch('/oidc-sso/status', { credentials: 'same-origin' });
    if (!res.ok) return null;
    statusCache = await res.json();
    return statusCache;
  } catch (e) {
    return null;
  }
}

function isLoginPage() {
  // Heuristic that does not depend on Strapi internals: the auth login route
  // plus a visible password field.
  const path = window.location.pathname || '';
  if (!/\/auth\/login\/?$/.test(path)) return false;
  return !!document.querySelector('input[type="password"], input[name="password"]');
}

function currentReturnTo() {
  const params = new URLSearchParams(window.location.search);
  const raw = params.get('redirectTo') || params.get('returnTo') || '/admin';
  if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//')) return '/admin';
  if (raw !== '/admin' && !raw.startsWith('/admin/') && !raw.startsWith('/admin?')) return '/admin';
  return raw;
}

function buttonStyles() {
  return [
    'display:flex',
    'align-items:center',
    'justify-content:center',
    'gap:8px',
    'width:100%',
    'box-sizing:border-box',
    'margin-top:16px',
    'padding:10px 16px',
    'border:1px solid #dcdce4',
    'border-radius:4px',
    'background:#ffffff',
    'color:#32324d',
    'font-size:14px',
    'font-weight:600',
    'line-height:1.2',
    'cursor:pointer',
    'text-decoration:none',
  ].join(';');
}

function dividerHtml() {
  return (
    '<div style="display:flex;align-items:center;gap:12px;margin:20px 0 4px;color:#8e8ea9;font-size:12px;">' +
    '<span style="flex:1;height:1px;background:#dcdce4;"></span>' +
    '<span>OR</span>' +
    '<span style="flex:1;height:1px;background:#dcdce4;"></span>' +
    '</div>'
  );
}

function renderError() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('sso_error');
  if (!code) return;
  if (document.getElementById(ERROR_ID)) return;

  const form = document.querySelector('form');
  if (!form || !form.parentElement) return;

  const msg = Object.prototype.hasOwnProperty.call(ERROR_MESSAGES, code)
    ? ERROR_MESSAGES[code]
    : 'Single sign-on failed. Please try again.';
  const box = document.createElement('div');
  box.id = ERROR_ID;
  box.setAttribute('role', 'alert');
  box.style.cssText =
    'margin:0 0 16px;padding:10px 12px;border:1px solid #f5c0b8;background:#fcecea;' +
    'color:#b72b1a;border-radius:4px;font-size:13px;';
  box.textContent = msg;
  form.parentElement.insertBefore(box, form);
}

async function tryInject() {
  if (!isLoginPage()) return;
  renderError();

  if (document.getElementById(CONTAINER_ID)) return;
  const status = await fetchStatus();
  if (!status || status.enabled === false) return;

  const form = document.querySelector('form');
  if (!form || !form.parentElement) return;

  const container = document.createElement('div');
  container.id = CONTAINER_ID;
  container.innerHTML = dividerHtml();

  const link = document.createElement('a');
  link.setAttribute('href', `${status.loginPath}?returnTo=${encodeURIComponent(currentReturnTo())}`);
  link.style.cssText = buttonStyles();
  link.textContent = status.buttonLabel || 'Sign in with SSO';
  container.appendChild(link);

  form.parentElement.insertBefore(container, form.nextSibling);

  if (status.hideLocalLogin) {
    // Break-glass is still reachable directly; we only visually de-emphasise it.
    form.style.display = 'none';
    const hint = document.createElement('button');
    hint.type = 'button';
    hint.textContent = 'Use local login instead';
    hint.style.cssText = 'margin-top:12px;background:none;border:none;color:#4945ff;cursor:pointer;font-size:13px;';
    hint.addEventListener('click', () => {
      form.style.display = '';
      hint.remove();
    });
    container.appendChild(hint);
  }
}

// Same-origin /admin path guard (mirrors the server's safeReturnTo).
function safeReturnToClient(rt) {
  if (typeof rt !== 'string' || !rt.startsWith('/') || rt.startsWith('//')) return '/admin';
  if (rt !== '/admin' && !rt.startsWith('/admin/') && !rt.startsWith('/admin?')) return '/admin';
  return rt;
}

/**
 * Completion step after the OIDC callback. The admin SPA initializes its token
 * from localStorage on cold load (StrapiApp: token = getStoredToken()) and does
 * NOT exchange the refresh cookie on its own. So when the callback bounces us
 * here with ?oidc_complete=<id>, we redeem that single-use id at the plugin's
 * /oidc-sso/complete-token endpoint for THIS login's access token (bound to the
 * id, not to any ambient refresh cookie - session-fixation defense) and write it
 * exactly where Strapi's own login puts it - localStorage 'jwtToken' +
 * 'isLoggedIn' - then navigate to the target so the SPA rehydrates as logged-in.
 */
function maybeCompleteSso() {
  const params = new URLSearchParams(window.location.search);
  const completionId = params.get('oidc_complete');
  if (!completionId) return false;
  const target = safeReturnToClient(params.get('returnTo') || '/admin');
  (async () => {
    try {
      // Redeem the single-use completion id for THIS login's access token. We do
      // NOT read the refresh cookie here, so a pre-existing/planted refresh cookie
      // cannot be adopted (session-fixation defense).
      const res = await fetch('/oidc-sso/complete-token?id=' + encodeURIComponent(completionId), {
        credentials: 'same-origin',
      });
      if (res.ok) {
        const body = await res.json();
        const token = body && body.data && body.data.token;
        if (token) {
          // Keys are Strapi admin internals (reducer.mjs STORAGE_KEYS).
          window.localStorage.setItem('jwtToken', JSON.stringify(token));
          window.localStorage.setItem('isLoggedIn', 'true');
          window.location.replace(target);
          return;
        }
      }
    } catch (e) {
      /* fall through to the error path */
    }
    window.location.replace('/admin/auth/login?sso_error=session_failed');
  })();
  return true;
}

export function injectSsoUi() {
  // If we're completing an SSO login, do that and skip the button UI.
  if (maybeCompleteSso()) return;

  let scheduled = false;
  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    window.setTimeout(() => {
      scheduled = false;
      tryInject().catch(() => {});
    }, 50);
  };

  // Initial attempt plus observe for client-side navigation / re-renders.
  schedule();
  const observer = new MutationObserver(schedule);
  observer.observe(document.body, { childList: true, subtree: true });

  // Also re-check on history navigation within the SPA.
  window.addEventListener('popstate', schedule);
}
