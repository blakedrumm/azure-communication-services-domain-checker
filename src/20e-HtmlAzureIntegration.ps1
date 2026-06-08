# ===== JavaScript Azure / MSAL Integration =====
$htmlPage += @'
function getMsalConfig() {
  // The client ID is injected server-side from ACS_ENTRA_CLIENT_ID env var.
  // If not set, auth buttons remain visible but disabled with guidance.
  const rawClientId = '__ENTRA_CLIENT_ID__';
  const clientId = (rawClientId || '').trim();
  if (!clientId || clientId.startsWith('__')) return null;

  const tenant = (entraTenant || '').trim();
  const authorityTenant = tenant || 'organizations';

  return {
    auth: {
      clientId: clientId,
      authority: `https://login.microsoftonline.com/${authorityTenant}`,
      knownAuthorities: ['login.microsoftonline.com'],
      redirectUri: window.location.origin + window.location.pathname,
      postLogoutRedirectUri: window.location.origin + window.location.pathname
    },
    cache: {
      cacheLocation: 'sessionStorage',
      storeAuthStateInCookie: false
    }
  };
}

function isMsAutoSignInEnabled() {
  const value = String(entraAutoSignIn || '1').trim().toLowerCase();
  return !['0', 'false', 'no', 'off', 'disabled'].includes(value);
}

function getSafeMsalErrorInfo(error) {
  const clean = value => {
    const text = String(value || '').trim();
    return /^[A-Za-z0-9_.:-]+$/.test(text) ? text : '';
  };

  return {
    errorCode: clean(error?.errorCode || error?.code || error?.name) || 'unknown_error',
    subError: clean(error?.subError),
    correlationId: clean(error?.correlationId)
  };
}

async function tryMsAutoSignIn() {
  if (!msalInstance || !isMsAutoSignInEnabled()) return false;

  try {
    // This does not force Windows Integrated Authentication. It gives Entra ID
    // one quiet chance to use an existing browser / device SSO session
    // (including WAM/PRT/WIA-backed sessions where available). Any condition
    // that needs user interaction is swallowed so the manual sign-in button
    // remains the fallback UX.
    const ssoResult = await msalInstance.ssoSilent({
      scopes: GRAPH_SCOPES,
      prompt: 'none'
    });

    if (ssoResult && ssoResult.account && ssoResult.accessToken) {
      msAuthAccount = ssoResult.account;
      try { msalInstance.setActiveAccount(ssoResult.account); } catch {}
      await verifyMsAccount(ssoResult.accessToken);
      return true;
    }

    console.info('[ACS Auth] Automatic Microsoft Entra SSO did not return an account or access token; showing manual sign-in.');
  } catch (e) {
    console.info('[ACS Auth] Automatic Microsoft Entra SSO unavailable; showing manual sign-in.', getSafeMsalErrorInfo(e));
  }

  return false;
}

async function initMsAuth() {
  const config = getMsalConfig();
  if (!config) {
    // No client ID configured; keep button visible and show guidance on click
    const btn = document.getElementById('msSignInBtn');
    if (btn) {
      btn.style.display = '';
      btn.disabled = false;
      btn.innerHTML = t('signInMicrosoft');
    }
    msalInitError = 'Missing ACS_ENTRA_CLIENT_ID in the served HTML.';
    setStatus(t('authSignInNotConfigured'));
    return;
  }

  try {
    await ensureMsalLoaded();
  } catch (e) {
    msalInitError = e?.message || 'MSAL library not loaded.';
    setStatus(t('authLibraryLoadFailed'));
    return;
  }

  if (typeof msal === 'undefined') {
    msalInitError = 'MSAL library not loaded.';
    setStatus(t('authLibraryLoadFailed'));
    return;
  }

  try {
    msalInitError = null;
    msalInstance = new msal.PublicClientApplication(config);
    await msalInstance.initialize();

    // Handle redirect response (if returning from auth flow)
    let response = null;
    try {
      response = await msalInstance.handleRedirectPromise();
    } catch (e) {
      // MSAL throws this when the app is loaded normally (not from a redirect) but no request state exists.
      // Treat it as non-fatal so the sign-in button remains usable.
      const msg = (e && (e.errorMessage || e.message)) ? String(e.errorMessage || e.message) : '';
      const code = e && e.errorCode ? String(e.errorCode) : '';
      const isNoCache = (code === 'no_token_request_cache_error') || msg.includes('no_token_request_cache_error');
      if (!isNoCache) { throw e; }
      response = null;
    }

    if (response && response.account && response.accessToken) {
      // Redirect-based login just completed in this window
      msAuthAccount = response.account;
      await verifyMsAccount(response.accessToken);
      return;
    }

    // No redirect in progress: restore existing session, if any
    const accounts = msalInstance.getAllAccounts();
    if (accounts.length > 0) {
      msAuthAccount = accounts[0];
      try {
        const silentResult = await msalInstance.acquireTokenSilent({
          scopes: ['User.Read'],
          account: msAuthAccount
        });
        await verifyMsAccount(silentResult.accessToken);
      } catch (e) {
        // Silent acquisition failed; user needs to sign in again
        updateAuthUI(null);
      }
    } else {
      // No account in the MSAL cache. Try a quiet Entra browser/device SSO
      // sign-in before falling back to the explicit Sign in button.
      const signedIn = await tryMsAutoSignIn();
      if (!signedIn) {
        updateAuthUI(null);
      }
    }
  } catch (e) {
    console.error('MSAL initialization error:', e);
    msalInitError = e?.message || 'Unknown initialization error.';
    setStatus(t('authInitFailed'));
  }
}

async function msSignIn() {
  if (!msalInstance) {
    if (msalInitError) {
      setStatus(t('authInitFailedWithReason', { reason: msalInitError }));
    } else {
      setStatus(t('authSetClientIdAndRestart'));
    }
    return;
  }

  // When running against a local development host, Microsoft Entra sign-in
  // usually fails because Localhost is rarely a registered redirect URI for
  // the app registration. Warn the developer and let them choose to proceed.
  if (typeof isLocalDevHost === 'function' && isLocalDevHost()) {
    if (!window.confirm(t('localhostSignInWarning'))) {
      return;
    }
  }

  try {
    const btn = document.getElementById('msSignInBtn');
    if (btn) { btn.disabled = true; btn.textContent = t('authSigningIn'); }

    // Use redirect flow for best compatibility with browser / popup blockers.
    // Only the Microsoft Graph User.Read scope is requested so we can read the
    // signed-in user's basic profile for the intake-form gating and anonymous
    // sign-in metrics. No Azure management or Log Analytics scopes are requested.
    await msalInstance.loginRedirect({
      scopes: GRAPH_SCOPES,
      prompt: 'select_account'
    });
  } catch (e) {
    console.error('Sign-in error:', e);
    const btn = document.getElementById('msSignInBtn');
    if (btn) { btn.disabled = false; btn.innerHTML = t('signInMicrosoft'); }

    if (e && e.errorCode === 'user_cancelled') {
      setStatus(t('authSignInCancelled'));
    } else {
      setStatus(t('authSignInFailed', { reason: e?.errorMessage || e?.message || t('authUnknownError') }));
    }
  }
}

async function msSignOut() {
  if (!msalInstance) return;

  try {
    // Clear the MSAL token cache locally without redirecting to the Microsoft
    // logout page.  This avoids the account-picker screen and keeps the user
    // on the current page.  The next sign-in still uses prompt:'select_account'
    // so the user can choose a different account if needed.
    const accounts = msalInstance.getAllAccounts() || [];
    for (const acct of accounts) {
      // MSAL v2 removeAccount is synchronous in the browser cache but returns void.
      // It only removes the local cache entry, it does not call Microsoft's logout endpoint.
      try { msalInstance.setActiveAccount(null); } catch {}
    }
    // Clear all MSAL-related entries from session storage
    const keysToRemove = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && (key.startsWith('msal.') || key.includes('login.microsoftonline.com') || key.includes('msal'))) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(k => sessionStorage.removeItem(k));

    msAuthAccount = null;
    isMsEmployee = false;
    updateAuthUI(null);
  } catch (e) {
    console.error('Sign-out error:', e);
  }
}

async function verifyMsAccount(accessToken) {
  try {
    let profile = null;
    try {
      const resp = await fetch('https://graph.microsoft.com/v1.0/me', {
        headers: {
          'Authorization': 'Bearer ' + accessToken
        }
      });
      if (resp.ok) {
        profile = await resp.json();
      }
    } catch {}

    const claims = (msAuthAccount && msAuthAccount.idTokenClaims) ? msAuthAccount.idTokenClaims : {};
    const userPrincipalName = String((profile && (profile.userPrincipalName || profile.mail)) || msAuthAccount?.username || claims.preferred_username || '').trim();
    const displayName = String((profile && profile.displayName) || msAuthAccount?.name || claims.name || userPrincipalName || '').trim();
    const tenantId = String(claims.tid || '').trim();
    // Object id (oid) is stable per user per tenant. We never send it raw -
    // we hash (tid + ':' + oid) with SubtleCrypto so the server only ever
    // sees an opaque 64-char hex digest.
    const objectId = String(claims.oid || '').trim();

    const data = {
      displayName,
      userPrincipalName,
      tenantId,
      isMicrosoftEmployee: /@(microsoft\.com|microsoftsupport\.com)$/i.test(userPrincipalName)
    };

    isMsEmployee = data.isMicrosoftEmployee === true;
    updateAuthUI(data);

    // Fire-and-forget anonymous analytics ping. Only sent when the user has
    // granted analytics consent (the server enforces this too); the server
    // sees only the SHA-256 hex of (tid + ':' + oid) plus a single boolean
    // flag, never the access token, UPN, oid, or tenant id.
    try {
      if (hasConsentFor('analytics')) {
        let accountKeyHex = '';
        try {
          if (tenantId && objectId && window.crypto && window.crypto.subtle && typeof TextEncoder !== 'undefined') {
            const enc = new TextEncoder();
            const buf = enc.encode(tenantId + ':' + objectId);
            const digest = await window.crypto.subtle.digest('SHA-256', buf);
            const bytes = new Uint8Array(digest);
            let hex = '';
            for (let i = 0; i < bytes.length; i++) {
              hex += bytes[i].toString(16).padStart(2, '0');
            }
            accountKeyHex = hex;
          }
        } catch {}

        const headers = buildConsentRequestHeaders({});
        if (accountKeyHex) {
          headers['X-ACS-Auth-Account-Key'] = accountKeyHex;
        }
        headers['X-ACS-Auth-Is-Microsoft'] = data.isMicrosoftEmployee ? '1' : '0';

        // No body - the route is header-only so it works under both the
        // HttpListener and TcpListener fallback paths without any body
        // parsing. Errors are swallowed; analytics must never block sign-in.
        fetch('/api/auth/event', {
          method: 'POST',
          headers: headers,
          cache: 'no-store'
        }).catch(() => {});
      }
    } catch {}
  } catch (e) {
    console.error('Auth verify error:', e);
    updateAuthUI(null);
  }
}

function updateAuthUI(authData) {
  lastAuthData = authData || null;
  const signInBtn = document.getElementById('msSignInBtn');
  const signOutBtn = document.getElementById('msSignOutBtn');
  const statusEl = document.getElementById('msAuthStatus');

  if (authData && msAuthAccount) {
    if (signInBtn) hideTopBarItem(signInBtn);
    if (signOutBtn) showTopBarItem(signOutBtn);
    if (statusEl) {
      showTopBarItem(statusEl);
      const name = escapeHtml(authData.displayName || msAuthAccount.name || '');
      if (authData.isMicrosoftEmployee) {
        statusEl.className = 'ms-auth-status ms-employee hide-on-screenshot engage-top-item engage-top-in';
        statusEl.innerHTML = '&#x2705; ' + name + ' (' + escapeHtml(t('authMicrosoftLabel')) + ')';
      } else {
        statusEl.className = 'ms-auth-status ms-external hide-on-screenshot engage-top-item engage-top-in';
        statusEl.innerHTML = '&#x1F464; ' + name;
      }
    }
  } else {
    if (signInBtn) {
      showTopBarItem(signInBtn);
      signInBtn.disabled = false;
      signInBtn.innerHTML = t('signInMicrosoft');
    }
    if (signOutBtn) hideTopBarItem(signOutBtn);
    if (statusEl) hideTopBarItem(statusEl);
    isMsEmployee = false;
  }

  // Intake form is shown to any user signed in with a Microsoft account.
  if (typeof updateIntakeFormVisibility === 'function') {
    updateIntakeFormVisibility(!!(authData && msAuthAccount));
  }
}

</script>

</body>
</html>
'@
