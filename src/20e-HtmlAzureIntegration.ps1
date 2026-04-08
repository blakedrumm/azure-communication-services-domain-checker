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
      // No existing account; ensure buttons are in a clean state
      updateAuthUI(null);
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

  try {
    const btn = document.getElementById('msSignInBtn');
    if (btn) { btn.disabled = true; btn.textContent = t('authSigningIn'); }

    // Use redirect flow for best compatibility with browser / popup blockers.
    // Request Graph scopes for the token, plus pre-consent ARM and Log Analytics
    // via extraScopesToConsent so acquireTokenSilent works later without popups.
    await msalInstance.loginRedirect({
      scopes: GRAPH_SCOPES,
      extraScopesToConsent: [...ARM_SCOPES, ...LOG_ANALYTICS_SCOPES],
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
    azureDiagnosticsState.subscriptions = [];
    azureDiagnosticsState.resources = [];
    azureDiagnosticsState.workspaces = [];
    azureDiagnosticsState.lastResult = null;
    azureDiagnosticsState.lastQueryText = '';
    azureDiagnosticsState.lastQueryName = '';
    setAzureDiagnosticsResultsHtml('');
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

    const data = {
      displayName,
      userPrincipalName,
      tenantId,
      isMicrosoftEmployee: /@(microsoft\.com|microsoftsupport\.com)$/i.test(userPrincipalName)
    };

    isMsEmployee = data.isMicrosoftEmployee === true;
    updateAuthUI(data);
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

  renderAzureDiagnosticsUi();

  if (authData && msAuthAccount) {
    loadAzureSubscriptions();
  }
}

function setAzureDiagnosticsStatus(message, isError = false) {
  const el = document.getElementById('azureDiagnosticsStatus');
  if (!el) return;
  el.textContent = message || '';
  el.className = isError ? 'azure-status error' : 'azure-status';
}

function setAzureDiagnosticsResultsHtml(html) {
  const el = document.getElementById('azureDiagnosticsResults');
  if (!el) return;
  el.innerHTML = html || '';
}

function getSelectedAzureSubscriptionId() {
  const el = document.getElementById('azureSubscriptionSelect');
  return el ? String(el.value || '') : '';
}

function getSelectedAzureResourceId() {
  const el = document.getElementById('azureResourceSelect');
  return el ? String(el.value || '') : '';
}

function getSelectedAzureWorkspaceId() {
  const el = document.getElementById('azureWorkspaceSelect');
  return el ? String(el.value || '') : '';
}

function renderAzureSelectOptions(selectId, items, getValue, getLabel, emptyText) {
  const el = document.getElementById(selectId);
  if (!el) return;
  const currentValue = el.value;
  const options = (items || []).map(item => {
    const value = String(getValue(item) || '');
    const label = String(getLabel(item) || value);
    return `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`;
  });
  if (options.length === 0) {
    el.innerHTML = `<option value="">${escapeHtml(emptyText)}</option>`;
    return;
  }
  el.innerHTML = options.join('');
  if (currentValue && items.some(item => String(getValue(item) || '') === currentValue)) {
    el.value = currentValue;
  }
}

function getAzureAuthDisplayName() {
  return (lastAuthData && (lastAuthData.displayName || lastAuthData.userPrincipalName))
    ? String(lastAuthData.displayName || lastAuthData.userPrincipalName)
    : '';
}

function renderAzureDiagnosticsUi() {
  const card = document.getElementById('azureDiagnosticsCard');
  if (!card) return;

  const signedIn = !!(msAuthAccount && msalInstance);
  card.style.display = (getMsalConfig() && signedIn) ? '' : 'none';

  const switchRow = document.getElementById('azureSwitchDirectoryRow');
  if (switchRow) switchRow.style.display = signedIn ? '' : 'none';

  renderAzureSelectOptions(
    'azureSubscriptionSelect',
    azureDiagnosticsState.subscriptions,
    item => item.subscriptionId,
    item => `${item.displayName || item.subscriptionId}${item.tenantId ? ` (${item.tenantId})` : ''}`,
    t('azureNoSubscriptions')
  );

  renderAzureSelectOptions(
    'azureResourceSelect',
    azureDiagnosticsState.resources,
    item => item.id,
    item => `${item.name} [${item.type}]`,
    t('azureNoResources')
  );

  renderAzureSelectOptions(
    'azureWorkspaceSelect',
    azureDiagnosticsState.workspaces,
    item => item.id,
    item => `${item.name}${item.customerId ? ` (${item.customerId})` : ''}`,
    t('azureNoWorkspaces')
  );

  const hint = document.getElementById('azureDiagnosticsHint');
  if (hint) {
    hint.textContent = signedIn
      ? t('azureSignedInAs', { user: getAzureAuthDisplayName() || t('authMicrosoftLabel') })
      : t('azureDiagnosticsHint');
  }

  ['azureRunInventoryBtn','azureRunDomainSearchBtn','azureRunAcsSearchBtn']
    .forEach(id => {
      const btn = document.getElementById(id);
      if (btn) btn.disabled = !signedIn || azureDiagnosticsState.isBusy;
    });

  if (!signedIn) {
    setAzureDiagnosticsStatus(t('azureSignInRequired'), false);
  }
}

function escapeKqlString(text) {
  return String(text || '')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/'/g, "\\'")
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

function getMsAuthLoginHint() {
  if (msAuthAccount) {
    return msAuthAccount.username || (msAuthAccount.idTokenClaims && msAuthAccount.idTokenClaims.preferred_username) || '';
  }
  if (lastAuthData && lastAuthData.userPrincipalName) {
    return lastAuthData.userPrincipalName;
  }
  return '';
}

async function acquireAzureAccessToken(scopes, tenantId, silentOnly) {
  const scopeLabel = (scopes || []).map(s => String(s).split('/').pop()).join(',');
  const tenantLabel = tenantId ? tenantId.substring(0, 8) + '...' : 'default';
  console.log(`[AzureDiag] acquireToken: scope=${scopeLabel}, tenant=${tenantLabel}, silentOnly=${!!silentOnly}`);

  if (!msalInstance || !msAuthAccount) {
    console.warn('[AzureDiag] acquireToken: FAILED \u2014 msalInstance or msAuthAccount is null');
    throw new Error(t('azureSignInRequired'));
  }

  const loginHint = getMsAuthLoginHint();
  const homeTenantId = msAuthAccount.tenantId || '';
  const isCrossTenant = tenantId && tenantId !== homeTenantId;

  const request = {
    scopes,
    account: msAuthAccount
  };
  if (tenantId) {
    request.authority = `https://login.microsoftonline.com/${tenantId}`;
  }
  // For cross-tenant requests, always force a fresh token from the target
  // tenant's authority.  MSAL v2 cache keys do not always differentiate by
  // tenant for the same resource, so without forceRefresh the cached home-
  // tenant token is returned and ARM sees subscriptions as "Disabled".
  if (isCrossTenant) {
    request.forceRefresh = true;
    console.log(`[AzureDiag] acquireToken: cross-tenant detected (home=${homeTenantId.substring(0, 8)}...), forcing refresh`);
  }

  try {
    const silent = await msalInstance.acquireTokenSilent(request);
    const tokenTenant = silent.tenantId || silent.account?.tenantId || 'n/a';
    const tokenTenantLabel = tokenTenant !== 'n/a' ? tokenTenant.substring(0, 8) + '...' : 'n/a';
    console.log(`[AzureDiag] acquireToken: silent OK for tenant=${tenantLabel}, tokenTenant=${tokenTenantLabel}, tokenLength=${silent.accessToken ? silent.accessToken.length : 0}, fromCache=${!!silent.fromCache}`);
    return silent.accessToken;
  } catch (e) {
    const errorCode = String(e?.errorCode || e?.name || 'unknown');
    console.warn(`[AzureDiag] acquireToken: silent FAILED for tenant=${tenantLabel}, errorCode=${errorCode}`);
    const requiresInteraction = e instanceof msal.InteractionRequiredAuthError ||
      ['interaction_required', 'consent_required', 'login_required'].includes(String(e?.errorCode || '').toLowerCase());
    if (!requiresInteraction) throw e;

    // Try once more with forceRefresh before falling back to redirect
    try {
      console.log(`[AzureDiag] acquireToken: retrying with forceRefresh for tenant=${tenantLabel}`);
      const retry = await msalInstance.acquireTokenSilent({ ...request, forceRefresh: true });
      console.log(`[AzureDiag] acquireToken: forceRefresh OK for tenant=${tenantLabel}`);
      return retry.accessToken;
    } catch (_retryErr) {
      const retryCode = String(_retryErr?.errorCode || _retryErr?.name || 'unknown');
      console.warn(`[AzureDiag] acquireToken: forceRefresh FAILED for tenant=${tenantLabel}, errorCode=${retryCode}`);
      // In silentOnly mode, do not redirect; just throw so callers can skip this tenant.
      if (silentOnly) throw _retryErr;

      // Silent retry also failed; use redirect to get consent.
      // This avoids opening a popup that shows a mini copy of the website.
      console.log('[AzureDiag] acquireToken: falling back to redirect for consent');
      setAzureDiagnosticsStatus(t('azureConsentRequired'));
      const redirectRequest = {
        scopes,
        account: msAuthAccount
      };
      if (tenantId) {
        redirectRequest.authority = `https://login.microsoftonline.com/${tenantId}`;
      }
      if (loginHint) {
        redirectRequest.loginHint = loginHint;
      }
      await msalInstance.acquireTokenRedirect(redirectRequest);
      // Page will redirect; code below this line will not execute.
      // After redirect, handleRedirectPromise in initMsAuth will resume the session.
      return '';
    }
  }
}

async function armFetchJson(url, options = {}, tenantId) {
  const token = await acquireAzureAccessToken(ARM_SCOPES, tenantId);
  const response = await fetch(url, {
    ...options,
    headers: {
      ...(options.headers || {}),
      Authorization: 'Bearer ' + token,
      Accept: 'application/json'
    }
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`ARM ${response.status}: ${text || response.statusText}`);
  }
  return response.json();
}

async function armFetchJsonSilent(url, options = {}, tenantId) {
  const urlPath = url.replace('https://management.azure.com', '');
  console.log(`[AzureDiag] armFetchSilent: ${urlPath.substring(0, 120)}${urlPath.length > 120 ? '...' : ''}`);
  const token = await acquireAzureAccessToken(ARM_SCOPES, tenantId, true);
  const response = await fetch(url, {
    ...options,
    headers: {
      ...(options.headers || {}),
      Authorization: 'Bearer ' + token,
      Accept: 'application/json'
    }
  });
  console.log(`[AzureDiag] armFetchSilent: HTTP ${response.status} for ${urlPath.substring(0, 80)}`);
  if (!response.ok) {
    const text = await response.text();
    console.warn(`[AzureDiag] armFetchSilent: FAILED HTTP ${response.status} \u2014 ${(text || '').substring(0, 200)}`);
    throw new Error(`ARM ${response.status}: ${text || response.statusText}`);
  }
  return response.json();
}

async function armFetchAll(url, tenantId) {
  const items = [];
  let next = url;
  const maxPages = 50;
  let page = 0;
  while (next && page < maxPages) {
    page++;
    const data = await armFetchJson(next, {}, tenantId);
    if (Array.isArray(data.value)) items.push(...data.value);
    // ARM uses '@odata.nextLink' (or sometimes 'nextLink') for pagination
    next = data['@odata.nextLink'] || data.nextLink || null;
  }
  return items;
}

async function armFetchAllSilent(url, tenantId) {
  const items = [];
  let next = url;
  const maxPages = 50;
  let page = 0;
  while (next && page < maxPages) {
    page++;
    const data = await armFetchJsonSilent(next, {}, tenantId);
    const pageCount = Array.isArray(data.value) ? data.value.length : 0;
    if (Array.isArray(data.value)) items.push(...data.value);
    const hasNext = !!(data['@odata.nextLink'] || data.nextLink);
    console.log(`[AzureDiag] armFetchAllSilent: page=${page}, itemsOnPage=${pageCount}, totalSoFar=${items.length}, hasNextPage=${hasNext}`);
    next = data['@odata.nextLink'] || data.nextLink || null;
  }
  console.log(`[AzureDiag] armFetchAllSilent: DONE pages=${page}, totalItems=${items.length}`);
  return items;
}

async function switchAzureDirectory() {
  const input = document.getElementById('azureTenantInput');
  const tenantValue = (input ? input.value : '').trim();
  if (!tenantValue) {
    setAzureDiagnosticsStatus('Enter a tenant ID or domain name (e.g. contoso.onmicrosoft.com).', true);
    return;
  }
  if (!msalInstance) {
    setAzureDiagnosticsStatus(t('azureSignInRequired'), true);
    return;
  }
  console.log(`[AzureDiag] switchAzureDirectory: re-authenticating against tenant "${tenantValue}"`);
  try {
    await msalInstance.loginRedirect({
      scopes: GRAPH_SCOPES,
      extraScopesToConsent: [...ARM_SCOPES, ...LOG_ANALYTICS_SCOPES],
      authority: `https://login.microsoftonline.com/${encodeURIComponent(tenantValue)}`,
      prompt: 'login'
    });
  } catch (e) {
    console.error('[AzureDiag] switchAzureDirectory failed:', e);
    setAzureDiagnosticsStatus(t('authSignInFailed', { reason: e?.message || t('authUnknownError') }), true);
  }
}

async function loadAzureSubscriptions() {
  console.log('[AzureDiag] ===== loadAzureSubscriptions START =====');
  console.log('[AzureDiag] msalInstance exists:', !!msalInstance);
  console.log('[AzureDiag] msAuthAccount exists:', !!msAuthAccount);
  if (msAuthAccount) {
    console.log('[AzureDiag] account homeAccountId length:', (msAuthAccount.homeAccountId || '').length);
    console.log('[AzureDiag] account environment:', msAuthAccount.environment || 'n/a');
    console.log('[AzureDiag] account tenantId:', msAuthAccount.tenantId ? msAuthAccount.tenantId.substring(0, 8) + '...' : 'n/a');
  }
  try {
    azureDiagnosticsState.isBusy = true;
    renderAzureDiagnosticsUi();
    setAzureDiagnosticsStatus(t('azureLoadingSubscriptions'));

    // Step 1: Enumerate all tenants the user has access to.
    // The home-tenant token can list tenants even if it cannot get tokens for them.
    console.log('[AzureDiag] Step 1: Enumerating tenants via GET /tenants...');
    let tenants = [];
    try {
      tenants = await armFetchAll('https://management.azure.com/tenants?api-version=2020-01-01');
      console.log(`[AzureDiag] Step 1 result: ${tenants.length} tenant(s) returned`);
    } catch (tenantErr) {
      const errCode = String(tenantErr?.errorCode || tenantErr?.name || tenantErr?.message || 'unknown').substring(0, 100);
      console.warn(`[AzureDiag] Step 1 FAILED: ${errCode} \u2014 falling back to default tenant`);
      tenants = [];
    }
    const tenantIds = tenants.length > 0
      ? tenants.map(tn => String(tn.tenantId || '')).filter(Boolean)
      : [null]; // null = use default (home) tenant
    console.log(`[AzureDiag] Step 1 final: ${tenantIds.length} tenant ID(s) to query: [${tenantIds.map(t => t ? t.substring(0, 8) + '...' : 'default').join(', ')}]`);

    // Step 2: For each tenant, silently acquire an ARM token and list subscriptions.
    // Cross-tenant token acquisition will fail for tenants where the app has no
    // consent (AADSTS65001) or where conditional access blocks it (AADSTS53003).
    // Those failures are expected and silently skipped.
    console.log('[AzureDiag] Step 2: Loading subscriptions per tenant...');
    const allSubscriptions = [];
    const seenSubscriptionIds = new Set();
    for (let i = 0; i < tenantIds.length; i++) {
      const tid = tenantIds[i];
      const tenantLabel = tid ? tid.substring(0, 8) + '...' : 'default';
      console.log(`[AzureDiag] Step 2.${i + 1}: Loading subscriptions for tenant=${tenantLabel}`);
      setAzureDiagnosticsStatus(t('azureLoadingTenantSubscriptions', {
        tenant: tenantLabel.length > 12 ? tenantLabel.substring(0, 12) + '...' : tenantLabel,
        current: String(i + 1),
        total: String(tenantIds.length)
      }));
      try {
        const subs = await armFetchAllSilent('https://management.azure.com/subscriptions?api-version=2020-01-01', tid);
        console.log(`[AzureDiag] Step 2.${i + 1}: ARM returned ${(subs || []).length} raw subscription(s) for tenant=${tenantLabel}`);
        let added = 0;
        let skippedDupe = 0;
        for (const item of (subs || [])) {
          if (seenSubscriptionIds.has(item.subscriptionId)) { skippedDupe++; continue; }
          seenSubscriptionIds.add(item.subscriptionId);
          allSubscriptions.push({
            subscriptionId: item.subscriptionId,
            displayName: item.displayName || item.subscriptionId,
            tenantId: item.tenantId || tid || ''
          });
          added++;
        }
        console.log(`[AzureDiag] Step 2.${i + 1}: added=${added}, skippedDupe=${skippedDupe}`);
      } catch (subErr) {
        const errCode = String(subErr?.errorCode || subErr?.name || 'unknown');
        const errMsg = String(subErr?.message || '').substring(0, 150);
        console.warn(`[AzureDiag] Step 2.${i + 1}: FAILED for tenant=${tenantLabel}, errorCode=${errCode}, message=${errMsg}`);
      }
    }
    console.log(`[AzureDiag] Step 2 complete: ${allSubscriptions.length} total subscription(s) across all tenants`);

    azureDiagnosticsState.subscriptions = allSubscriptions;
    azureDiagnosticsState.resources = [];
    azureDiagnosticsState.workspaces = [];
    renderAzureDiagnosticsUi();
    setAzureDiagnosticsStatus(
      allSubscriptions.length > 0
        ? `${allSubscriptions.length} ${t('azureSubscription').toLowerCase()}(s) loaded.`
        : t('azureNoSubscriptions')
    );

    if (allSubscriptions.length > 0) {
      const subSelect = document.getElementById('azureSubscriptionSelect');
      if (subSelect && subSelect.options.length > 0) subSelect.selectedIndex = 0;
      // Release busy before chaining so that discoverAzureResources can set it again cleanly
      azureDiagnosticsState.isBusy = false;
      renderAzureDiagnosticsUi();
      try {
        await discoverAzureResources();
      } catch (chainErr) {
        console.error('Azure resource discovery chain failed:', chainErr);
        setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: chainErr?.message || t('authUnknownError') }), true);
      }
      return;
    }
    console.log('[AzureDiag] ===== loadAzureSubscriptions END (no subscriptions) =====');
  } catch (e) {
    const errCode = String(e?.errorCode || e?.name || 'unknown');
    const errMsg = String(e?.message || '').substring(0, 200);
    console.error(`[AzureDiag] loadAzureSubscriptions OUTER ERROR: errorCode=${errCode}, message=${errMsg}`);
    setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: e?.message || t('authUnknownError') }), true);
  } finally {
    azureDiagnosticsState.isBusy = false;
    renderAzureDiagnosticsUi();
  }
}

function getSelectedSubscriptionTenantId() {
  const subId = getSelectedAzureSubscriptionId();
  if (!subId) return null;
  const sub = azureDiagnosticsState.subscriptions.find(s => s.subscriptionId === subId);
  return (sub && sub.tenantId) ? sub.tenantId : null;
}

async function discoverAzureResources() {
  const subscriptionId = getSelectedAzureSubscriptionId();
  if (!subscriptionId) {
    setAzureDiagnosticsStatus(t('azureSelectSubscriptionFirst'), true);
    return;
  }
  const tenantId = getSelectedSubscriptionTenantId();

  try {
    azureDiagnosticsState.isBusy = true;
    renderAzureDiagnosticsUi();
    setAzureDiagnosticsStatus(t('azureLoadingResources'));

    const resources = await armFetchAll(`https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resources?api-version=2021-04-01`, tenantId);
    azureDiagnosticsState.resources = (resources || [])
      .filter(item => /^microsoft\.communication\//i.test(String(item.type || '')))
      .sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));

    azureDiagnosticsState.workspaces = [];
    renderAzureDiagnosticsUi();
    setAzureDiagnosticsStatus(
      azureDiagnosticsState.resources.length > 0
        ? `${azureDiagnosticsState.resources.length} ACS resource(s) discovered.`
        : t('azureNoResources')
    );

    if (azureDiagnosticsState.resources.length > 0) {
      const resSelect = document.getElementById('azureResourceSelect');
      if (resSelect && resSelect.options.length > 0) resSelect.selectedIndex = 0;
      // Release busy before chaining so that discoverAzureWorkspaces can set it again cleanly
      azureDiagnosticsState.isBusy = false;
      renderAzureDiagnosticsUi();
      try {
        await discoverAzureWorkspaces();
      } catch (chainErr) {
        console.error('Azure workspace discovery chain failed:', chainErr);
        setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: chainErr?.message || t('authUnknownError') }), true);
      }
      return;
    }
  } catch (e) {
    console.error('Azure resource discovery failed:', e);
    setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: e?.message || t('authUnknownError') }), true);
  } finally {
    azureDiagnosticsState.isBusy = false;
    renderAzureDiagnosticsUi();
  }
}

async function getWorkspaceMetadata(workspaceResourceId) {
  // Ensure the resource ID starts with '/' for a valid ARM URL
  const normalizedId = workspaceResourceId.startsWith('/') ? workspaceResourceId : '/' + workspaceResourceId;
  const tenantId = getSelectedSubscriptionTenantId();
  const data = await armFetchJson(`https://management.azure.com${normalizedId}?api-version=2022-10-01`, {}, tenantId);
  return {
    id: data.id,
    name: data.name,
    location: data.location,
    customerId: data.properties && data.properties.customerId ? data.properties.customerId : '',
    resourceGroup: data.id ? (data.id.split('/')[4] || '') : ''
  };
}

async function discoverAzureWorkspaces() {
  const subscriptionId = getSelectedAzureSubscriptionId();
  if (!subscriptionId) {
    setAzureDiagnosticsStatus(t('azureSelectSubscriptionFirst'), true);
    return;
  }
  const tenantId = getSelectedSubscriptionTenantId();

  const selectedResourceId = getSelectedAzureResourceId();
  const resourcesToCheck = selectedResourceId
    ? azureDiagnosticsState.resources.filter(item => item.id === selectedResourceId)
    : azureDiagnosticsState.resources;

  try {
    azureDiagnosticsState.isBusy = true;
    renderAzureDiagnosticsUi();
    setAzureDiagnosticsStatus(t('azureLoadingWorkspaces'));

    const workspaceMap = new Map();

    for (const resource of resourcesToCheck) {
      try {
        const diagnostics = await armFetchJson(`https://management.azure.com${resource.id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview`, {}, tenantId);
        for (const setting of (diagnostics.value || [])) {
          // The workspaceId lives under setting.properties, not at the top level
          const wsId = (setting.properties && setting.properties.workspaceId) || setting.workspaceId || '';
          if (wsId) {
            workspaceMap.set(wsId.toLowerCase(), wsId);
          }
        }
      } catch (diagErr) {
        console.warn('Diagnostic settings read failed for', resource.id, diagErr);
      }
    }

    if (workspaceMap.size === 0) {
      const resources = await armFetchAll(`https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resources?api-version=2021-04-01`, tenantId);
      for (const resource of resources) {
        if (String(resource.type || '').toLowerCase() === 'microsoft.operationalinsights/workspaces') {
          workspaceMap.set(String(resource.id).toLowerCase(), resource.id);
        }
      }
    }

    const workspaces = [];
    for (const workspaceId of workspaceMap.values()) {
      try {
        workspaces.push(await getWorkspaceMetadata(workspaceId));
      } catch (e) {
        console.warn('Workspace metadata load failed for', workspaceId, e);
      }
    }

    azureDiagnosticsState.workspaces = workspaces.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
    renderAzureDiagnosticsUi();

    if (azureDiagnosticsState.workspaces.length > 0) {
      const wsSelect = document.getElementById('azureWorkspaceSelect');
      if (wsSelect && wsSelect.options.length > 0) wsSelect.selectedIndex = 0;
    }

    setAzureDiagnosticsStatus(
      azureDiagnosticsState.workspaces.length > 0
        ? t('azureDiscoverSuccess')
        : t('azureNoWorkspaces')
    );
  } catch (e) {
    console.error('Azure workspace discovery failed:', e);
    setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: e?.message || t('authUnknownError') }), true);
  } finally {
    azureDiagnosticsState.isBusy = false;
    renderAzureDiagnosticsUi();
  }
}

function buildAzureQueryTemplate(templateName) {
  const domain = String((document.getElementById('domainInput')?.value || '').trim());
  switch (templateName) {
    case 'workspaceInventory':
      return {
        name: t('azureWorkspaceInventory'),
        query: 'union withsource=SourceTable * | summarize Rows=count() by SourceTable | top 25 by Rows desc'
      };
    case 'domainSearch':
      if (!domain) throw new Error(t('azureDomainRequired'));
      return {
        name: t('azureDomainSearch'),
        query: `search in (*) "${escapeKqlString(domain)}" | take 100`
      };
    case 'acsSearch':
      return {
        name: t('azureAcsSearch'),
        query: 'search in (*) "Microsoft.Communication" | take 100'
      };
    default:
      throw new Error('Unknown Azure query template: ' + templateName);
  }
}

function renderLogAnalyticsResult(result) {
  if (!result || !Array.isArray(result.tables) || result.tables.length === 0) {
    return `<div>${escapeHtml(t('azureQueryReturnedNoTables'))}</div>`;
  }

  const workspace = azureDiagnosticsState.workspaces.find(item => item.id === getSelectedAzureWorkspaceId());
  const subscription = azureDiagnosticsState.subscriptions.find(item => item.subscriptionId === getSelectedAzureSubscriptionId());
  const meta = `<div class="azure-result-meta">${escapeHtml(t('azureResultsSummary', {
    tenant: lastAuthData?.tenantId || 'n/a',
    subscription: subscription?.displayName || subscription?.subscriptionId || 'n/a',
    workspace: workspace?.name || workspace?.customerId || 'n/a'
  }))}</div>`;
  const queryText = azureDiagnosticsState.lastQueryText
    ? `<div class="azure-result-meta"><strong>${escapeHtml(t('azureQueryTextLabel'))}:</strong> <code class="guidance-code">${escapeHtml(azureDiagnosticsState.lastQueryText)}</code></div>`
    : '';

  const tablesHtml = result.tables.map(table => {
    const columns = Array.isArray(table.columns) ? table.columns : [];
    const rows = Array.isArray(table.rows) ? table.rows.slice(0, 100) : [];
    const totalRows = Array.isArray(table.rows) ? table.rows.length : 0;
    const truncatedNote = totalRows > 100 ? ` (showing 100 of ${totalRows})` : '';
    return `
      <div>
        <div class="azure-result-meta"><strong>${escapeHtml(table.name || 'Table')}</strong> \u2014 ${rows.length} row(s)${truncatedNote}</div>
        <div class="azure-result-table-wrap">
          <table class="azure-result-table">
            <thead><tr>${columns.map(col => `<th>${escapeHtml(col.name || '')}</th>`).join('')}</tr></thead>
            <tbody>
              ${rows.map(row => `<tr>${columns.map((col, index) => {
                const val = row[index] === null || row[index] === undefined ? '' : String(row[index]);
                return `<td title="${escapeHtml(val)}">${escapeHtml(val)}</td>`;
              }).join('')}</tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>`;
  }).join('');

  return meta + queryText + tablesHtml;
}

async function runAzureQueryTemplate(templateName) {
  const workspaceId = getSelectedAzureWorkspaceId();
  if (!workspaceId) {
    setAzureDiagnosticsStatus(t('azureSelectWorkspaceFirst'), true);
    return;
  }

  const workspace = azureDiagnosticsState.workspaces.find(item => item.id === workspaceId);
  if (!workspace || !workspace.customerId) {
    setAzureDiagnosticsStatus(t('azureSelectWorkspaceFirst'), true);
    return;
  }

  try {
    azureDiagnosticsState.isBusy = true;
    renderAzureDiagnosticsUi();

    const template = buildAzureQueryTemplate(templateName);
    azureDiagnosticsState.lastQueryText = template.query;
    azureDiagnosticsState.lastQueryName = template.name;
    setAzureDiagnosticsStatus(t('azureRunningQuery', { name: template.name }));

    const token = await acquireAzureAccessToken(LOG_ANALYTICS_SCOPES);
    const response = await fetch(`https://api.loganalytics.io/v1/workspaces/${encodeURIComponent(workspace.customerId)}/query`, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        query: template.query,
        timespan: 'P1D'
      })
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`${response.status}: ${text || response.statusText}`);
    }

    const result = await response.json();
    azureDiagnosticsState.lastResult = result;
    setAzureDiagnosticsResultsHtml(renderLogAnalyticsResult(result));
    setAzureDiagnosticsStatus(`${template.name} completed.`);
  } catch (e) {
    console.error('Azure Log Analytics query failed:', e);
    setAzureDiagnosticsStatus(t('azureQueryFailed', { reason: e?.message || t('authUnknownError') }), true);
  } finally {
    azureDiagnosticsState.isBusy = false;
    renderAzureDiagnosticsUi();
  }
}
</script>

</body>
</html>
'@
