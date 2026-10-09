const $ = (id) => document.getElementById(id);
let toastTimer = null;
let startupHealthTimer = null;
let popupGeneration = 0;
let popupState = { session: null, profile: null, sites: [], device: null, proxy: null, health: null };

function busy(button, on, label) {
  if (!button) return;
  if (on) {
    button.disabled = true;
    button.dataset.oldLabel = button.textContent;
    button.innerHTML = `<span class="spinner"></span>${escapeHtml(label)}`;
  } else {
    button.disabled = false;
    button.textContent = button.dataset.oldLabel || label;
    delete button.dataset.oldLabel;
  }
}

function show(id) {
  for (const name of ['startup', 'connectivity', 'login', 'suspended', 'deviceBlocked', 'locked', 'app']) {
    $(name).classList.toggle('hidden', name !== id);
  }
}
function isConnectivityError(message){
  const m=String(message||'').toLowerCase();
  return navigator.onLine===false || m.includes('could not reach supabase') || m.includes('supabase request timed out') || m.includes('could not reach firebase') || m.includes('firebase request timed out') || m.includes('network error') || m.includes('failed to fetch') || m.includes('check your internet connection') || m.includes('internet connection') || m.includes('proxy health request') || m.includes('proxy connection') || m.includes('proxy could not be restored') || m.includes('proxy is not working') || m.includes('could not connect');
}
function showConnectivity(){
  const e=$('connectivityText');
  if(e)e.textContent='Internet or proxy may not be working. Please check your connection or proxy and try again.';
  show('connectivity');
}


function showError(message) {
  const box = $('loginError');
  box.textContent = String(message || 'Something went wrong.');
  box.classList.remove('hidden');
}

function clearError() {
  $('loginError').classList.add('hidden');
  $('loginError').textContent = '';
}

function showStartup(text = 'Restoring secure session…') {
  $('startupText').textContent = text;
  show('startup');
}

function showLocked(reason = 'Profile locked.') {
  $('lockedText').textContent = reason;
  show('locked');
}

function showSuspended() {
  show('suspended');
}

function showDeviceBlocked(reason = 'This account is already registered on another Chrome device.') {
  const box = $('deviceBlockedReason');
  if (box) box.textContent = reason;
  show('deviceBlocked');
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'
  }[c]));
}

function send(type, payload = {}, timeoutMs = 12000) {
  return new Promise((resolve) => {
    let finished = false;
    const finish = (value) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve(value || { ok:false, error: chrome.runtime.lastError?.message || 'No response from extension.' });
    };
    const timer = setTimeout(() => finish({
      ok:false,
      error:'The background service did not respond. The interface is still available; please retry.'
    }), timeoutMs);
    try {
      chrome.runtime.sendMessage({ type, ...payload }, (response) => {
        if (chrome.runtime.lastError) finish({ ok:false, error:chrome.runtime.lastError.message });
        else finish(response);
      });
    } catch (error) {
      finish({ ok:false, error:error?.message || String(error) });
    }
  });
}

async function restoreAuth() {
  const session=await CS.Auth.session(false);
  if(!session)return null;
  try{
    return await CS.Auth.currentProfile(true);
  }catch(error){
    if(error?.code==='ACCOUNT_SUSPENDED'){
      return{suspended:true,profile:error.profile||null,session};
    }
    const cached=await CS.Auth.cached();
    if(cached)return{session,profile:cached,stale:true};
    throw error;
  }
}

async function loadAssignedState(authState) {
  const { session, profile } = authState;
  if (!profile || profile.role !== 'client') throw new Error('This account is not a client account.');
  if (profile.active === false) return { suspended:true };

  const subId = String(profile.subadminUid || '').trim();
  if (!subId) throw new Error('This client account has no assigned Admin Extension.');

  const [statusDoc, accessDoc, proxyDoc, legacyProxyDoc, clientDevice] = await Promise.all([
    CS.Firebase.getDoc(['users', subId, 'control', 'status'], session.idToken),
    CS.Firebase.getDoc(['clientAccess', session.uid], session.idToken).catch(() => ({exists:false, data:null})),
    CS.Firebase.getDoc(['users', subId, 'proxy', 'config'], session.idToken).catch(() => ({ exists:false, data:null })),
    CS.Firebase.getDoc(['subadminProxyConfigs', subId], session.idToken).catch(() => ({ exists:false, data:null })),
    CS.Firebase.getDoc(['devices', session.uid], session.idToken).catch(() => ({ exists:false, data:null }))
  ]);

  if (statusDoc.exists && statusDoc.data?.active === false) return { suspended:true };

  let sites = [];

  // Hidden Main Admin-created clients inherit the Admin Extension's current
  // active website set. Resolve it live so adding/removing a managed website
  // is reflected immediately after login or Fresh Sync, without a stale
  // copied siteIds/clientAccess list.
  if (profile.visibleToSubadmin === false) {
    const docs = await CS.Firebase.queryDocsByField(
      ['sites'],
      'subadminUid',
      'EQUAL',
      subId,
      session.idToken
    );
    sites = docs
      .filter((d) => d.data?.active !== false && d.data?.enabled !== false)
      .map((d) => ({id:d.id, ...d.data}))
      .sort((a,b) => String(a.name || a.hostname).localeCompare(String(b.name || b.hostname)));
  } else {
    let siteIds = Array.isArray(accessDoc.data?.siteIds) ? accessDoc.data.siteIds.map(String) : [];
    if (!siteIds.length && Array.isArray(profile.siteIds)) siteIds = profile.siteIds.map(String);
    if (!siteIds.length && profile.siteId) siteIds = [String(profile.siteId)];

    sites = (await Promise.all(siteIds.map(async (siteId) => {
      const site = await CS.Firebase.getDoc(['sites', siteId], session.idToken).catch(() => ({exists:false}));
      if (!site.exists || site.data?.active === false || site.data?.enabled === false) return null;
      if (String(site.data?.subadminUid || '') !== subId) return null;
      return {id:siteId, ...site.data};
    }))).filter(Boolean);
  }

  return {
    ok:true,
    loggedIn:true,
    session,
    profile,
    sites,
    proxy:(proxyDoc.exists && proxyDoc.data?.host && proxyDoc.data?.port ? proxyDoc.data : (legacyProxyDoc.exists && legacyProxyDoc.data?.host && legacyProxyDoc.data?.port ? legacyProxyDoc.data : { mode:'unconfigured', healthy:false, ip:'', lastError:'Proxy is not configured.' })),
    device:clientDevice.exists ? clientDevice.data : null,
    localOnly:true
  };
}

async function verifyCurrentProxy(authState, state) {
  const proxy = CS.Proxy.normalize(state.proxy || {mode:'unconfigured'});
  if (proxy.mode === 'unconfigured') {
    return { ok:false, ip:null, reason:'Proxy is not configured.' };
  }

  await CS.Proxy.setActiveCredentials(proxy);
  await CS.Proxy.apply(proxy);
  await CS.Rules.applyNavigationPolicy(state.sites || [], { locked:false, testEnabled:true });

  try {
    const fresh = { ...proxy, expectedIp: String(proxy.expectedIp || '').trim() };
    const result = await CS.Proxy.test(fresh);
    return result;
  } finally {
    // Keep the normal navigation policy active after the one-time test.
    await CS.Rules.applyNavigationPolicy(state.sites || [], { locked:false, testEnabled:false }).catch(() => {});
  }
}

async function updateDeviceIp(authState, state, health) {
  if (!state?.device || !health?.ok) return;
  // Public IP / proxy-health telemetry is local runtime state; do not write it
  // to Firebase merely because the popup performed a health check.
  popupState.device = {
    ...state.device,
    lastIp:health.ip || state.device.lastIp || '',
    proxyHealthy:true,
    status:'active',
    lastProxyCheckAt:CS.Util.now()
  };
}

function render(state) {
  const previousState=state?.profile?.uid && state.profile.uid===popupState?.profile?.uid ? popupState : {};
  popupState = state || {};
  if (state?.deviceBlocked) return showDeviceBlocked(state.error);
  if (state?.suspended || state?.suspendedReason) return showSuspended();
  if (!state?.locked && state?.deviceResetRequired) {
    $('username').textContent = state.profile?.displayName || state.profile?.email || 'User';
    $('accountEmail').textContent = state.profile?.email || '';
    $('website').textContent = 'Device reset pending';
    $('ip').textContent = '—';
    $('proxy').textContent = '—';
    $('lastSync').textContent = 'Not synced';
    $('proxyBadge').className = 'badge warn';
    $('proxyBadge').innerHTML = '<span class="dot"></span>Re-authorizing';
    $('proxyInfo').className = 'alert info';
    $('proxyInfo').textContent = 'This device was reset. Re-open the extension to authorize it again.';
    $('syncInfo').textContent = '';
    $('sitesList').innerHTML = '';
    show('app');
    return;
  }
  if (state?.locked && (state?.waitingForSite || state?.waitingForDevice)) {
    $('username').textContent = state.profile?.displayName || state.profile?.email || 'User';
    $('accountEmail').textContent = state.profile?.email || '';
    $('website').textContent = state.waitingForDevice ? 'Device reset pending' : 'Waiting for assignment';
    $('ip').textContent = '—';
    $('proxy').textContent = '—';
    $('lastSync').textContent = 'Not synced';
    $('proxyBadge').className = 'badge warn';
    $('proxyBadge').innerHTML = '<span class="dot"></span>Waiting';
    $('proxyInfo').className = 'alert info';
    $('proxyInfo').textContent = state.waitingForDevice
      ? 'This device was reset. Waiting for the new device registration to become active.'
      : 'Your Admin Extension has not assigned a managed website yet.';
    $('sitesList').innerHTML = '';
    show('app');
    return;
  }
  if (state?.locked || state?.lockReason) return showLocked(state.error || state.lockReason);
  if (!state?.profile) return show('login');

  $('username').textContent = state.profile.displayName || state.profile.email || 'User';
  $('accountEmail').textContent = state.profile.email || '';
  $('website').textContent = state.sites?.length === 1
    ? (state.sites[0].name || state.sites[0].hostname)
    : `${state.sites?.length || 0} managed websites`;
  const proxyState=state.proxy || previousState.proxy || {};
  const healthState=state.health || state.proxyHealth || previousState.health || previousState.proxyHealth || {};
  const deviceState=state.device || previousState.device || {};
  const lastState=state.lastState || previousState.lastState || {};

  $('ip').textContent = healthState?.ip || deviceState?.lastIp || lastState?.ip || (state.proxyChecking?'Checking…':'—');
  $('proxy').textContent = proxyState?.mode === 'fixed_servers'
    ? `${proxyState.scheme || 'http'}://${proxyState.host}:${proxyState.port}`
    : 'Not configured';
  $('lastSync').textContent = deviceState?.lastSyncAt
    ? new Date(deviceState.lastSyncAt).toLocaleString()
    : (lastState?.lastSyncAt ? new Date(lastState.lastSyncAt).toLocaleString() : 'Not synced');
  // A newer locally verified login sync wins over stale backend telemetry.
  const displayedUid=String(state?.profile?.uid||state?.session?.uid||'');
  CS.Store?.get?.(['clientVerifiedSyncAt','clientVerifiedSyncUid'])?.then(r=>{
    if(!displayedUid || String(r.clientVerifiedSyncUid||'')!==displayedUid)return;
    if(String(popupState?.profile?.uid||popupState?.session?.uid||'')!==displayedUid)return;
    const verified=Date.parse(r.clientVerifiedSyncAt||'');
    const remote=Date.parse(deviceState?.lastSyncAt||lastState?.lastSyncAt||'');
    if(Number.isFinite(verified) && (!Number.isFinite(remote)||verified>remote))
      $('lastSync').textContent=new Date(verified).toLocaleString();
  }).catch(()=>{});

  const h = healthState;
  const configured = proxyState?.mode === 'fixed_servers';
  const checking = configured && (state.proxyChecking === true || h.pending === true);
  // Preserve the last-known-good/optimistic connected state while verification
  // is in progress. Only an explicit confirmed failure should turn it red.
  const confirmedFailure = configured && h.pending !== true && h.ok === false && state.proxyFailed === true;
  const working = configured && !confirmedFailure && (h.ok === true || deviceState?.proxyHealthy === true);
  $('proxyBadge').className = `badge ${working ? 'good' : checking ? 'warn' : 'bad'}`;
  $('proxyBadge').innerHTML = `<span class="dot"></span>${working ? 'Connected' : checking ? 'Checking' : 'Not Working'}`;
  $('proxyInfo').className = `alert ${working || checking ? 'info' : 'bad'}`;
  $('proxyInfo').textContent = working || checking
    ? (checking ? 'Verifying the proxy in the background…' : 'Proxy is active for this device.')
    : (h.reason || state.proxy?.lastError || state.error || 'Proxy is not configured or not working.');
  // syncInfo remains as a hidden compatibility hook; keep the dashboard visually quiet.
  $('syncInfo').textContent = '';
  $('sitesList').innerHTML = (state.sites || []).map((site) =>
    `<div class="site-pill"><span>${escapeHtml(site.name || site.hostname)}</span><span>${escapeHtml(site.hostname || '')}</span></div>`
  ).join('') || '<div class="small">No managed websites are currently assigned.</div>';
  show('app');
}

async function performBackgroundSync(forceProxyTest = false, freshSync = false) {
  const r = await send(freshSync ? 'fresh-sync' : 'refresh', {}, 18000);
  if (!r.ok && !r.loggedIn && !r.suspended) { if(isConnectivityError(r?.error))showConnectivity(); return r; }
  render(r);
  return r;
}

function watchProxyRecovery(baseState){
  const generation=popupGeneration;
  let polling=false;
  clearInterval(startupHealthTimer);
  startupHealthTimer=setInterval(async()=>{
    if(polling || generation!==popupGeneration)return;
    polling=true;
    try{
      const r=await send('proxy-wait-status',{},4000);
      if(generation!==popupGeneration)return;
      if(r?.status==='recovering'){
        render({...baseState,health:r.health||{ok:false,pending:true,reason:'Verifying the proxy in the background…'},proxyChecking:true,proxyFailed:false});
        return;
      }
      if(r?.status==='failed'){
        clearInterval(startupHealthTimer);
        render({...baseState,health:r.health||{ok:false,pending:false,reason:'Proxy is not working.'},proxyChecking:false,proxyFailed:true});
        return;
      }
      if(r?.status==='connected' && r?.health?.ok===true){
        clearInterval(startupHealthTimer);
        render({...baseState,health:{...r.health,pending:false},proxyChecking:false,proxyFailed:false});
        return;
      }
      clearInterval(startupHealthTimer);
    }catch{}finally{polling=false;}
  },1500);
}

async function hydrateCachedClientView(generation=popupGeneration){
  try{
    const [session,profile,stored]=await Promise.all([
      CS.Auth.session(false),
      CS.Auth.cached(),
      CS.Store.get([
        'clientSitesCache',
        'clientLastState',
        'clientProxyHealth',
        'lastSavedProxyConfig',
        'activeProxyCredentials',
        'clientDeviceCache',
        'clientLockReason',
        'clientSuspendedReason'
      ])
    ]);

    if(generation!==popupGeneration || !session || !profile || profile.role!=='client') return false;
    if(stored.clientSuspendedReason || profile.active===false){
      // This is only a local snapshot. An Admin may have unsuspended the
      // account since it was cached. Confirm live status before showing a
      // suspension warning (or requesting any destructive enforcement).
      showStartup('Checking account status…');
      return false;
    }

    // A cached lock is not displayed immediately because it may be stale.
    // Keep the old startup loader visible while the foreground security/control
    // reconciliation confirms whether the profile is actually still locked.
    if (String(stored.clientLockReason || '').trim()) {
      showStartup('Restoring secure session…');
      return false;
    }

    const proxyRaw=stored.lastSavedProxyConfig || stored.activeProxyCredentials || null;
    const proxy=proxyRaw && proxyRaw.host && Number(proxyRaw.port)
      ? {...proxyRaw,mode:'fixed_servers'}
      : {mode:'unconfigured',healthy:false,ip:'',lastError:'Proxy is not configured.'};
    const previousHealth=stored.clientProxyHealth || {};
    const previousLastState=stored.clientLastState || {};
    const previousDevice=stored.clientDeviceCache || {};
    const hasKnownGood=previousHealth.ok===true || previousDevice.proxyHealthy===true || previousLastState.proxyHealthy===true;
    const hasKnownFailure=previousHealth.ok===false && previousHealth.pending===false;

    // Show the cached client dashboard immediately. Proxy verification continues
    // in the background and will replace this optimistic state with the real
    // result once Chrome has finished checking the proxy.
    render({
      ok:true,
      loggedIn:true,
      session,
      profile,
      sites:Array.isArray(stored.clientSitesCache)?stored.clientSitesCache:[],
      proxy,
      device:previousDevice,
      lastState:previousLastState,
      health:{...previousHealth,pending:hasKnownFailure?false:true},
      proxyChecking:proxy.mode==='fixed_servers',
      proxyFailed:hasKnownFailure,
      locked:!!stored.clientLockReason,
      suspended:false,
      cachedView:true
    });
    return true;
  }catch{
    return false;
  }
}

async function startup() {
  const generation=++popupGeneration;
  clearError();
  clearInterval(startupHealthTimer);
  if(navigator.onLine===false)return showConnectivity();

  // Popup open is an explicit foreground reconciliation point. Run the same
  // control-plane checks normally driven by alarms without waiting for the
  // next background tick. This stays fire-and-forget so the dashboard can
  // still paint immediately from cached state.
  send('popup-open',{},20000).catch(()=>{});


  // Never block the popup on network/Firebase/proxy verification. Paint the
  // last known client state immediately, then reconcile everything in the
  // background. This restores the normal fast popup experience.
  const cachedShown=await hydrateCachedClientView(generation);
  if(generation!==popupGeneration)return;
  const watchdog=setTimeout(()=>{
    if(generation===popupGeneration && !cachedShown && !$('startup').classList.contains('hidden')){
      show('login');
      showError('Startup is taking too long. Please reload the extension.');
    }
  },15000);

  try{
    const local=await restoreAuth();
    if(generation!==popupGeneration){clearTimeout(watchdog);return;}
    if(!local){
      clearTimeout(watchdog);
      popupState={};
      show('login');
      return;
    }
    if(local.suspended){clearTimeout(watchdog);showSuspended();send('activate-suspension',{reason:'Account suspended.'},12000).catch(()=>{});return;}

    // Resume is deliberately proxy-test-free. clientStep still applies the
    // configured proxy immediately, while check-proxy below performs the actual
    // health verification in the background.
    const state=await send('resume',{allowDeviceReset:true},20000);
    clearTimeout(watchdog);
    if(generation!==popupGeneration)return;

    if(state?.deviceBlocked)return showDeviceBlocked(state.error);
    if(state?.suspended){showSuspended();send('activate-suspension',{reason:'Account suspended.'},12000).catch(()=>{});return;}
    if(state?.locked)return render(state);
    if(!(state?.profile&&state?.loggedIn)){
      if(!cachedShown)throw new Error(state?.error||'This device could not be authorized.');
      return;
    }

    // Keep the dashboard visible with the latest account/site state while the
    // proxy test runs separately.
    render({...state,proxyChecking:state?.proxy?.mode==='fixed_servers' ? true : false,proxyFailed:false});

    if(state?.proxy?.mode==='fixed_servers'||state?.proxyChecking){
      const baseState=state;
      // Do not await this from the UI startup path: the popup must remain open
      // and usable while Chrome verifies the proxy.
      send('check-proxy',{},20000).then((health)=>{
        if(generation!==popupGeneration)return;
        if(health?.deviceBlocked)return showDeviceBlocked(health.error);
        if(health?.suspended){showSuspended();send('activate-suspension',{reason:'Account suspended.'},12000).catch(()=>{});return;}
        if(!health) return;

        const merged=health?.profile&&health?.loggedIn
          ? health
          : {...baseState,...health,proxyFailed:health?.proxyFailed===true,health:health?.health||{ok:false,reason:health?.error||'Proxy is not working.'}};

        // A temporary failure enters background recovery. Only a confirmed
        // failure turns the dashboard red; the managed tab remains normal Chrome
        // navigation through the proxy throughout.
        if(health?.proxyChecking===true || health?.health?.pending===true){
          render({...merged,proxyChecking:true,proxyFailed:false,health:health?.health||{ok:false,pending:true,reason:'Verifying the proxy in the background…'}});
          watchProxyRecovery({...baseState,...health,proxy:health.proxy||baseState.proxy,profile:health.profile||baseState.profile,sites:health.sites||baseState.sites,device:health.device||baseState.device});
        }else if(health?.proxyFailed===true || (health?.health?.ok===false && health?.health?.pending!==true)){
          render({...merged,proxyChecking:false,proxyFailed:true,health:health?.health||{ok:false,pending:false,reason:health?.error||'Proxy is not working.'}});
        }else{
          render({...merged,proxyChecking:false,proxyFailed:false});
        }
      }).catch(()=>{});
    }
  }catch(error){
    clearTimeout(watchdog);
    if(generation!==popupGeneration)return;
    const message=String(error?.message||error||'');
    const proxyError=/proxy|tunnel|err_(proxy|tunnel|connection_timed_out|connection_refused)/i.test(message);
    if(proxyError && cachedShown){
      render({
        ...(popupState||{}),
        proxyChecking:false,
        proxyFailed:true,
        health:{ok:false,pending:false,reason:message||'Proxy is not working.'}
      });
      return;
    }
    if(isConnectivityError(message))return showConnectivity();
    if(!cachedShown){
      show('login');
      showError(message||'Startup failed. Please try again.');
    }
  }
}

function setProxyChecking(){
  const badge=$('proxyBadge'),info=$('proxyInfo');
  if(badge){badge.className='badge warn';badge.innerHTML='<span class="dot"></span>Checking';}
  if(info){info.className='alert info';info.textContent='Checking the current proxy and public IP…';}
}


$('fixChrome').onclick = async () => {
  const b = $('fixChrome');
  busy(b, true, 'Refreshing…');
  try {
    const r = await send('fix-chrome', {}, 30000);
    if (!r?.ok) {
      toast(r?.error || 'Chrome could not be refreshed.');
      busy(b, false, 'Fix Chrome');
    }
  } catch (error) {
    toast(error?.message || 'Chrome could not be refreshed.');
    busy(b, false, 'Fix Chrome');
  }
};

$('loginBtn').onclick=async()=>{
  const generation=++popupGeneration;
  clearInterval(startupHealthTimer);
  clearError();
  const email=$('email').value.trim(),password=$('password').value;
  if(!email||!password){showError('Enter email and password.');return;}
  const b=$('loginBtn');busy(b,true,'Signing in…');
  try{
    const result=await send('login',{email,password},90000);
    if(generation!==popupGeneration)return;
    if(result?.deviceBlocked)return showDeviceBlocked(result.error);
    if(result?.suspended)return showSuspended();
    if(result?.profile&&result?.loggedIn){
      render(result);
      if(result?.proxy?.mode==='fixed_servers'||result?.proxyChecking){
        send('check-proxy',{},20000).then((health)=>{
        if(generation!==popupGeneration)return;
          if(health?.deviceBlocked)return showDeviceBlocked(health.error);
          if(health?.suspended)return showSuspended();
          if(!health)return;
          const merged=health?.profile&&health?.loggedIn
            ? health
            : {...result,...health,proxyFailed:health?.proxyFailed===true,health:health?.health||{ok:false,reason:health?.error||'Proxy is not working.'}};
          if(health?.proxyChecking===true || health?.health?.pending===true){
            render({...merged,proxyChecking:true,proxyFailed:false,health:health?.health||{ok:false,pending:true,reason:'Verifying the proxy in the background…'}});
            watchProxyRecovery({...result,...health,proxy:health.proxy||result.proxy,profile:health.profile||result.profile,sites:health.sites||result.sites,device:health.device||result.device});
          }else if(health?.proxyFailed===true || (health?.health?.ok===false && health?.health?.pending!==true)){
            render({...merged,proxyChecking:false,proxyFailed:true});
          }else{
            render({...merged,proxyChecking:false,proxyFailed:false});
          }
        }).catch(()=>{});
      }
      if(Number(result?.applied||0)>0){
        toast(`Login completed • ${result.applied} site${Number(result.applied)===1?'':'s'} synced.`);
      }
      return;
    }
    if(isConnectivityError(result?.error)||result?.proxyFailed===true)return showConnectivity();
    show('login');showError(result?.error||'Sign in failed.');
  }catch(error){
    if(isConnectivityError(error?.message))return showConnectivity();
    show('login');showError(error?.message||String(error));
  }finally{busy(b,false,'Sign in');}
};

$('freshSync').onclick = async () => {
  const generation=popupGeneration;
  const b = $('freshSync');
  let completed = false;
  busy(b, true, 'Logging In…');
  try {
    const r = await send('fresh-sync', {}, 20000);
    if(generation!==popupGeneration)return;
    if(r?.profile || r?.suspended || r?.locked || r?.deviceBlocked)render(r);
    if (r?.ok) {
      completed = true;
      b.disabled = true;
      b.classList.add('login-success');
      b.textContent = 'Logged In';

      if(r.applied){
        const failed=Number(r.cookieFailures||0);
        toast(failed
          ? `Login completed • ${failed} cookie${failed===1?'':'s'} failed.`
          : (Number(r.reloadedTabs||0)>0
            ? `Login completed • ${r.reloadedTabs} managed tab${r.reloadedTabs===1?' was':'s were'} refreshed.`
            : `Login completed for ${r.applied} site${r.applied===1?'':'s'}.`));
      }else{
        const d=(r.syncDiagnostics||[])[0];
        toast(d?.status==='already-applied' ? 'Login completed • latest session already applied.' : (r.error||'Login completed.'));
      }
      return;
    }
    if(isConnectivityError(r?.error)||r?.proxyFailed===true)return showConnectivity();
    toast(r?.error || 'Login failed.');
  } finally {
    if (!completed) busy(b, false, 'LogIn Website');
  }
};

$('logout').onclick = async () => {
  ++popupGeneration;
  clearInterval(startupHealthTimer);
  popupState={};
  const b = $('logout');
  busy(b, true, 'Signing out…');
  const result=await send('logout', {}, 90000);
  // If the background response is interrupted, still prevent any cached
  // extension session from reappearing on the next browser launch.
  await CS.Store.set({clientSignedOut:true}).catch(()=>{});
  await CS.Auth.logout().catch(() => {});
  $('password').value='';
  $('freshSync').classList.remove('login-success');
  $('freshSync').disabled=false;
  $('freshSync').textContent='LogIn Website';
  delete $('freshSync').dataset.oldLabel;
  show('login');
  busy(b, false, '↪');
  if(result?.ok!==true)showError(result?.error||'Signed out, but browser cleanup was interrupted. Please retry.');
};

$('retrySuspended').onclick = () => startup();
$('retryLocked').onclick = async () => {
  const r = await send('warning-check');
  if (r?.ok) startup(); else showLocked(r?.error || 'Remove unauthorized extensions first.');
};
$('grantAccess').onclick = async () => {
  const local = await restoreAuth();
  if (!local) return show('login');
  try {
    const state = await loadAssignedState(local);
    const origins = [...new Set((state.sites || []).flatMap((site) => {
      try { return [`${new URL(site.origin).origin}/*`]; } catch { return []; }
    }))];
    if (!origins.length || await chrome.permissions.request({origins})) {
      await performBackgroundSync(false, false);
      toast('Website access granted.');
    } else toast('Permission was not granted.');
  } catch (error) {
    toast(error?.message || String(error));
  }
};

function toast(message) {
  const el = $('toast');
  el.textContent = String(message || '');
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 2400);
}


$('checkAgainConnectivity')?.addEventListener('click',async()=>{
  const b=$('checkAgainConnectivity');
  if(!b || b.disabled)return;
  const started=performance.now();
  b.classList.add('connectivity-checking');
  b.setAttribute('aria-busy','true');
  busy(b,true,'Checking…');
  try{if(typeof startup==='function')await startup();else window.location.reload();}catch(e){showConnectivity();}
  finally{
    const wait=Math.max(0,450-(performance.now()-started));
    if(wait)await new Promise(r=>setTimeout(r,wait));
    if(b){
      busy(b,false,'Check again');
      b.classList.remove('connectivity-checking');
      b.removeAttribute('aria-busy');
    }
  }
});
window.addEventListener('offline',()=>showConnectivity());
// Always show a usable login screen if JavaScript starts successfully but Firebase
// or the background worker is unavailable. This avoids a blank white popup.
show('login');
startup();

$('deviceBlockedBack').onclick=()=>show('login');

window.addEventListener('unload',()=>clearInterval(startupHealthTimer));
