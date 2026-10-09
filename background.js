/* Cookie Sync Client v9.2 reset-safe device authorization + proxy recovery */
importScripts('shared/config.js','shared/public-suffix.js','shared/util.js','shared/recovery.js','shared/store.js','shared/firebase.js','shared/auth.js','shared/crypto.js','shared/cookies.js','shared/proxy.js','shared/rules.js','shared/security.js','shared/sync.js');

CS.Proxy.installAuthListener();

let runningPromise=null;
let clientLoginInProgress=false;
let proxyRecoveryPromise=null;
// One global queue for destructive/sync browser operations. This prevents
// Fix Chrome, remote refresh, Fresh Sync, Share Login sync, and the regular
// client lifecycle from clearing or restoring cookies at the same time.
let browserOperationPromise=Promise.resolve();
async function withBrowserOperation(fn){
  const previous=browserOperationPromise;
  let release;
  browserOperationPromise=new Promise(resolve=>{release=resolve;});
  await previous.catch(()=>{});
  try{
    return await fn();
  }finally{
    release();
  }
}
const PROXY_HEALTH_ALARM='cookie-sync-proxy-health';
const PROXY_ROTATION_CLEANUP_ALARM='cookie-sync-proxy-rotation-cleanup';
const MANUAL_SHARE_OPEN_ALARM='cookie-sync-manual-share-open';
const PRESENCE_HEARTBEAT_ALARM='cookie-sync-presence-heartbeat';
const STATE_RECONCILIATION_ALARM='cookie-sync-state-reconciliation';
const SUSPENSION_CHECK_ALARM='cookie-sync-suspension-check';
const CONTROL_PLANE_ALARM='cookie-sync-control-plane';
const PROXY_RECOVERY_MAX_ATTEMPTS=4;
const PROXY_RECOVERY_DELAYS=[0,1200,3000,5000];
// Reuse a very recent successful proxy check so startup/popup can release the
// managed site immediately. A real proxy error still locks and recovers at once.
const PROXY_HEALTH_CACHE_MAX_AGE_MS=75000;
const PROXY_HEALTH_TIMEOUT_MS=8000;
const MANUAL_SHARE_OPEN_MAX_AGE_MS=5*60*1000;
async function ensureManualShareOpenAlarm(){
  if(!chrome.alarms?.create)return;
  try{await chrome.alarms.create(MANUAL_SHARE_OPEN_ALARM,{delayInMinutes:0.5,periodInMinutes:1});}catch{}
}

async function ensurePresenceHeartbeatAlarm(){
  if(!chrome.alarms?.create)return;
  try{await chrome.alarms.create(PRESENCE_HEARTBEAT_ALARM,{delayInMinutes:1,periodInMinutes:1});}catch{}
}

async function ensureControlPlaneAlarm(){
  if(!chrome.alarms?.create)return;
  try{
    // Alarms can disappear across browser restarts/extension reloads. Restore
    // the poll when a worker wakes, but never postpone an existing due poll.
    const current=await chrome.alarms.get?.(CONTROL_PLANE_ALARM);
    if(current && Number(current.periodInMinutes)===1)return;
    await chrome.alarms.create(CONTROL_PLANE_ALARM,{delayInMinutes:0.5,periodInMinutes:1});
  }catch{}
}

let presenceWriteInFlight=null;
async function sendPresenceHeartbeat(force=false){
  if(presenceWriteInFlight)return presenceWriteInFlight;
  presenceWriteInFlight=(async()=>{
    try{
      const s=await CS.Auth.session(true).catch(()=>null);
      const p=await CS.Auth.cached().catch(()=>null);
      if(!s?.uid||!s?.idToken||!p||p.role!=='client'||p.active===false)return false;

      const now=Date.now();
      const local=await CS.Store.get(['clientPresenceLastSentAt','clientDeviceCache','clientDeviceCacheUid']).catch(()=>({}));
      if(!force && now-Number(local.clientPresenceLastSentAt||0)<45000)return false;

      const identity=await CS.Crypto.deviceIdentityForAccount(String(s.uid));
      const device=local.clientDeviceCacheUid===String(s.uid)?local.clientDeviceCache:null;
      if(!device || String(device.deviceId||'')!==String(identity.deviceId||''))return false;
      if(String(device.status||'')==='revoked')return false;

      const stamp=new Date(now).toISOString();
      const updated=await CS.Firebase.touchDevicePresence(s.uid,identity.deviceId,s.idToken,stamp).catch(()=>null);
      if(!updated)return false;

      await CS.Store.set({
        clientPresenceLastSentAt:now,
        clientDeviceCache:{...device,lastSeenAt:stamp}
      }).catch(()=>{});
      return true;
    }catch{return false}
    finally{presenceWriteInFlight=null;}
  })();
  return presenceWriteInFlight;
}


async function processHiddenProxyRotationSignal(me,sites,signalVersion){
  const uid=String(me?.session?.uid||'');
  const subadmin=String(me?.profile?.subadminUid||'');
  if(!uid||!subadmin||!Array.isArray(sites)||!sites.length||!Number(signalVersion||0))return{ok:false,reason:'missing-signal-context'};

  // Hidden clients already have a valid device claim. A proxy-rotation signal
  // must never enter the normal authorization/reclaim path: doing so can race
  // with Admin -> Reset Device and immediately recreate a freshly-reset claim.
  const binding=await getDeviceBinding().catch(()=>null);
  if(String(binding?.uid||'')!==uid||!String(binding?.deviceId||''))return{ok:false,reason:'no-device-binding'};

  const control=await getControl(me);
  const controlReset=Math.max(Number(control?.state?.resetVersion||0),Number(me?.profile?.deviceResetVersion||0));
  const bindingReset=Number(binding?.resetVersion||0);

  // A real Admin reset always wins over a hidden proxy-rotation signal. Stop
  // here and let the normal client startup/reauthorization path handle it.
  if(controlReset>bindingReset)return{ok:false,resetPending:true};

  const claim=await CS.Firebase.getDoc(['deviceClaims',uid],me.session.idToken).catch(()=>({exists:false,data:null}));
  const deviceDoc=await CS.Firebase.getDoc(['devices',uid],me.session.idToken).catch(()=>({exists:false,data:null}));
  const deviceId=String(binding.deviceId||'');
  if(!claim.exists||!deviceDoc.exists||String(claim.data?.deviceId||'')!==deviceId||String(deviceDoc.data?.deviceId||'')!==deviceId||String(deviceDoc.data?.status||'')==='revoked'){
    return{ok:false,resetPending:true};
  }

  const proxy=CS.Proxy.normalize(control.proxy||{mode:'unconfigured'});
  if(proxy.mode!=='fixed_servers')return{ok:false,proxyFailed:true,reason:'Proxy is not configured.'};

  try{
    await CS.Proxy.setActiveCredentials(proxy);
    await CS.Proxy.apply(proxy);
    await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:true});
    const health=await CS.Proxy.test(proxy,{timeoutMs:PROXY_HEALTH_TIMEOUT_MS});
    if(!health.ok){
      await beginProxyRecovery(health.reason||'Proxy is not working.').catch(()=>{});
      return{ok:false,proxyFailed:true,health};
    }

    // Re-check reset state after proxy application/health verification. This
    // closes the race where Admin reset happens while the proxy test is running.
    const freshMe=await CS.Auth.currentProfile(true).catch(()=>null);
    if(!freshMe?.session?.uid||String(freshMe.session.uid)!==uid)return{ok:false,resetPending:true};
    const freshControl=await getControl(freshMe);
    const freshReset=Math.max(Number(freshControl?.state?.resetVersion||0),Number(freshMe?.profile?.deviceResetVersion||0));
    if(freshReset>bindingReset)return{ok:false,resetPending:true};

    const cleanup=await cleanupAfterProxyRotation(subadmin,Number(signalVersion||control.state.proxyVersion||0),{existingDeviceOnly:true});
    if(!cleanup.ok)return{ok:false,proxyCleanupPending:true,reason:cleanup.reason||'Browser refresh is pending.'};

    await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:false}).catch(()=>{});
    await CS.Store.set({
      clientProxyHealth:{...health,pending:false,checkedAt:Date.now()},
      lastProxyHealthProxyIdentity:clientProxyIdentity(proxy),
      lastSavedProxyConfig:proxy,
      lastSavedProxyConfigAt:Date.now(),
      lastSavedProxySubadminUid:subadmin,
      clientAppliedProxyVersion:Number(signalVersion||control.state.proxyVersion||0),
      clientAppliedProxySubadminUid:subadmin,
      clientAppliedProxyIdentity:clientProxyIdentity(proxy)
    }).catch(()=>{});
    return{ok:true,health};
  }catch(e){
    const message=String(e?.message||e||'Hidden proxy rotation failed.');
    if(e?.code==='DEVICE_RESET_PENDING')return{ok:false,resetPending:true};
    return{ok:false,reason:message};
  }
}

async function checkManualShareOpen({forceSites=false}={}){
  try{
    const me=await CS.Auth.currentProfile(false).catch(()=>null);
    if(!me?.session?.idToken)return;
    const sites=await loadSites(me,{force:forceSites===true});
    if(!Array.isArray(sites)||!sites.length)return;
    const local=await CS.Store.get([
      'lastAdminBrowserRefreshAt',
      'lastAdminBrowserRefreshSubadminUid',
      'lastTargetedBrowserRefreshAt',
      'lastTargetedBrowserRefreshUid',
      'manualShareOpenedVersions',
      'lastProxyRotationSignalVersion',
      'lastProxyRotationSignalSubadminUid',
      'clientAppliedProxyVersion',
      'clientAppliedProxySubadminUid',
      'clientLoginSessionStartedAt'
    ]).catch(()=>({}));
    const localSub=String(local.lastAdminBrowserRefreshSubadminUid||'');
    const localAt=Number(local.lastAdminBrowserRefreshAt||0);
    const targetedUid=String(local.lastTargetedBrowserRefreshUid||'');
    const targetedAt=Number(local.lastTargetedBrowserRefreshAt||0);
    const opened={...(local.manualShareOpenedVersions||{})};
    const sessionStartedAt=Number(local.clientLoginSessionStartedAt||0);
    // Refresh/share events are bound to the current client login session.
    // Historical requests must never replay during login or a later worker wake.
    if(!sessionStartedAt){
      await CS.Store.set({clientLoginSessionStartedAt:Date.now()}).catch(()=>{});
      await CS.Store.remove(['clientVerifiedSyncAt','clientVerifiedSyncUid']).catch(()=>{});
    }
    const activeSessionStartedAt=sessionStartedAt||Date.now();
    // Do not replay an Admin refresh signal that predates this client account.
    // A newly-created account must perform only its own first-device cleanup
    // and must not inherit an older global/targeted refresh request merely
    // because the request is still present in the latest snapshot.
    const accountCreatedAt=Date.parse(String(me.profile.createdAt||''));
    const accountCreatedMs=Number.isFinite(accountCreatedAt)?accountCreatedAt:0;
    let changed=false;
    let key=null;
    const pendingManualShares=[];

    for(const site of sites){
      const r=await CS.Firebase.getDoc(['sites',site.id,'sync','latest'],me.session.idToken).catch(()=>({exists:false,data:null}));
      if(!r.exists||!r.data)continue;
      const snap=r.data;
      const reason=String(snap.reason||'');

      // Main Admin-created hidden clients are intentionally absent from the
      // Sub-admin client list. A proxy rotation still has to reach them.
      // Admin publishes this durable signal into the same managed-site snapshot
      // that hidden clients already read. Treat it as a fallback transport for
      // proxy rotation; the normal control-plane version check remains the
      // authoritative path.
      if(reason.startsWith('admin-proxy-rotation:')){
        const signalVersion=Number(reason.slice('admin-proxy-rotation:'.length).trim()||snap.requiredProxyVersion||0);
        // The rotation signal is durable in the shared snapshot, so its local
        // acknowledgement must survive client logout/login. Use the proxy version
        // already installed on this browser as an additional acknowledgement source;
        // otherwise logout clears the signal marker and the exact same old rotation
        // would be replayed on every subsequent login.
        const signalSeenVersion=String(local.lastProxyRotationSignalSubadminUid||'')===String(me.profile.subadminUid||'')
          ? Number(local.lastProxyRotationSignalVersion||0) : 0;
        const appliedProxySub=String(local.clientAppliedProxySubadminUid||'');
        const appliedProxyVersion=appliedProxySub===String(me.profile.subadminUid||'')
          ? Number(local.clientAppliedProxyVersion||0) : 0;
        const seenVersion=Math.max(signalSeenVersion,appliedProxyVersion);
        if(signalVersion>0 && signalVersion>seenVersion){
        // Hidden proxy rotation is a browser-session operation only. It must
        // never enter clientStep()/ensureDevice(), because the normal
        // authorization path can race with Admin -> Reset Device and reclaim
        // a device that the Admin has just released.
        const rotation=await processHiddenProxyRotationSignal(me,sites,signalVersion).catch(()=>({ok:false}));
        if(rotation?.ok && rotation?.proxyFailed!==true && rotation?.proxyCleanupPending!==true && rotation?.resetPending!==true){
          await CS.Store.set({
            lastProxyRotationSignalVersion:signalVersion,
            lastProxyRotationSignalSubadminUid:String(me.profile.subadminUid||'')
          }).catch(()=>{});
        }
      }
      }

      if(reason.startsWith('admin-refresh-user:')){
        const signalAt=Date.parse(String(snap.publishedAt||''));
        const signal=Number.isFinite(signalAt)?signalAt:0;
        const targetUid=reason.slice('admin-refresh-user:'.length).trim();
        if(targetUid===String(me.session.uid||'') && (targetedUid!==targetUid || signal>targetedAt)){
          if(signal>0 && signal<=activeSessionStartedAt){
            await CS.Store.set({
              lastTargetedBrowserRefreshAt:signal,
              lastTargetedBrowserRefreshUid:targetUid
            }).catch(()=>{});
            continue;
          }
          if(signal>0 && accountCreatedMs>0 && signal<=accountCreatedMs){
            // This targeted refresh was published before the client account
            // existed, so acknowledge it without touching the browser.
            await CS.Store.set({
              lastTargetedBrowserRefreshAt:signal,
              lastTargetedBrowserRefreshUid:targetUid
            }).catch(()=>{});
            continue;
          }
          // A cleanup closes tabs and may recreate service-worker execution state.
          // Persist the acknowledgement before cleanup so the same command cannot
          // run again merely because the Client logs in again.
          const handledAt=signal||Date.now();
          await CS.Store.set({
            lastTargetedBrowserRefreshAt:handledAt,
            lastTargetedBrowserRefreshUid:targetUid
          }).catch(()=>{});

          const refreshed=await refreshChromeForClient({remoteAdmin:true,profileRefresh:true}).catch(()=>({ok:false}));
          if(refreshed?.ok)return;

          await CS.Store.remove([
            'lastTargetedBrowserRefreshAt',
            'lastTargetedBrowserRefreshUid'
          ]).catch(()=>{});
        }
        continue;
      }

      if(reason==='admin-refresh-users'){
        const signalAt=Date.parse(String(snap.publishedAt||''));
        const signal=Number.isFinite(signalAt)?signalAt:0;
        const refreshSubadmin=String(me.profile.subadminUid||'');
        if(localSub!==refreshSubadmin || signal>localAt){
          if(signal>0 && signal<=activeSessionStartedAt){
            await CS.Store.set({
              lastAdminBrowserRefreshAt:signal,
              lastAdminBrowserRefreshSubadminUid:refreshSubadmin
            }).catch(()=>{});
            continue;
          }
          if(signal>0 && accountCreatedMs>0 && signal<=accountCreatedMs){
            // A global refresh published before this client account was created
            // is stale for this account. Acknowledge it without a browser wipe
            // or the `chrome-refreshed.html` page.
            await CS.Store.set({
              lastAdminBrowserRefreshAt:signal,
              lastAdminBrowserRefreshSubadminUid:refreshSubadmin
            }).catch(()=>{});
            continue;
          }
          // A browser-data cleanup can close tabs and recreate execution state.
          // Mark this exact refresh signal as handled BEFORE starting cleanup so
          // signing in again cannot replay the same Admin refresh event.
          const handledAt=signal||Date.now();
          await CS.Store.set({
            lastAdminBrowserRefreshAt:handledAt,
            lastAdminBrowserRefreshSubadminUid:refreshSubadmin
          }).catch(()=>{});

          const refreshed=await refreshChromeForClient({remoteAdmin:true}).catch(()=>({ok:false}));
          if(refreshed?.ok)return;

          // Cleanup failed: remove the optimistic acknowledgement so the normal
          // background alarm can retry the same refresh event later.
          await CS.Store.remove([
            'lastAdminBrowserRefreshAt',
            'lastAdminBrowserRefreshSubadminUid'
          ]).catch(()=>{});
        }
        continue;
      }

      if(reason!=='manual')continue;
      const version=Number(snap.version||0);
      if(version<=0)continue;
      if(Number(opened[String(site.id)]||0)>=version)continue;
      const publishedAtMs=Date.parse(String(snap.publishedAt||''));
      if(Number.isFinite(publishedAtMs) && publishedAtMs<=activeSessionStartedAt){
        // Login already retrieves the latest snapshot. Only a Share Login push
        // published during this active session may trigger the special auto-open.
        continue;
      }
      if(Number.isFinite(publishedAtMs) && (Date.now()-publishedAtMs)>MANUAL_SHARE_OPEN_MAX_AGE_MS){
        // A manual Share Login is a live push, not a deferred task. Do not let a
        // stale event open the managed site hours later when the extension wakes.
        opened[String(site.id)]=Math.max(Number(opened[String(site.id)]||0),version);
        changed=true;
        continue;
      }

      // Queue the pending Share Login event. We sync once for the whole client,
      // then open each newly shared site only after its exact snapshot version
      // is confirmed as applied (or was already applied by another lifecycle).
      pendingManualShares.push({site,version});
    }

    if(pendingManualShares.length){
      const syncResult=await syncLatestCookies({fresh:false,reloadTabs:false}).catch(()=>null);
      const diagnostics=Array.isArray(syncResult?.syncDiagnostics)?syncResult.syncDiagnostics:[];

      for(const pending of pendingManualShares){
        const siteId=String(pending.site.id);
        const diag=diagnostics.find(x=>String(x?.siteId||'')===siteId && Number(x?.version||0)===pending.version);
        const synced=diag && (diag.status==='applied' || diag.status==='already-applied');
        if(!synced)continue;

        const target=String(pending.site.origin||(`https://${String(pending.site.hostname||'').replace(/^\.+/,'')}`)||'').trim();
        if(!/^https?:\/\//i.test(target))continue;

        try{
          await chrome.tabs.create({url:target,active:true});
          opened[siteId]=pending.version;
          changed=true;
        }catch{}
      }
    }

    if(changed)await CS.Store.set({manualShareOpenedVersions:opened}).catch(()=>{});
  }catch{}
}

async function ensureProxyHealthAlarm(){
  if(!chrome.alarms?.create)return;
  try{await chrome.alarms.create(PROXY_HEALTH_ALARM,{delayInMinutes:0.5,periodInMinutes:1});}catch{}
}
let proxyRecoveryRunning=false;

async function cachedState(){
  const s=await CS.Auth.raw();
  const p=await CS.Auth.cached();
  const c=await CS.Store.get(['clientSitesCache','clientLastState','clientLockReason','clientProxyHealth','clientSuspendedReason']);
  return{session:s?{uid:s.uid,email:s.email}:null,profile:p,sites:Array.isArray(c.clientSitesCache)?c.clientSitesCache:[],lastState:c.clientLastState||null,lockReason:c.clientLockReason||null,suspendedReason:c.clientSuspendedReason||null,proxyHealth:c.clientProxyHealth||null};
}
async function getSubStatus(me,{force=false}={}){
  if(!me.profile.subadminUid)throw new Error('This client account has no assigned Admin Extension.');
  const sub=String(me.profile.subadminUid);
  const local=await CS.Store.get(['clientSubStatusCache','clientSubStatusCacheAt','clientSubStatusCacheSubadminUid']).catch(()=>({}));
  const age=Date.now()-Number(local.clientSubStatusCacheAt||0);
  if(!force && local.clientSubStatusCacheSubadminUid===sub && age>=0 && age<15000 && local.clientSubStatusCache){
    return local.clientSubStatusCache;
  }
  const r=await CS.Firebase.getDoc(['users',sub,'control','status'],me.session.idToken);
  const status=r.exists?r.data:{active:true};
  await CS.Store.set({clientSubStatusCache:status,clientSubStatusCacheAt:Date.now(),clientSubStatusCacheSubadminUid:sub}).catch(()=>{});
  return status;
}
// Runs the same control-plane work that normally happens on background alarms,
// but immediately when the client popup is opened. It is deliberately serialized
// so popup-open reconciliation cannot race another popup-open reconciliation or
// duplicate a destructive browser cleanup.
let foregroundCheckPromise=null;
async function runForegroundChecks(){
  if(foregroundCheckPromise)return foregroundCheckPromise;
  foregroundCheckPromise=(async()=>{
    const control=await controlPlaneTick().catch(e=>({ok:false,error:e?.message||String(e)}));
    if(control?.suspended || control?.deviceResetRequired || control?.deviceBlocked || control?.loggedIn===false){
      return control;
    }
    await checkManualShareOpen({forceSites:true}).catch(()=>{});
    return control;
  })();
  try{return await foregroundCheckPromise;}
  finally{foregroundCheckPromise=null;}
}

let controlPlanePromise=null;
async function controlPlaneTick(){
  // Popup, periodic alarm and browser-activity checks must not race a
  // destructive suspension/reset/revocation on the same browser profile.
  if(controlPlanePromise)return controlPlanePromise;
  controlPlanePromise=controlPlaneTickUnlocked();
  try{return await controlPlanePromise;}
  finally{controlPlanePromise=null;}
}
async function controlPlaneTickUnlocked(){
  // One lightweight control-plane cycle: account status, assigned admin status,
  // device claim/device record, and reset/proxy control versions. This replaces
  // the old separate state-reconciliation + suspension timers. It never pushes
  // cookies, reloads managed tabs, or runs a proxy health test.
  // Device claims are written by the explicit login/resume path. A parallel
  // background read in the middle of registration must not falsely revoke it.
  if(clientLoginInProgress)return {ok:true,loggedIn:true,controlCheckDeferred:true};
  if(runningPromise){
    // A proxy recovery or long-running sync must not suppress account-status
    // checks indefinitely. Only read live client/Admin suspension here; leave
    // device registration checks to the idle control-plane path.
    try{
      const pending=await CS.Auth.currentProfile(true);
      // The session can expire or be removed while an unrelated operation is
      // running. Never leave previously allowed websites open in that state.
      if(!pending?.session?.uid){
        await enforceLoggedOutNetworkLock().catch(()=>{});
        return {ok:true,loggedIn:false};
      }
      if(pending?.profile?.role==='client'){
        let inactive=pending.profile.active===false;
        if(!inactive && pending.profile.subadminUid){
          const admin=await getSubStatus(pending,{force:true});
          inactive=admin.active===false;
        }
        if(inactive){
          await setSuspensionNetworkLock('Account suspended.');
          // Best-effort queued browser cleanup. The persistent DNR lock does
          // not depend on this queue finishing or on the popup being opened.
          enforceClientSuspension('Account suspended.').catch(()=>{});
          return {ok:true,loggedIn:true,suspended:true,cleanupPending:true};
        }
      }
    }catch{}
    return {ok:true,loggedIn:true,controlCheckDeferred:true};
  }
  const s=await CS.Auth.session(true).catch(()=>null);
  if(!s?.uid){
    // A revoked/expired/invalidated session must remove old allow rules even
    // when nobody has opened the popup or pressed Log Out.
    await enforceLoggedOutNetworkLock().catch(()=>{});
    return {ok:true,loggedIn:false};
  }

  let me=null;
  try{
    me=await CS.Auth.currentProfile(true);
  }catch(e){
    if(e?.code==='ACCOUNT_SUSPENDED'){
      const r=await enforceClientSuspension('Account suspended.').catch(()=>null);
      return {ok:true,loggedIn:true,suspended:true,...(r||{})};
    }
    if(e?.code==='PROFILE_MISSING'){
      // Auth.currentProfile has already invalidated the deleted account.
      // Do not leave the previously authorized browser tabs usable until
      // someone opens the extension popup.
      await enforceLoggedOutNetworkLock().catch(()=>{});
      return {ok:true,loggedIn:false,profileMissing:true};
    }
    throw e;
  }
  if(!me?.profile || me.profile.role!=='client'){
    // A missing/changed role is not authorization to keep client site rules.
    await enforceLoggedOutNetworkLock().catch(()=>{});
    return {ok:false,loggedIn:false,unauthorizedRole:true};
  }
  if(me.profile.active===false){
    const r=await enforceClientSuspension('Account suspended.').catch(()=>null);
    return {ok:true,loggedIn:true,suspended:true,...(r||{})};
  }

  // Check the assigned Admin's status in parallel with the durable device state.
  const subId=String(me.profile.subadminUid||'').trim();
  if(!subId){
    await enforceLoggedOutNetworkLock().catch(()=>{});
    return {ok:false,loggedIn:true,missingAssignment:true};
  }
  const uid=String(me.session.uid);
  const localBinding=await getDeviceBinding().catch(()=>({uid:'',deviceId:'',resetVersion:0}));
  const localCacheR=await CS.Store.get(['clientDeviceCache','clientDeviceCacheUid']).catch(()=>({}));
  const localDevice=String(localCacheR.clientDeviceCacheUid||'')===uid ? localCacheR.clientDeviceCache : null;

  const [subStatusR,claimR,deviceR,stateR]=await Promise.all([
    CS.Firebase.getDoc(['users',subId,'control','status'],me.session.idToken).catch(e=>({exists:false,data:null,_readError:e})),
    CS.Firebase.getDoc(['deviceClaims',uid],me.session.idToken).catch(e=>({exists:false,data:null,_readError:e})),
    CS.Firebase.getDoc(['devices',uid],me.session.idToken).catch(e=>({exists:false,data:null,_readError:e})),
    CS.Firebase.getDoc(['users',subId,'control','state'],me.session.idToken).catch(e=>({exists:false,data:null,_readError:e}))
  ]);

  // The awaited profile/device reads may overlap a login that began *after*
  // this poll started. Do not act on partially published registration rows.
  if(clientLoginInProgress || runningPromise)return {ok:true,loggedIn:true,controlCheckDeferred:true};
  const subStatus=subStatusR.exists&&subStatusR.data?subStatusR.data:{active:true};
  if(subStatus.active===false){
    const r=await enforceClientSuspension('Account suspended.').catch(()=>null);
    return {ok:true,loggedIn:true,suspended:true,...(r||{})};
  }

  // Never interpret a transient Supabase read failure as a real
  // missing device claim. Doing so can incorrectly log out an otherwise valid
  // client when the network is slow or the proxy is recovering.
  if(claimR._readError || deviceR._readError || stateR._readError || subStatusR._readError){
    return {ok:true,loggedIn:true,authorized:true,controlCheckDeferred:true};
  }

  // Server claim selects the legacy ID for an already-registered account.
  // A new/unclaimed account gets its own stable, account-scoped device ID.
  const identity=await CS.Crypto.deviceIdentityForAccount(
    uid,String(claimR.data?.deviceId||deviceR.data?.deviceId||'')
  );
  const locallyBound=String(localBinding.uid||'')===uid &&
    !!String(localBinding.deviceId||'') &&
    String(localBinding.deviceId||'')===String(identity?.deviceId||'');

  const controlState=stateR.exists&&stateR.data?stateR.data:{};
  const controlReset=Math.max(
    Number(controlState.resetVersion||0),
    Number(me.profile.deviceResetVersion||0)
  );
  const localReset=Number(localBinding.resetVersion||0);
  // Reset releases the server claim. Once both rows disappear, the selected
  // identity may shift from the legacy ID to the new account-scoped ID; that
  // must NOT hide a newer reset from the previously authorized browser.
  const resetPendingForKnownDevice =
    String(localBinding.uid||'')===uid &&
    !!String(localBinding.deviceId||'') &&
    controlReset > localReset;

  // Admin Reset Device deliberately removes both durable device records. Once
  // that reset marker is newer than this browser's binding, the missing claim
  // and device are EXPECTED, not an unauthorized-device condition. Keep the
  // session alive and let the explicit popup/login flow re-authorize this same
  // Chrome device instead of logging it out in the background.
  if(resetPendingForKnownDevice && !claimR.exists && !deviceR.exists){
    const cached=(await CS.Store.get('clientSitesCache').catch(()=>({}))).clientSitesCache||[];
    await clearAllManagedUnlocked(cached,'This device was reset by an Admin. Open LogIn to re-authorize this device.').catch(()=>{});
    await CS.Store.set({clientResetLockVersion:controlReset}).catch(()=>{});
    return {ok:true,loggedIn:true,resetPending:true,deviceResetRequired:true};
  }

  // A brand-new/unclaimed Client is intentionally left alone here. Normal
  // login/bootstrap owns first registration and will create the claim atomically.
  if(!locallyBound && !claimR.exists && !deviceR.exists){
    return {ok:true,loggedIn:true,unclaimed:true};
  }

  const deviceId=String(identity?.deviceId||'');
  const claimId=String(claimR.data?.deviceId||'');
  const serverDeviceId=String(deviceR.data?.deviceId||'');
  const serverSubId=String(deviceR.data?.subadminUid||'');
  const deviceRevoked=String(deviceR.data?.status||'')==='revoked';

  if(
    !claimR.exists || !deviceR.exists ||
    !deviceId || claimId!==deviceId ||
    serverDeviceId!==deviceId || serverSubId!==subId || deviceRevoked
  ){
    // Reset Device updates the profile before deleting the device/claim rows.
    // If this control-plane poll began before the reset and finished after the
    // deletes, the first read can look exactly like an unauthorized device.
    // Re-read the profile (and once more after a tiny settling delay) before
    // treating the mismatch as a security event.
    let latestReset=Number(me.profile.deviceResetVersion||0);
    if(await explicitDeviceResetPending(me,localBinding))latestReset=Math.max(latestReset,Number(localBinding.resetVersion||0)+1);
    if(latestReset>Number(localBinding.resetVersion||0)){
      const cached=(await CS.Store.get('clientSitesCache').catch(()=>({}))).clientSitesCache||[];
      await clearAllManagedUnlocked(cached,'This device was reset by an Admin. Open LogIn to re-authorize this device.').catch(()=>{});
      await CS.Store.set({clientResetLockVersion:latestReset}).catch(()=>{});
      return {ok:true,loggedIn:true,resetPending:true,deviceResetRequired:true};
    }

    // One short re-read also covers the tiny commit window between the
    // profile update and the claim/device deletes, without making the normal
    // control-plane loop slow.
    await CS.Util.sleep(200);
    const [retryClaim,retryDevice,retryProfile]=await Promise.all([
      CS.Firebase.getDoc(['deviceClaims',uid],me.session.idToken).catch(()=>({exists:false,data:null})),
      CS.Firebase.getDoc(['devices',uid],me.session.idToken).catch(()=>({exists:false,data:null})),
      CS.Firebase.getDoc(['users',uid],me.session.idToken).catch(()=>({exists:false,data:null}))
    ]);
    const retryReset=Math.max(latestReset,Number(retryProfile?.data?.deviceResetVersion||0));
    if(retryReset>Number(localBinding.resetVersion||0)){
      const cached=(await CS.Store.get('clientSitesCache').catch(()=>({}))).clientSitesCache||[];
      await clearAllManagedUnlocked(cached,'This device was reset by an Admin. Open LogIn to re-authorize this device.').catch(()=>{});
      await CS.Store.set({clientResetLockVersion:retryReset}).catch(()=>{});
      return {ok:true,loggedIn:true,resetPending:true,deviceResetRequired:true};
    }
    const retryOk=
      retryClaim?.exists && retryDevice?.exists &&
      String(retryClaim.data?.deviceId||'')===deviceId &&
      String(retryDevice.data?.deviceId||'')===deviceId &&
      String(retryDevice.data?.subadminUid||'')===subId &&
      String(retryDevice.data?.status||'')!=='revoked';
    if(retryOk){
      return {ok:true,loggedIn:true,authorized:true,reconciled:true};
    }

    let deviceKey=`device:${uid}`;
    if(deviceId)deviceKey+=`:${deviceId}`;
    const reason=deviceRevoked
      ? 'This device has been revoked.'
      : 'This account is no longer authorized on this Chrome device.';
    await CS.Security.securityWipe({key:deviceKey,reason,warningKind:'device'}).catch(()=>{});
    const cached=(await CS.Store.get('clientSitesCache').catch(()=>({}))).clientSitesCache||[];
    await clearAllManagedUnlocked(cached,reason).catch(()=>{});
    await CS.Auth.logout().catch(()=>{});
    return {ok:false,loggedIn:false,deviceBlocked:true,error:reason};
  }
  const controlProxy=Number(controlState.proxyVersion||0);
  const serverProxyVersion=Number(deviceR.data?.lastProxyVersion||0);
  const resetPending=controlReset>localReset;
  // A proxy rotation advances resetVersion as a session-safety signal. Let the
  // normal proxy path process that rotation instead of incorrectly blocking the
  // already-authorized device here. The server device record is authoritative
  // for the last proxy version, so this does not depend on a local cache hit.
  const proxyRotationPending=resetPending &&
    serverDeviceId===deviceId &&
    controlProxy>serverProxyVersion;

  if(resetPending && !proxyRotationPending){
    const marker=await CS.Store.get('clientResetLockVersion').catch(()=>({}));
    if(Number(marker.clientResetLockVersion||0)!==controlReset){
      const cached=(await CS.Store.get('clientSitesCache').catch(()=>({}))).clientSitesCache||[];
      await clearAllManagedUnlocked(cached,'This device was reset by an Admin. Open LogIn to re-authorize this device.').catch(()=>{});
      await CS.Store.set({clientResetLockVersion:controlReset}).catch(()=>{});
    }
    return {ok:true,loggedIn:true,resetPending:true,deviceResetRequired:true};
  }

  // The control-plane poll is also the client-side signal for a remote Admin
  // proxy rotation. Do not wait for the user to open the popup. Once the
  // published proxy version moves beyond the version recorded on this device,
  // run the normal client proxy path immediately. That path applies/tests the
  // new proxy and, when it detects a real rotation, performs the full browser
  // refresh: clear cookies/site data/cache/history, restore the newest shared
  // cookies, close existing tabs and show chrome-refreshed.html automatically.
  // Cookie sync is kept inside that one-time rotation refresh; this branch does
  // not start any periodic cookie synchronization.
  if(proxyRotationPending || controlProxy>serverProxyVersion){
    const rotation=await clientStep({
      forceProxyTest:true,
      freshSync:false,
      deferProxyTest:false,
      allowDeviceReset:false,
      syncCookies:false,
      forceSites:true,
      preferCachedProxyHealth:false
    }).catch(e=>({ok:false,error:e?.message||String(e)}));
    return {
      ok:true,
      loggedIn:true,
      authorized:rotation?.ok!==false,
      proxyRotationTriggered:true,
      proxyRotationResult:rotation
    };
  }

  // Refresh navigation settings on the existing one-minute control-plane
  // cadence, with no cookie sync, proxy reapplication or browser cleanup.
  const before=await CS.Store.get(['clientWebsiteAccess','networkLockdown','clientSitesCache','clientSitesCacheSubadminUid']).catch(()=>({}));
  const current=typeof loadWebsiteAccess==='function' ? await loadWebsiteAccess(me,{force:true}) : {allowAll:false,domains:[]};
  // After device verification, reconcile the navigation rules once per
  // EXISTING control-plane tick. The previous implementation compared cached
  // policy objects but couldn't detect Chrome rules lost/overwritten after
  // login or a browser restart. Never unlock a failed proxy/security gate.
  if(before.networkLockdown===false &&
     before.clientSitesCacheSubadminUid===String(me.profile.subadminUid||'') &&
     Array.isArray(before.clientSitesCache)){
    await CS.Rules.applyNavigationPolicy(before.clientSitesCache,{locked:false,testEnabled:false}).catch(()=>{});
  }
  return {ok:true,loggedIn:true,authorized:true};
}

async function loadSites(me,{force=false}={}){
  const sub=String(me.profile.subadminUid||'').trim();
  if(!sub)throw new Error('This client account has no assigned Admin Extension.');
  const local=await CS.Store.get(['clientSitesCache','clientSitesCacheAt','clientSitesCacheSubadminUid']).catch(()=>({}));
  const age=Date.now()-Number(local.clientSitesCacheAt||0);
  if(!force && local.clientSitesCacheSubadminUid===sub && age>=0 && age<10000 && Array.isArray(local.clientSitesCache)){
    return local.clientSitesCache;
  }

  let sites=[];
  // Main Admin-created clients inherit every currently active website of their
  // assigned Admin Extension. The list is refreshed explicitly by login or
  // Fresh Sync, and is briefly cached for background/proxy recovery runs.
  if(me.profile.visibleToSubadmin===false){
    const docs=await CS.Firebase.queryDocsByField(['sites'],'subadminUid','EQUAL',sub,me.session.idToken);
    sites=docs
      .filter(d=>d.data?.active!==false&&d.data?.enabled!==false)
      .map(d=>({id:d.id,...d.data}))
      .sort((a,b)=>String(a.name||a.hostname).localeCompare(String(b.name||b.hostname)));
  }else{
    let siteIds=[];
    try{
      const access=await CS.Firebase.getDoc(['clientAccess',me.session.uid],me.session.idToken);
      if(access.exists&&Array.isArray(access.data?.siteIds))siteIds=access.data.siteIds.map(String);
    }catch{}
    if(!siteIds.length&&Array.isArray(me.profile.siteIds))siteIds=me.profile.siteIds.map(String);
    if(!siteIds.length&&me.profile.siteId)siteIds=[String(me.profile.siteId)];
    sites=(await Promise.all(siteIds.map(async siteId=>{
      const r=await CS.Firebase.getDoc(['sites',siteId],me.session.idToken).catch(()=>({exists:false}));
      if(!r.exists||r.data?.active===false||r.data?.enabled===false)return null;
      if(String(r.data?.subadminUid||'')!==sub)return null;
      return{id:siteId,...r.data};
    }))).filter(Boolean);
  }
  await CS.Store.set({clientSitesCache:sites,clientSitesCacheAt:Date.now(),clientSitesCacheSubadminUid:sub}).catch(()=>{});
  return sites;
}

async function loadWebsiteAccess(me,{force=false}={}){
  const uid=String(me?.session?.uid||'');
  const sub=String(me?.profile?.subadminUid||'');
  const empty={allowAll:false,domains:[]};
  if(!uid||!sub)return empty;
  const stored=await CS.Store.get(['clientWebsiteAccess','clientWebsiteAccessAt','clientWebsiteAccessUid','clientWebsiteAccessSub']).catch(()=>({}));
  const matches=stored.clientWebsiteAccessUid===uid && stored.clientWebsiteAccessSub===sub;
  const old=matches && stored.clientWebsiteAccess ? stored.clientWebsiteAccess : empty;
  // No cross-account policy carryover when another client signs into Chrome.
  if(!matches)await CS.Store.set({clientWebsiteAccess:empty,clientWebsiteAccessUid:uid,clientWebsiteAccessSub:sub,clientWebsiteAccessAt:0});
  const age=Date.now()-Number(stored.clientWebsiteAccessAt||0);
  if(!force && matches && age>=0 && age<15000)return old;
  try{
    const url=`${CS.CONFIG.supabaseUrl.replace(/\/$/,'')}/rest/v1/website_access_settings?subadmin_id=eq.${encodeURIComponent(sub)}&select=allow_all_websites,whitelist`;
    const rows=await CS.Firebase.request(url,{
      headers:{Authorization:`Bearer ${me.session.idToken}`},timeoutMs:8000
    });
    const row=Array.isArray(rows)?rows[0]:null;
    const domains=Array.isArray(row?.whitelist)?row.whitelist.filter(x=>typeof x==='string').slice(0,100):[];
    const policy={allowAll:row?.allow_all_websites===true,domains};
    await CS.Store.set({clientWebsiteAccess:policy,clientWebsiteAccessAt:Date.now(),clientWebsiteAccessUid:uid,clientWebsiteAccessSub:sub,clientWebsiteAccessError:''});
    return policy;
  }catch(e){
    // Failed DB/migration/network fetch must never create an allow-all policy.
    // Retain last verified settings for this client; never inherit another user's.
    await CS.Store.set({clientWebsiteAccessError:String(e?.message||e||'Website settings unavailable').slice(0,300)}).catch(()=>{});
    return old;
  }
}

async function clearAllManagedUnlocked(sites, reason, warningKind='device'){
  const message=String(reason||'Access locked.');
  await CS.Store.set({
    clientLockReason:message,
    clientProxyHealth:{ok:false,ip:null,reason:message,checkedAt:Date.now()}
  }).catch(()=>{});
  for(const site of sites||[]) await CS.Cookies.clearOrigin(site).catch(()=>{});
  await CS.Rules.applyNavigationPolicy(sites||[],{locked:true,testEnabled:false,warningKind}).catch(()=>{});
}
async function clearAllManaged(sites, reason){
  return withBrowserOperation(()=>clearAllManagedUnlocked(sites,reason));
}

globalThis.clearAllManaged = clearAllManaged;


async function openSuspendedPage(){
  const url=chrome.runtime.getURL('suspended.html');
  try{
    const tabs=await chrome.tabs.query({});
    const existing=tabs.find(t=>String(t?.url||'')===url);
    if(Number.isInteger(existing?.id) && existing.id>=0){
      await chrome.tabs.update(existing.id,{active:true}).catch(()=>{});
      return existing.id;
    }
    // Create the suspension page BEFORE any tab cleanup. Keeping this tab alive
    // guarantees Chrome has a tab/window left to display the suspension notice.
    const tab=await chrome.tabs.create({url,active:true});
    return tab?.id ?? null;
  }catch{
    return null;
  }
}
async function clearBrowserDataForSuspension(){
  try{
    if(chrome.browsingData?.remove){
      await chrome.browsingData.remove({}, {
        appcache:true,
        cache:true,
        cacheStorage:true,
        cookies:true,
        fileSystems:true,
        formData:true,
        history:true,
        indexedDB:true,
        localStorage:true,
        serviceWorkers:true,
        webSQL:true
      });
    }
  }catch{}
}

async function closeAllTabsForSuspension(keepTabId){
  if(!Number.isInteger(keepTabId) || keepTabId<0) return false;
  try{
    const tabs=await chrome.tabs.query({});
    const ids=tabs
      .map(t=>Number(t?.id))
      .filter(Number.isInteger)
      .filter(id=>id>=0 && id!==Number(keepTabId));
    // Remove every other tab, but NEVER remove the suspension page. This avoids
    // closing the last browser tab/window and leaving Chrome itself closed.
    for(const id of ids){
      await chrome.tabs.remove(id).catch(()=>{});
    }
    await chrome.tabs.update(Number(keepTabId),{active:true}).catch(()=>{});
    return true;
  }catch{
    return false;
  }
}

async function setSuspensionNetworkLock(reason='Account suspended.'){
  const message=String(reason||'Account suspended.');
  // This durable marker must be set before any pending proxy/health/sync DNR
  // update finishes. All navigation policies now honor it until a verified
  // live unsuspend clears it.
  await CS.Store.set({
    clientSuspendedReason:message,
    clientProxyHealth:{ok:false,ip:null,reason:message,checkedAt:Date.now()}
  });
  await CS.Rules.applyNavigationPolicy([],{locked:true,testEnabled:false,warningKind:'suspended'});
}

async function enforceClientSuspensionUnlocked(reason='Account suspended.'){
  const local=await CS.Store.get(['clientSuspensionLock']).catch(()=>({}));
  // Restore the actual network block every time. The completion marker only
  // deduplicates the destructive browsing-data wipe, not access enforcement.
  await setSuspensionNetworkLock(reason);
  await CS.Proxy.clear().catch(()=>{});
  if(local.clientSuspensionLock===true){
    // Remove any ordinary tabs left open by a Chrome restart or by a delayed
    // suspension, without repeatedly erasing the user's browser history.
    const tabs=await chrome.tabs.query({}).catch(()=>[]);
    if(tabs.some(t=>/^https?:\/\//i.test(String(t?.url||'')))){
      const suspensionTabId=await openSuspendedPage();
      if(Number.isInteger(suspensionTabId)&&suspensionTabId>=0){
        await closeAllTabsForSuspension(suspensionTabId);
      }
    }
    return {suspended:true,alreadyEnforced:true};
  }
  const suspensionTabId=await openSuspendedPage();
  if(!Number.isInteger(suspensionTabId) || suspensionTabId<0)return {suspended:true,alreadyEnforced:false};
  await clearBrowserDataForSuspension();
  await closeAllTabsForSuspension(suspensionTabId);
  await chrome.tabs.update(Number(suspensionTabId),{active:true}).catch(()=>{});
  await CS.Store.set({clientSuspensionLock:true}).catch(()=>{});
  return {suspended:true,alreadyEnforced:false};
}

async function enforceClientSuspension(reason='Account suspended.'){
  // Lock networking immediately, even when an unrelated browser operation
  // is still running. Browser cleanup is serialized separately.
  await setSuspensionNetworkLock(reason);
  return withBrowserOperation(()=>enforceClientSuspensionUnlocked(reason));
}


// Fast path used when the client popup has already confirmed suspension.
// The popup does not wait for browser cleanup; it tells the service worker
// immediately so the existing suspension enforcement starts without waiting
// for the next periodic control-plane alarm.
async function activateSuspensionImmediately(reason='Account suspended.'){
  // A popup message can originate from an old cached status. Reconfirm the
  // current account and assigned Admin before clearing Chrome data/tabs.
  return checkClientSuspension({enforce:true});
}

globalThis.enforceClientSuspension=enforceClientSuspension;

async function checkClientSuspension({enforce=true}={}){
  const s=await CS.Auth.session(true).catch(()=>null);
  if(!s?.uid)return {ok:true,loggedIn:false,suspended:false};
  try{
    const me=await CS.Auth.currentProfile(true);
    if(!me)return {ok:true,loggedIn:false,suspended:false};
    if(me.profile?.role!=='client')return {ok:true,loggedIn:true,suspended:false,profile:me.profile};
    if(me.profile?.active===false){
      const r=enforce?await enforceClientSuspension('Account suspended.'):null;
      return {ok:true,loggedIn:true,suspended:true,profile:me.profile,...(r||{})};
    }
    const sub=await getSubStatus(me,{force:true});
    if(sub?.active===false){
      const r=enforce?await enforceClientSuspension('Account suspended.'):null;
      return {ok:true,loggedIn:true,suspended:true,profile:me.profile,...(r||{})};
    }
    await CS.Store.remove(['clientSuspensionLock','clientSuspendedReason']).catch(()=>{});
    return {ok:true,loggedIn:true,suspended:false,profile:me.profile};
  }catch(e){
    if(e?.code==='ACCOUNT_SUSPENDED'){
      const r=enforce?await enforceClientSuspension('Account suspended.'):null;
      return {ok:true,loggedIn:true,suspended:true,profile:e.profile||null,...(r||{})};
    }
    throw e;
  }
}

async function getDeviceBinding(){
  const r=await CS.Store.get(['deviceBindingUid','deviceBindingId','deviceBindingResetVersion']);
  return {
    uid:String(r.deviceBindingUid||''),
    deviceId:String(r.deviceBindingId||''),
    resetVersion:Number(r.deviceBindingResetVersion||0)
  };
}

async function rememberDeviceBinding(uid,deviceId,resetVersion){
  await CS.Store.set({
    deviceBindingUid:String(uid||''),
    deviceBindingId:String(deviceId||''),
    deviceBindingResetVersion:Number(resetVersion||0)
  });
}

async function explicitDeviceResetPending(me,binding){
  const uid=String(me?.session?.uid||'');
  if(!uid||String(binding?.uid||'')!==uid||!String(binding?.deviceId||''))return false;

  // Prefer the freshly fetched profile value, but use the current profile first
  // so the common case stays cheap. This helper is used immediately before any
  // background path could create/rewrite a device record, closing the race where
  // Admin Reset Device happens while a clientStep is already in flight.
  let resetVersion=Number(me?.profile?.deviceResetVersion||0);
  if(resetVersion<=Number(binding.resetVersion||0)){
    try{
      const freshProfile=await CS.Firebase.getDoc(['users',uid],me.session.idToken);
      if(freshProfile?.exists&&freshProfile?.data){
        resetVersion=Math.max(resetVersion,Number(freshProfile.data.deviceResetVersion||0));
      }
    }catch{}
  }
  return resetVersion>Number(binding.resetVersion||0);
}

// Only the websites assigned to this client are bookmarked on a newly
// authorized device. Use the validated managed-site origins, not a guessed
// hostname or the single cached recovery destination.
async function ensureManagedSiteBookmarks(sites,profile){
  if(!chrome.bookmarks?.getTree || !chrome.bookmarks?.create || !chrome.bookmarks?.search)return false;
  const targets=new Map();
  for(const site of Array.isArray(sites)?sites:[]){
    const target=CS.Recovery.assignedDestination([site],profile);
    if(!target || targets.has(target.url))continue;
    targets.set(target.url,{
      url:target.url,
      title:String(site.name||site.hostname||target.hostname).trim()||target.hostname
    });
  }
  if(!targets.size)return true;
  try{
    const roots=await chrome.bookmarks.getTree();
    const bar=roots?.[0]?.children?.find(node=>node?.id==='1' || node?.title==='Bookmarks bar');
    let complete=true;
    for(const target of targets.values()){
      try{
        const existing=await chrome.bookmarks.search({url:target.url});
        if(Array.isArray(existing) && existing.some(bookmark=>bookmark.url===target.url))continue;
        await chrome.bookmarks.create({parentId:bar?.id||'1',title:target.title,url:target.url});
      }catch{complete=false;}// One bad entry must not prevent the remaining bookmarks.
    }
    return complete;
  }catch{return false;}
}

async function ensureFirstRegistrationSetup(deviceResult,sites,profile,{openWelcome=true}={}){
  if(!deviceResult?.newlyRegistered)return;
  await ensureManagedSiteBookmarks(sites,profile).catch(()=>{});

  // Show the welcome page only once for the first successful device
  // registration. It opens as a normal browser tab and never as a popup.
  const session=await CS.Auth.raw().catch(()=>null);
  const uid=String(session?.uid||'');
  if(!uid)return;
  const flagKey=`firstRegistrationWelcomeShown:${uid}`;
  const existing=await CS.Store.get(flagKey).catch(()=>({}));
  if(existing[flagKey]||!openWelcome)return;
  try{
    // Set the durable one-time marker BEFORE opening the tab.  Multiple
    // startup/login paths can otherwise observe the missing marker at the
    // same time and each open a second welcome page.
    await CS.Store.set({[flagKey]:Date.now()});
    await chrome.tabs.create({url:chrome.runtime.getURL('welcome.html'),active:true});
  }catch{}
}

function syncScopeHostname(hostname){
    return CS.Util.scopeHostname(hostname);
  }
function managedUrlForSites(url, sites){
  try{
    const u=new URL(String(url||''));
    if(!['http:','https:'].includes(u.protocol)) return false;
    return (sites||[]).some(s=>s && CS.Util.hostnameMatches(syncScopeHostname(s.hostname),u.hostname));
  }catch{return false;}
}
async function saveProxyRecoveryState(patch={}){
  const r=await CS.Store.get('proxyRecoveryState').catch(()=>({}));
  const prev=r.proxyRecoveryState||{};
  const sameIncident=prev.active===true;
  const next={
    active:true,
    startedAt:sameIncident ? (Number(prev.startedAt)||Date.now()) : Date.now(),
    attempts:sameIncident ? (Number(prev.attempts)||0) : 0,
    lastError:sameIncident ? String(prev.lastError||'') : '',
    confirmedFailed:false,
    ...patch
  };
  await CS.Store.set({proxyRecoveryState:next,clientProxyHealth:{ok:false,pending:true,ip:null,reason:String(next.lastError||'Reconnecting to proxy…'),checkedAt:Date.now()}}).catch(()=>{});
  return next;
}
async function beginProxyRecovery(reason){
  const sites=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
  await saveProxyRecoveryState({lastError:String(reason||'Proxy connection interrupted.')});
  await CS.Store.remove(['clientLockReason']).catch(()=>{});
  // Proxy recovery must not replace the real managed page with an extension
  // waiting screen or a security warning. Keep the normal managed-site
  // navigation policy active so Chrome itself can continue loading through the
  // proxy and show its native error page if the proxy cannot connect.
  await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:true}).catch(()=>{});
  ensureProxyHealthAlarm().catch(()=>{});
  if(!proxyRecoveryPromise) setTimeout(()=>recoverProxyInBackground().catch(()=>{}),0);
}
async function confirmProxyFailure(reason){
  const sites=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
  const message=String(reason||'Proxy could not be restored after repeated checks.');
  await CS.Store.set({
    proxyRecoveryState:{active:false,confirmedFailed:true,startedAt:Date.now(),attempts:PROXY_RECOVERY_MAX_ATTEMPTS,lastError:message},
    clientProxyHealth:{ok:false,pending:false,ip:null,reason:message,checkedAt:Date.now()}
  }).catch(()=>{});
  // A failed proxy is still a normal browser-network failure. Do not fail
  // closed with an extension page; leave the managed site request on Chrome's
  // normal path so the browser shows its native connection/proxy error.
  await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:true}).catch(()=>{});
}
async function recoverProxyInBackground(){
  if(proxyRecoveryPromise)return proxyRecoveryPromise;
  const existing=await CS.Store.get('proxyRecoveryState').catch(()=>({}));
  if(existing.proxyRecoveryState?.active!==true && existing.proxyRecoveryState?.confirmedFailed!==true)return null;
  proxyRecoveryPromise=(async()=>{
    proxyRecoveryRunning=true;
    try{
      let lastReason='Proxy is not working.';
      for(let i=0;i<PROXY_RECOVERY_MAX_ATTEMPTS;i++){
        if(i) await CS.Util.sleep(PROXY_RECOVERY_DELAYS[i]||1500);
        const state=await saveProxyRecoveryState({attempts:i,lastError:lastReason});
        if(Date.now()-Number(state.startedAt||Date.now())>30000)break;
        try{
          const result=await clientStep({forceProxyTest:true,freshSync:false,deferProxyTest:false,allowDeviceReset:false,recoveryAttempt:true,syncCookies:false});
          if(result?.health?.ok===true){
            await CS.Store.set({proxyRecoveryState:{active:false,confirmedFailed:false,startedAt:state.startedAt,attempts:i+1,lastError:''},clientProxyHealth:{...result.health,pending:false}}).catch(()=>{});
            return result;
          }
          lastReason=String(result?.health?.reason||result?.error||'Proxy is not working.');
        }catch(e){ lastReason=String(e?.message||e||lastReason); }
      }
      await confirmProxyFailure(lastReason);
      return{ok:true,proxyFailed:true,health:{ok:false,pending:false,reason:lastReason}};
    }finally{
      proxyRecoveryRunning=false;
      proxyRecoveryPromise=null;
    }
  })();
  return proxyRecoveryPromise;
}
async function lockForProxyFailure(reason){
  await beginProxyRecovery(reason);
}

async function ensureProxyRotationCleanupAlarm(){
  if(!chrome.alarms?.create)return;
  try{await chrome.alarms.create(PROXY_ROTATION_CLEANUP_ALARM,{delayInMinutes:0.5});}catch{}
}

async function cleanupAfterProxyRotation(subadminId,proxyVersion,options={}){
  const sub=String(subadminId||'');
  const version=Number(proxyVersion||0);
  if(!sub || !version)return{ok:true};
  const rotationCloseKey=`proxyRotationTabsClosed:${sub}`;
  const rotationClearKey=`proxyRotationDataCleared:${sub}`;
  const pendingKey='proxyRotationCleanupPending';
  const local=await CS.Store.get([rotationCloseKey,rotationClearKey,pendingKey]).catch(()=>({}));

  // A proxy rotation is a full browser-session reset. Reuse the same cleanup
  // path used by the explicit Chrome Refresh action: clear cookies/site data,
  // cache, browsing history and related web storage, restore the newest shared
  // cookie snapshot, then replace the open tabs with the normal
  // "Your Chrome has been refreshed" confirmation page.
  //
  // This function runs inside the existing browser-operation queue, so it must
  // call the unlocked variant directly rather than nesting withBrowserOperation().
  const dataClearedVersion=Number(local[rotationClearKey]||0);
  if(dataClearedVersion<version){
    let clearError='';
    let refreshResult=null;
    for(let attempt=0;attempt<2;attempt++){
      try{
        refreshResult=await refreshChromeForClientUnlocked({remoteAdmin:true,profileRefresh:true,existingDeviceOnly:options.existingDeviceOnly===true});
        clearError='';
        break;
      }catch(e){
        clearError=String(e?.message||e||'Browser refresh failed.');
        if(attempt===0)await CS.Util.sleep(750);
      }
    }
    if(clearError){
      await CS.Store.set({[pendingKey]:{subadminUid:sub,version,phase:'browser-refresh',lastError:clearError,updatedAt:Date.now()}}).catch(()=>{});
      await ensureProxyRotationCleanupAlarm();
      return{ok:false,phase:'browser-refresh',reason:clearError};
    }
    await CS.Store.set({
      [rotationCloseKey]:version,
      [rotationClearKey]:version
    }).catch(()=>{});
    await CS.Store.remove([pendingKey]).catch(()=>{});
    return{ok:true,version,tabsClosedVersion:version,dataClearedVersion:version,sync:refreshResult?.sync||null};
  }

  await CS.Store.remove([pendingKey]).catch(()=>{});
  return{ok:true,version,tabsClosedVersion:Number(local[rotationCloseKey]||version),dataClearedVersion};
}

async function ensureDevice(me,{fast=false,allowDeviceReset=false}={}){
  const uid=String(me.session.uid);
  let identity=await CS.Crypto.deviceIdentityForAccount(uid);

  // Reset Device is a server-side operation that updates the client profile
  // and then removes the durable device records. A background clientStep can
  // already be in flight when that happens. Before an unclaimed account is
  // allowed to create/recreate a device claim, re-read the profile and make
  // sure a newer explicit device-reset version has not appeared since this
  // browser was last bound. This closes the reset-vs-background-startup race
  // without changing proxy-rotation behavior (proxy rotations do not modify
  // profile.deviceResetVersion).
  if(!allowDeviceReset){
    const binding=await getDeviceBinding().catch(()=>null);
    if(await explicitDeviceResetPending(me,binding)){
      const e=new Error('This device was reset by an Admin. Open LogIn to re-authorize this device.');
      e.code='DEVICE_RESET_PENDING';
      throw e;
    }
  }

  // Proxy recovery is a local retry loop. Reuse a recently validated device
  // record instead of hitting Supabase for the immutable claim + device
  // document on every retry. Normal login/startup/device-gate remains remote-
  // verified, and the recovery path still re-reads control/reset metadata.
  if(fast){
    const local=await CS.Store.get(['clientDeviceCache','clientDeviceCacheAt','clientDeviceCacheUid']).catch(()=>({}));
    const age=Date.now()-Number(local.clientDeviceCacheAt||0);
    const d=local.clientDeviceCache;
    if(local.clientDeviceCacheUid===uid && d &&
       age>=0 && age<15000 &&
       String(d.deviceId||'')===String(identity.deviceId||'') &&
       String(d.subadminUid||'')===String(me.profile.subadminUid||'') &&
       d.status!=='revoked'){
      return{device:d,identity};
    }
  }

  // deviceClaims is an immutable server-side claim. Unlike the old design,
  // deleting/missing /devices/{uid} can never silently make another Chrome
  // installation the owner of an already-claimed account.
  const claim=await CS.Firebase.getDoc(['deviceClaims',uid],me.session.idToken);
  const existing=await CS.Firebase.getDoc(['devices',uid],me.session.idToken);
  identity=await CS.Crypto.deviceIdentityForAccount(
    uid,String(claim.data?.deviceId||existing.data?.deviceId||''),
    {preserveLocalBinding:false}
  );

  if(claim.exists){
    const claimedId=String(claim.data?.deviceId||'');
    if(!claimedId || claimedId!==String(identity.deviceId||'')){
      const e=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
      e.code='DEVICE_ALREADY_CLAIMED';
      throw e;
    }

    // A claim without a device record is an inconsistent/partially reset state.
    // Recreate only with the exact claimed device identity; never allow a new
    // installation to take over the account.
    if(!existing.exists){
      const doc={
        uid,
        subadminUid:me.profile.subadminUid,
        deviceId:identity.deviceId,
        status:'active',
        extensionVersion:CS.CONFIG.version,
        lastSeenAt:CS.Util.now(),
        lastProxyVersion:0,lastResetVersion:0,lastSyncVersion:0,
        lastSyncVersionBySite:{},lastSyncAt:'',lastIp:'',proxyHealthy:false,
        claimedAt:claim.data?.claimedAt||CS.Util.now()
      };
      try{ await CS.Firebase.createDoc(['devices',uid],doc,me.session.idToken); await cacheDevice(doc); return{device:doc,identity,newlyRegistered:true}; }
      catch(e){
        const fresh=await CS.Firebase.getDoc(['devices',uid],me.session.idToken);
        if(!fresh.exists) throw e;
        if(String(fresh.data?.deviceId||'')!==String(identity.deviceId)){
          const x=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
          x.code='DEVICE_ALREADY_CLAIMED'; throw x;
        }
        return validateExisting(fresh.data,identity,me);
      }
    }

    return validateExisting(existing.data,identity,me);
  }

  // Legacy migration: an existing device record is authoritative. Only that
  // exact device can create the immutable claim.
  if(existing.exists){
    if(String(existing.data?.deviceId||'')!==String(identity.deviceId||'')){
      const e=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
      e.code='DEVICE_ALREADY_CLAIMED'; throw e;
    }
    await createClaimOrValidate(identity,existing.data);
    return validateExisting(existing.data,identity,me);
  }

  // Truly unclaimed account. Creating the claim is atomic in Supabase, so if
  // two Chrome installations race, exactly one becomes the owner.
  const claimDoc={uid,deviceId:identity.deviceId,claimedAt:CS.Util.now(),status:'claimed'};
  try{
    await CS.Firebase.createDoc(['deviceClaims',uid],claimDoc,me.session.idToken);
  }catch(e){
    const fresh=await CS.Firebase.getDoc(['deviceClaims',uid],me.session.idToken);
    if(!fresh.exists) throw e;
    if(String(fresh.data?.deviceId||'')!==String(identity.deviceId||'')){
      const x=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
      x.code='DEVICE_ALREADY_CLAIMED'; throw x;
    }
  }

  const doc={
    uid,subadminUid:me.profile.subadminUid,deviceId:identity.deviceId,status:'active',
    extensionVersion:CS.CONFIG.version,lastSeenAt:CS.Util.now(),
    lastProxyVersion:0,lastResetVersion:0,lastSyncVersion:0,lastSyncVersionBySite:{},
    lastSyncAt:'',lastIp:'',proxyHealthy:false,claimedAt:claimDoc.claimedAt
  };
  try{
    await CS.Firebase.createDoc(['devices',uid],doc,me.session.idToken);
    await cacheDevice(doc);
    return{device:doc,identity,newlyRegistered:true};
  }catch(e){
    const fresh=await CS.Firebase.getDoc(['devices',uid],me.session.idToken);
    if(!fresh.exists) throw e;
    return validateExisting(fresh.data,identity,me);
  }

  async function createClaimOrValidate(ident,d){
    const claimData={uid,deviceId:ident.deviceId,claimedAt:d.claimedAt||CS.Util.now(),status:'claimed'};
    try{await CS.Firebase.createDoc(['deviceClaims',uid],claimData,me.session.idToken);}
    catch(e){
      const fresh=await CS.Firebase.getDoc(['deviceClaims',uid],me.session.idToken);
      if(!fresh.exists) throw e;
      if(String(fresh.data?.deviceId||'')!==String(ident.deviceId||'')){
        const x=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
        x.code='DEVICE_ALREADY_CLAIMED'; throw x;
      }
    }
  }

  async function cacheDevice(d){
    if(!d)return;
    await CS.Store.set({
      clientDeviceCache:d,
      clientDeviceCacheAt:Date.now(),
      clientDeviceCacheUid:uid
    }).catch(()=>{});
  }

  async function validateExisting(d,ident,user){
    if(String(d?.deviceId||'')!==String(ident?.deviceId||'')){
      const e=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
      e.code='DEVICE_ALREADY_CLAIMED'; throw e;
    }
    if(String(d?.subadminUid||'')!==String(user.profile.subadminUid||'')){
      const e=new Error('Device assignment does not match this account.'); e.code='DEVICE_ASSIGNMENT_MISMATCH'; throw e;
    }
    if(d.status==='revoked'){
      const e=new Error('This device has been revoked. Use Reset Device before signing in again.'); e.code='DEVICE_REVOKED'; throw e;
    }
    await cacheDevice(d);
    return{device:d,identity:ident};
  }
}
async function deviceGate(){
  const me=await CS.Auth.currentProfile(true);
  if(!me) return {ok:false,loggedIn:false};
  if(me.profile?.role!=='client') throw new Error('This account is not a client account.');
  if(me.profile?.active===false) return {ok:true,suspended:true,profile:me.profile};

  const sub=await getSubStatus(me,{force:true});
  if(sub.active===false) return {ok:true,suspended:true,profile:me.profile};

  const sites=await loadSites(me,{force:true});
  if(!sites.length) return {ok:true,profile:me.profile,sites,waitingForSite:true,locked:true};

  const device=await ensureDevice(me);
  if(device.resetRequired) return {ok:true,profile:me.profile,sites,waitingForDevice:true,locked:true,deviceReset:true};
  await ensureFirstRegistrationSetup(device,sites,me.profile);

  await CS.Store.set({clientSitesCache:sites});
  return {ok:true,loggedIn:true,profile:me.profile,sites,device:device.device};
}

function clientProxyIdentity(raw){
  const p=CS.Proxy.normalize(raw);
  if(p.mode==='unconfigured')return '';
  // Chrome's effective proxy API does not expose the authenticated proxy
  // username/password, so including credentials here makes the same proxy
  // look different on every startup. That caused the client to treat every
  // popup/startup as a new proxy rotation and reopen proxy-setup.html.
  // Rotation identity is therefore based on the actual connection endpoint.
  return JSON.stringify([p.mode,p.scheme,p.host,Number(p.port)]);
}
function effectiveProxyDoc(eff){
  const sp=eff?.value?.mode==='fixed_servers' ? eff.value?.rules?.singleProxy : null;
  if(!sp?.host || !Number(sp.port))return null;
  return {mode:'fixed_servers',scheme:String(sp.scheme||'http').toLowerCase(),host:String(sp.host||'').trim(),port:Number(sp.port),username:'',password:''};
}
function usableProxyDoc(d){
  if(!d || d.mode==='direct' || d.enabled===false) return false;
  return !!String(d.host||'').trim() && Number.isInteger(Number(d.port)) && Number(d.port)>0;
}
function proxyDocRank(d){
  const version=Number(d?.version||0);
  const updated=Date.parse(d?.updatedAt||'') || 0;
  const checked=Date.parse(d?.lastCheckedAt||'') || 0;
  return [version, updated, checked];
}
function pickProxyDoc(docs){
  const usable=docs.filter(usableProxyDoc);
  usable.sort((a,b)=>{
    const ar=proxyDocRank(a), br=proxyDocRank(b);
    for(let i=0;i<ar.length;i++) if(br[i]!==ar[i]) return br[i]-ar[i];
    if(Boolean(b.healthy)!==Boolean(a.healthy)) return Number(b.healthy)-Number(a.healthy);
    return 0;
  });
  return usable[0]||null;
}
async function getControl(me,{force=false}={}){
  const subId=String(me.profile.subadminUid||'').trim();
  if(!subId)throw new Error('This client account has no assigned Admin Extension.');

  const local=await CS.Store.get([
    'clientControlCache','clientControlCacheAt','clientControlCacheSubadminUid',
    'lastSavedProxyConfig','lastSavedProxySubadminUid'
  ]).catch(()=>({}));
  const age=Date.now()-Number(local.clientControlCacheAt||0);
  if(!force && local.clientControlCacheSubadminUid===subId && age>=0 && age<10000 && local.clientControlCache){
    return local.clientControlCache;
  }

  const stateR=await CS.Firebase.getDoc(['users',subId,'control','state'],me.session.idToken).catch(()=>({exists:false,data:null}));
  const controlState=stateR.exists&&stateR.data?stateR.data:{};
  const stateProxyVersion=Number(controlState.proxyVersion||0);
  const stateResetVersion=Number(controlState.resetVersion||0);

  let serverProxy=null;
  let proxySource='';
  const cachedUsable=
    local.lastSavedProxySubadminUid===subId &&
    usableProxyDoc(local.lastSavedProxyConfig)
      ? local.lastSavedProxyConfig : null;
  const cachedVersion=Number(cachedUsable?.version||0);
  const cachedProxyAge=Date.now()-Number(local.lastSavedProxyConfigAt||0);
  const cachedProxyFresh=Number.isFinite(cachedProxyAge) && cachedProxyAge>=0 && cachedProxyAge<60000;

  // If our local canonical proxy is at least as new as the control version,
  // use it for a short period to avoid redundant reads. After that, re-check
  // the canonical document even if control/state has not advanced, which keeps
  // the client robust when a proxy write succeeds but its advisory version
  // update lags or fails.
  if(cachedUsable && cachedVersion>=stateProxyVersion && cachedProxyFresh){
    serverProxy=cachedUsable;
    proxySource='cache';
  }else{
    const nested=await CS.Firebase.getDoc(['users',subId,'proxy','config'],me.session.idToken).catch(()=>({exists:false,data:null}));
    if(nested.exists){
      if(usableProxyDoc(nested.data)){serverProxy=nested.data;proxySource='canonical';}
    }else{
      const legacy=await CS.Firebase.getDoc(['subadminProxyConfigs',subId],me.session.idToken).catch(()=>({exists:false,data:null}));
      if(usableProxyDoc(legacy.data)){serverProxy=legacy.data;proxySource='legacy';}
    }
  }

  if(serverProxy){
    const normalized={...serverProxy,mode:'fixed_servers'};
    const result={
      state:{...controlState,proxyVersion:Math.max(stateProxyVersion,Number(normalized.version||0)),resetVersion:Math.max(stateResetVersion,Number(normalized.resetVersion||0),Number(me.profile.deviceResetVersion||0))},
      proxy:normalized,
      proxySource
    };
    await CS.Store.set({
      lastSavedProxyConfig:normalized,
      lastSavedProxyConfigAt:Date.now(),
      lastSavedProxySubadminUid:subId,
      clientControlCache:result,
      clientControlCacheAt:Date.now(),
      clientControlCacheSubadminUid:subId
    }).catch(()=>{});
    return result;
  }

  const cachedFallback=local.lastSavedProxySubadminUid===subId&&local.lastSavedProxyConfig?local.lastSavedProxyConfig:null;
  const fallback={
    state:{...controlState,proxyVersion:Math.max(stateProxyVersion,Number(cachedFallback?.version||0)),resetVersion:Math.max(stateResetVersion,Number(me.profile.deviceResetVersion||0),Number(cachedFallback?.resetVersion||0))},
    proxy:cachedFallback ? {...cachedFallback,mode:'unconfigured',healthy:false,ip:'',lastError:'Saved proxy data is unavailable or incomplete.'} : {mode:'unconfigured',healthy:false,ip:'',lastError:'Proxy is not configured.'},
    proxySource:''
  };
  await CS.Store.set({clientControlCache:fallback,clientControlCacheAt:Date.now(),clientControlCacheSubadminUid:subId}).catch(()=>{});
  return fallback;
}
async function getSyncKey(me){
  return CS.Sync.getGroupKey(me.profile.subadminUid,me.session.idToken);
}
async function applyLatestSnapshots(me,sites,key,device,controlState,{fresh=false,syncOnly=false}={}){
  let next={...device}, applied=0, newest=Number(device.lastSyncVersion||0), newestReset=Number(device.lastResetVersion||0), cookieFailures=0;
  const appliedSiteIds=[];
  const diagnostics=[];
  const proxyVersion=Number(controlState?.proxyVersion||0);
  const resetVersion=Number(controlState?.resetVersion||0);

  for(const site of sites){
    const r=await CS.Firebase.getDoc(['sites',site.id,'sync','latest'],me.session.idToken);
    if(!r.exists||!r.data?.envelope){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'missing'});
      continue;
    }

    // `admin-refresh-users` is a control signal carried by the same snapshot
    // row, but the row still contains the latest valid encrypted cookie
    // envelope. The refresh flow clears the browser first and then calls
    // syncLatestCookiesUnlocked({fresh:true}); that sync must be allowed to apply this
    // envelope or the refresh would leave the clean browser without cookies.
    // The separate checkManualShareOpen() path still owns the actual refresh
    // command handling/page flow; this function is only responsible for
    // restoring the snapshot itself.
    const ver=Number(r.data.version||0);
    if(!fresh && ver<=Number(device.lastSyncVersionBySite?.[site.id]||0)){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'already-applied',version:ver});
      continue;
    }

    // Normal client lifecycle keeps the existing proxy/reset safety gates.
    // The dedicated cookie-sync path intentionally does not: the snapshot is
    // already authorized by the client's site assignment + shared sync key,
    // and cookie restoration must not depend on a proxy health check.
    if(!syncOnly && Number(r.data.requiredProxyVersion||0)!==proxyVersion){
      diagnostics.push({
        siteId:site.id,hostname:site.hostname,status:'proxy-version-mismatch',
        snapshotProxyVersion:Number(r.data.requiredProxyVersion||0),clientProxyVersion:proxyVersion
      });
      continue;
    }

    const snapshotResetVersion=Number(r.data.requiredResetVersion||0);
    if(!syncOnly && snapshotResetVersion<resetVersion){
      diagnostics.push({
        siteId:site.id,hostname:site.hostname,status:'stale-reset-snapshot',
        snapshotResetVersion,clientResetVersion:resetVersion
      });
      continue;
    }

    // A malformed/legacy snapshot must never prevent the client from logging
    // in or syncing its other assigned sites. The Supabase compatibility layer
    // normalizes invalid TEXT envelopes to null; skip those snapshots safely.
    if(!r.data.envelope || typeof r.data.envelope!=='object'){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'invalid-snapshot'});
      continue;
    }

    let payload=null;
    try{
      payload=await CS.Crypto.decryptWithKey(r.data.envelope,key);
    }catch(e){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'invalid-snapshot',error:e?.message||String(e)});
      continue;
    }
    if(payload.siteId!==site.id){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'site-id-mismatch'});
      continue;
    }
    // During explicit cookie restoration, an empty envelope is not a logged-in
    // browser session. Keep it eligible for a later legitimate Admin share.
    if(syncOnly && (!Array.isArray(payload.cookies) || !payload.cookies.length)){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'missing',reason:'Snapshot has no cookies.'});
      continue;
    }

    let result;
    try{result=await CS.Cookies.reconcile(site,payload.cookies||[]);}
    catch(e){
      cookieFailures++;
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'invalid-snapshot',error:e?.message||String(e)});
      continue;
    }
    cookieFailures+=Number(result.failed||0);

    // A page that was already open before the snapshot arrived may have
    // started its request with the old cookies. Only mark the site for a
    // reload when at least one cookie was actually written.
    if(Number(result.set||0)>0) appliedSiteIds.push(String(site.id));

    // Leave failed snapshots unacknowledged so the next sync retries them.
    if(!Number(result.failed||0) && Number(result.set||0)>=(payload.cookies||[]).length){
      next.lastSyncVersionBySite={...(next.lastSyncVersionBySite||{}),[site.id]:ver};
      newest=Math.max(newest,ver);
      applied++;
      newestReset=Math.max(newestReset,snapshotResetVersion);
    }

    diagnostics.push({
      siteId:site.id,
      hostname:site.hostname,
      status:Number(result.failed||0) || Number(result.set||0)<(payload.cookies||[]).length?'partial':'applied',
      version:ver,
      cookies:Number(payload.cookies?.length||0),
      cookiesSet:Number(result.set||0),
      cookiesFailed:Number(result.failed||0)
    });
  }

  if(applied) next.lastSyncAt=CS.Util.now();
  next.lastSyncVersion=newest;
  if(!syncOnly) next.lastResetVersion=Math.max(newestReset,resetVersion);
  else next.lastResetVersion=Math.max(newestReset,Number(device.lastResetVersion||0));

  return{device:next,applied,cookieFailures,syncDiagnostics:diagnostics,appliedSiteIds:[...new Set(appliedSiteIds)]};
}

async function reloadManagedTabsAfterSync(sites, appliedSiteIds){
  const wanted=new Set((appliedSiteIds||[]).map(String));
  if(!wanted.size)return 0;
  let reloaded=0;
  try{
    const tabs=await chrome.tabs.query({});
    for(const tab of tabs){
      if(tab?.id==null || !/^https?:\/\//i.test(String(tab.url||'')))continue;
      const match=(sites||[]).find(site=>wanted.has(String(site.id)) && managedUrlForSites(tab.url,[site]));
      if(!match)continue;
      try{
        await chrome.tabs.reload(tab.id,{bypassCache:false});
        reloaded++;
      }catch{}
    }
  }catch{}
  return reloaded;
}

function stableDeviceSignature(d){
  const bySite={};
  for(const k of Object.keys(d?.lastSyncVersionBySite||{}).sort())bySite[k]=Number(d.lastSyncVersionBySite[k]||0);
  return JSON.stringify({
    uid:String(d?.uid||''),
    subadminUid:String(d?.subadminUid||''),
    deviceId:String(d?.deviceId||''),
    status:String(d?.status||''),
    extensionVersion:String(d?.extensionVersion||''),
    lastProxyVersion:Number(d?.lastProxyVersion||0),
    lastResetVersion:Number(d?.lastResetVersion||0),
    lastSyncVersion:Number(d?.lastSyncVersion||0),
    lastSyncVersionBySite:bySite,
    lastSyncAt:String(d?.lastSyncAt||''),
    lastIp:String(d?.lastIp||''),
    publicKey:String(d?.publicKey||'')
  });
}
async function persistDeviceIfMeaningful(me,previous,next){
  if(stableDeviceSignature(previous)===stableDeviceSignature(next))return false;
  await CS.Firebase.setDoc(['devices',me.session.uid],next,me.session.idToken);
  return true;
}

async function syncLatestCookiesUnlocked({fresh=false,reloadTabs=true,existingDeviceOnly=false}={}){
  let me=await CS.Auth.currentProfile(true);
  if(!me)return{ok:false,loggedIn:false};
  if(me.profile.role!=='client')throw new Error('This account is not a client account.');
  if(me.profile.active===false)return{ok:true,loggedIn:true,suspended:true};

  const sites=await loadSites(me,{force:true});
  if(!sites.length)return{ok:true,loggedIn:true,profile:me.profile,sites,applied:0};

  const scan=await CS.Security.scan(sites);
  if(scan.locked)return{ok:false,loggedIn:true,profile:me.profile,sites,locked:true,error:'Unauthorized Chrome extension detected.'};

  const key=await getSyncKey(me);
  if(!key)return{ok:true,loggedIn:true,profile:me.profile,sites,applied:0,received:0,error:'No synchronization key is available yet.'};

  // Fresh Sync is an explicit user action, but it must still honor the
  // durable one-device claim. The snapshot path used to trust only the
  // devices/{uid} document, which could let a second Chrome installation
  // continue with cookies if its UI reached Fresh Sync through a stale state.
  let deviceResult;
  if(existingDeviceOnly){
    const [claim,deviceDoc]=await Promise.all([
      CS.Firebase.getDoc(['deviceClaims',String(me.session.uid)],me.session.idToken),
      CS.Firebase.getDoc(['devices',String(me.session.uid)],me.session.idToken)
    ]);
    const identity=await CS.Crypto.deviceIdentityForAccount(
      String(me.session.uid),String(claim.data?.deviceId||deviceDoc.data?.deviceId||'')
    );
    const deviceId=String(identity?.deviceId||'');
    if(!claim.exists||!deviceDoc.exists||String(claim.data?.deviceId||'')!==deviceId||String(deviceDoc.data?.deviceId||'')!==deviceId||String(deviceDoc.data?.status||'')==='revoked'){
      const e=new Error('This device was reset before the browser refresh completed.');
      e.code='DEVICE_RESET_PENDING';
      throw e;
    }
    deviceResult={device:deviceDoc.data,identity};
  }else{
    deviceResult=await ensureDevice(me);
  }
  const device={...deviceResult.device};
  const r=await applyLatestSnapshots(
    me,sites,key,device,{},
    {fresh,syncOnly:true}
  );

  // Never reload an already-open page as part of Login/Fresh Sync. Cookie
  // injection completes in the background and the customer decides when to
  // refresh the website. This keeps both the client and managed site exactly
  // where the user left them. The proxy-rotation cleanup path remains separate.
  const reloadedTabs=0;

  const nextDevice={
    ...r.device,
    status:'active'
  };

  // Fresh Sync only writes the durable device record when the snapshot actually
  // advanced. Re-syncing an already-applied snapshot therefore causes zero
  // device writes.
  if(Number(r.applied||0)>0){
    await persistDeviceIfMeaningful(me,device,nextDevice).catch(()=>{});
    // A subsequent proxy-health check can return older device telemetry.
    // Retain the successful Chrome cookie-write timestamp for the popup.
    await CS.Store.set({
      clientVerifiedSyncUid:String(me.session.uid),
      clientVerifiedSyncAt:nextDevice.lastSyncAt
    }).catch(()=>{});
  }

  await CS.Store.set({
    clientLastState:{
      ip:nextDevice.lastIp||'',
      lastSyncAt:nextDevice.lastSyncAt||'',
      proxyHealthy:nextDevice.proxyHealthy===true,
      applied:r.applied,
      cookieFailures:r.cookieFailures,
      syncDiagnostics:r.syncDiagnostics
    }
  }).catch(()=>{});

  return{
    ok:true,
    loggedIn:true,
    profile:me.profile,
    sites,
    device:nextDevice,
    applied:r.applied,
    cookieFailures:r.cookieFailures,
    syncDiagnostics:r.syncDiagnostics,
    reloadedTabs
  };
}

async function syncLatestCookies(options={}){
  return withBrowserOperation(()=>syncLatestCookiesUnlocked(options));
}
async function installAndTestProxy(me,sites,control,{force=false,resetRequired=false}={}){
  const proxy=CS.Proxy.normalize(control.proxy);
  if(proxy.mode==='unconfigured') return {ok:false,ip:null,reason:'Proxy is not configured.'};
  await CS.Proxy.setActiveCredentials(proxy);await CS.Proxy.apply(proxy);
  // For a one-time check, temporarily allow the health endpoint as a top-level request.
  await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:true});
  if(!force&&!resetRequired) return {ok:control.proxy.healthy===true,ip:control.proxy.ip||null,reason:control.proxy.healthy===true?'Last saved proxy check is healthy.':(control.proxy.lastError||'Proxy is not working.')};
  return CS.Proxy.test(proxy);
}
function stateSafeBoolean(v){return v===true;}
async function runClientStep({forceProxyTest=false,freshSync=false,deferProxyTest=false,allowDeviceReset=false,recoveryAttempt=false,syncCookies=true,forceSites=false,suppressFirstWelcome=false,forceProfile=false,preferCachedProxyHealth=true}={}){
  let me=null;
  try{
    try{me=await CS.Auth.currentProfile(forceProfile===true);if(!me)me=await CS.Auth.currentProfile(true);}
    catch(e){
      if(e.code==='ACCOUNT_SUSPENDED'){
        const r=await enforceClientSuspensionUnlocked('Account suspended.');
        return{ok:true,loggedIn:true,suspended:true,error:'Account suspended.',...r};
      }
      if(e.code==='PROFILE_MISSING'){
        // A deleted profile invalidates the session; revoke old web access now.
        await enforceLoggedOutNetworkLock().catch(()=>{});
        return{ok:false,loggedIn:false,error:'Account profile is missing.'};
      }
      throw e;
    }

    if(!me){
      await enforceLoggedOutNetworkLock().catch(()=>{});
      return{ok:false,loggedIn:false};
    }
    if(me.profile.role!=='client'){
      await enforceLoggedOutNetworkLock().catch(()=>{});
      return{ok:false,loggedIn:false,unauthorizedRole:true};
    }

    const suspensionCache=await CS.Store.get(['clientSuspensionLock','clientSuspendedReason']).catch(()=>({}));
    const pendingSuspension=!!(suspensionCache.clientSuspensionLock || suspensionCache.clientSuspendedReason);
    const staleSuspendedProfile=me.profile.active===false;
    // Cached inactive profiles are not proof of *current* suspension. In
    // particular, an unsuspended client must not have tabs/history wiped again.
    if(staleSuspendedProfile || pendingSuspension){
      me=await CS.Auth.currentProfile(true);
      if(!me)return{ok:false,loggedIn:false};
    }
    if(me.profile.active===false){
      const r=await enforceClientSuspensionUnlocked('Account suspended.');
      return{ok:true,loggedIn:true,suspended:true,error:'Account suspended.',...r};
    }

    // An inactive cached Admin status can outlive an Admin's "Unsuspend"
    // click. Bypass the 15-second cache before any destructive enforcement.
    const verifiedSuspension=staleSuspendedProfile || pendingSuspension;
    let subStatus=await getSubStatus(me,{force:forceSites||verifiedSuspension});
    if(subStatus.active===false && !forceSites && !verifiedSuspension){
      subStatus=await getSubStatus(me,{force:true});
    }
    if(subStatus.active===false){
      const r=await enforceClientSuspensionUnlocked('Account suspended.');
      return{ok:true,loggedIn:true,suspended:true,error:'Account suspended.',...r};
    }
    // Clear the old local warning only after both statuses are verified live.
    if(pendingSuspension){
      await CS.Store.remove(['clientSuspensionLock','clientSuspendedReason']).catch(()=>{});
    }

    const previousSites=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
    const sites=await loadSites(me,{force:forceSites});
    const websiteAccess=typeof loadWebsiteAccess==='function' ? await loadWebsiteAccess(me,{force:forceSites}) : {allowAll:false,domains:[]};
    const activeIds=new Set(sites.map(s=>s.id));
    for(const oldSite of previousSites){
      if(!activeIds.has(oldSite.id))await CS.Cookies.clearOrigin(oldSite).catch(()=>{});
    }
    await CS.Store.set({clientSitesCache:sites});

    const scan=await CS.Security.scan(sites);
    if(scan.locked){
      await CS.Rules.applyNavigationPolicy(sites,{locked:true,testEnabled:false,warningKind:'extension'}).catch(()=>{});
      return{ok:false,loggedIn:true,profile:me.profile,sites,locked:true,error:'Unauthorized Chrome extension detected.'};
    }

    const origins=[...new Set(sites.flatMap(s=>{
      try{
        const u=new URL(s.origin);
        const scope=syncScopeHostname(u.hostname);
        return[
          `${u.origin}/*`,
          `https://${scope}/*`, `https://*.${scope}/*`,
          `http://${scope}/*`, `http://*.${scope}/*`
        ];
      }catch{return[]}
    }))];
    if(origins.length && !(await chrome.permissions.contains({origins}))){
      await CS.Rules.applyNavigationPolicy(sites,{locked:true,testEnabled:false,warningKind:'website'}).catch(()=>{});
      return{ok:true,loggedIn:true,profile:me.profile,sites,needsPermission:true};
    }

    if(!sites.length && !websiteAccess.allowAll && !websiteAccess.domains.length){
      await CS.Rules.applyNavigationPolicy([],{locked:true,testEnabled:false,warningKind:'website'});
      return{ok:true,loggedIn:true,profile:me.profile,sites,waitingForSite:true,locked:true,error:'No managed website is assigned yet.'};
    }

    // Read the published reset state BEFORE attempting to create/recreate a device claim.
    // This prevents a previously authorized browser from silently reclaiming the account
    // in the background immediately after an Admin presses Reset Device.
    // Capture the locally known/currently installed proxy BEFORE getControl().
    // getControl() refreshes lastSavedProxyConfig with the remote proxy, so this
    // snapshot must happen first in order to tell whether the incoming proxy is
    // actually different from the proxy currently in Chrome.
    const preControlLocal=await CS.Store.get(['lastSavedProxyConfig','lastSavedProxySubadminUid']).catch(()=>({}));
    const previousSavedProxy=
      String(preControlLocal.lastSavedProxySubadminUid||'')===String(me.profile.subadminUid||'') &&
      usableProxyDoc(preControlLocal.lastSavedProxyConfig)
        ? preControlLocal.lastSavedProxyConfig : null;
    let installedProxyBefore=null;
    try{installedProxyBefore=effectiveProxyDoc(await CS.Proxy.effective());}catch{}

    const control=await getControl(me);
    const controlReset=Math.max(
      Number(control.state.resetVersion||0),
      Number(me.profile.deviceResetVersion||0)
    );
    const controlProxy=Number(control.state.proxyVersion||0);
    const binding=await getDeviceBinding();
    const cachedDeviceState=await CS.Store.get(['clientDeviceCache','clientDeviceCacheUid']).catch(()=>({}));
    const cachedDevice=cachedDeviceState.clientDeviceCache;
    const sameCachedDevice=
      String(cachedDeviceState.clientDeviceCacheUid||'')===String(me.session.uid) &&
      cachedDevice &&
      String(cachedDevice.deviceId||'')===String(binding.deviceId||'');
    // A newer resetVersion matters only to a device that was actually bound
    // before that reset. Keep this distinction separate from proxyVersion:
    // Admin proxy rotation advances both counters, but it must NOT turn a
    // normal proxy rotation into a device re-authorization prompt.
    const resetPendingForKnownDevice=
      String(binding.uid||'')===String(me.session.uid) &&
      !!String(binding.deviceId||'') &&
      controlReset > Number(binding.resetVersion||0);
    // A proxy rotation intentionally advances BOTH proxyVersion and
    // resetVersion. That reset is session-safety for the old proxy, not a
    // request to make the user click Sync Again. Allow the same already-bound
    // device to process that specific proxy rotation automatically. A reset
    // with no newer proxyVersion still requires explicit re-authorization.
    const proxyRotationPending =
      resetPendingForKnownDevice &&
      sameCachedDevice &&
      controlProxy > Number(cachedDevice?.lastProxyVersion||0);

    if(resetPendingForKnownDevice && !allowDeviceReset && !proxyRotationPending){
      const resetMarker=await CS.Store.get('clientResetLockVersion').catch(()=>({}));
      if(Number(resetMarker.clientResetLockVersion||0)!==controlReset){
        await clearAllManagedUnlocked(sites,'This device was reset by an Admin. Open Cookie Sync to re-authorize this device.').catch(()=>{});
        await CS.Store.set({clientResetLockVersion:controlReset}).catch(()=>{});
      }
      return{
        ok:true,loggedIn:true,profile:me.profile,sites,
        waitingForDevice:true,deviceResetRequired:true,locked:false,
        proxy:control.proxy,
        proxyFailed:false,
        error:'This device was reset by an Admin. Open Cookie Sync to re-authorize this device.',
        applied:0
      };
    }

    const deviceResult=await ensureDevice(me,{fast:recoveryAttempt,allowDeviceReset});
    await ensureFirstRegistrationSetup(deviceResult,sites,me.profile,{openWelcome:suppressFirstWelcome!==true});
    let device={...deviceResult.device};

    // A first-time device registration must NEVER be treated as a proxy
    // rotation.  Keep a short-lived local marker across any concurrent
    // startup/login/background clientStep calls so the initial application of
    // the currently published proxy cannot trigger the destructive rotation
    // cleanup or the DAT-setup welcome page.  Only a later Admin proxy change
    // should clear the browser session.
    const firstProxySetupKey=`clientFirstProxySetup:${String(me.session.uid||'')}`;
    const firstProxySetupState=(await CS.Store.get(firstProxySetupKey).catch(()=>({})))[firstProxySetupKey]||null;
    if(deviceResult.newlyRegistered){
      // Drop any stale rotation retry state before initializing a brand-new
      // device.  This prevents an old pending cleanup from appearing as a
      // false "new DAT setup" immediately after first registration.
      await CS.Store.remove([
        'proxyRotationCleanupPending',
        `proxyRotationTabsClosed:${String(me.profile.subadminUid||'')}`,
        `proxyRotationDataCleared:${String(me.profile.subadminUid||'')}`
      ]).catch(()=>{});
      await CS.Store.set({[firstProxySetupKey]:{
        proxyVersion:Number(controlProxy||0),
        startedAt:Date.now()
      }}).catch(()=>{});
    }
    const initialProxySetupPending = !!(
      firstProxySetupState &&
      Number(firstProxySetupState.proxyVersion||0)===Number(controlProxy||0)
    ) || deviceResult.newlyRegistered;

    // Keep a browser-local record of the proxy version that this exact
    // extension instance has successfully installed.  This is a safety
    // fallback for cases where a device telemetry write is delayed/denied;
    // otherwise the stale server lastProxyVersion can make the same proxy
    // look like a brand-new rotation every time the popup opens.
    const localProxyMarker=await CS.Store.get([
      'clientAppliedProxyVersion','clientAppliedProxySubadminUid','clientAppliedProxyIdentity'
    ]).catch(()=>({}));
    const localProxyVersion=
      String(localProxyMarker.clientAppliedProxySubadminUid||'')===String(me.profile.subadminUid||'')
        ? Number(localProxyMarker.clientAppliedProxyVersion||0) : 0;
    const localProxyIdentity=
      String(localProxyMarker.clientAppliedProxySubadminUid||'')===String(me.profile.subadminUid||'')
        ? String(localProxyMarker.clientAppliedProxyIdentity||'') : '';

    const previousProxyVersion=Math.max(
      Number(device.lastProxyVersion||0),
      localProxyVersion
    );
    const needReset=Number(device.lastResetVersion||0)<controlReset;
    const needProxy=previousProxyVersion<controlProxy;
    const hadPriorProxySession=previousProxyVersion>0 || !!String(device.lastIp||'').trim() || !!device.lastProxyCheckAt || !!previousSavedProxy || !!localProxyIdentity;

    // A rotation is based on the proxy that is actually installed, not on
    // whether the endpoint has ever appeared before. Returning to an older
    // proxy still counts as a rotation when the currently installed proxy is
    // different. Reusing the CURRENT proxy is the only no-cleanup case.
    const targetProxyIdentity=clientProxyIdentity(control.proxy);
    const installedProxyIdentity=installedProxyBefore ? clientProxyIdentity(installedProxyBefore) : '';
    const previousSavedProxyIdentity=previousSavedProxy ? clientProxyIdentity(previousSavedProxy) : '';
    const proxyDiffersFromInstalled=!!targetProxyIdentity && !!installedProxyIdentity && targetProxyIdentity!==installedProxyIdentity;
    const proxyDiffersFromSaved=!!targetProxyIdentity && !!previousSavedProxyIdentity && targetProxyIdentity!==previousSavedProxyIdentity;
    const proxyWasActuallyRotated=!initialProxySetupPending && !deviceResult.newlyRegistered && hadPriorProxySession && (proxyDiffersFromInstalled || (!installedProxyIdentity && proxyDiffersFromSaved));

    if(needReset||needProxy){
      device={...device,status:'resetting',proxyHealthy:false,lastIp:'',lastSyncAt:''};
      if(needReset && !needProxy) await clearAllManagedUnlocked(sites,'Preparing your browser for the latest session reset.');
    }

    if(!control.proxy || control.proxy.mode==='unconfigured'){
      const proxy={
        mode:'unconfigured',
        healthy:false,
        ip:'',
        lastError:'Proxy is not configured.'
      };
      await clearAllManagedUnlocked(
        sites,
        'Proxy is not configured. Contact your Admin Extension.',
        'website'
      ).catch(()=>{});
      // No proxy means the managed browser must fail closed. This is a
      // website-access issue, not evidence that the device was revoked.
      await CS.Rules.applyNavigationPolicy(sites,{locked:true,testEnabled:false,warningKind:'website'}).catch(()=>{});
      return{
        ok:true,
        loggedIn:true,
        profile:me.profile,
        sites,
        proxy,
        proxyFailed:true,
        locked:true,
        health:{ok:false,ip:null,reason:'Proxy is not configured.'},
        applied:0,
        newlyRegistered:!!deviceResult.newlyRegistered
      };
    }

    const proxy=CS.Proxy.normalize(control.proxy);
    try{
      await CS.Proxy.setActiveCredentials(proxy);
      await CS.Proxy.apply(proxy);
    }catch(e){
      // If Chrome rejects or loses the proxy configuration, immediately fail
      // closed before propagating the error. This prevents any direct-web
      // fallback window from being available to the managed browser. This
      // isn't a device-authorization error.
      await CS.Rules.applyNavigationPolicy(sites,{locked:true,testEnabled:false,warningKind:'website'}).catch(()=>{});
      throw e;
    }

    if(proxy.mode==='fixed_servers'){
      // Do not gate managed navigation while the proxy is being verified. The
      // real page request should go through the configured proxy immediately;
      // slow/failed connections are handled by Chrome's normal loading/error UI.
      await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:true});
    }

    let health=null;
    if(deferProxyTest && proxy.mode==='fixed_servers'){
      const cachedHealthState=await CS.Store.get(['clientProxyHealth','lastProxyHealthProxyIdentity']).catch(()=>({}));
      const cachedHealth=cachedHealthState.clientProxyHealth;
      const cachedAge=Date.now()-Number(cachedHealth?.checkedAt||0);
      const sameProxy=String(cachedHealthState.lastProxyHealthProxyIdentity||'')===clientProxyIdentity(proxy);
      const cacheFresh=preferCachedProxyHealth!==false && cachedHealth?.ok===true && cachedHealth?.pending!==true && sameProxy && cachedAge>=0 && cachedAge<=PROXY_HEALTH_CACHE_MAX_AGE_MS;
      if(!cacheFresh){
        if(allowDeviceReset || needReset){
          await rememberDeviceBinding(me.session.uid,device.deviceId,controlReset).catch(()=>{});
        }
        const pending={ok:false,pending:true,ip:null,reason:'Checking proxy…'};
        await CS.Store.set({
          clientProxyHealth:{ok:stateSafeBoolean(device.proxyHealthy),pending:true,ip:device.lastIp||null,reason:'Checking proxy…',checkedAt:Date.now()},
          clientLastState:{ip:device.lastIp||'',lastSyncAt:device.lastSyncAt||'',proxyHealthy:device.proxyHealthy===true}
        });
        return{ok:true,loggedIn:true,profile:me.profile,sites,proxy,device,health:pending,proxyChecking:true,applied:0,newlyRegistered:!!deviceResult.newlyRegistered};
      }
      health={...cachedHealth,pending:false,reason:cachedHealth.reason||'Proxy is working'};
    }
    if(!health)health=await CS.Proxy.test(proxy,{timeoutMs:PROXY_HEALTH_TIMEOUT_MS});

    if(!allowDeviceReset){
      const liveBinding=await getDeviceBinding().catch(()=>binding);
      if(await explicitDeviceResetPending(me,liveBinding)){
        const e=new Error('This device was reset by an Admin. Open LogIn to re-authorize this device.');
        e.code='DEVICE_RESET_PENDING';
        throw e;
      }
    }

    if(!health.ok){
      // Proxy failure is temporary/local runtime state. Do not persist it to
      // Supabase as device telemetry.
      device={...device,status:'proxy_error',proxyHealthy:false,lastSeenAt:CS.Util.now(),lastProxyCheckAt:CS.Util.now(),lastIp:health.ip||''};
      await lockForProxyFailure(health.reason||'Proxy is not working.');
      await CS.Store.set({
        clientLastState:{ip:health.ip||'',lastSyncAt:device.lastSyncAt||'',proxyHealthy:false},
        clientProxyHealth:{...health,pending:true,reason:health.reason||'Reconnecting to proxy…'}
      }).catch(()=>{});
      return{ok:true,loggedIn:true,profile:me.profile,sites,health:{...health,pending:true},proxyFailed:true,proxyChecking:true,device,applied:0,newlyRegistered:!!deviceResult.newlyRegistered};
    }

    // A profile-data wipe is for an actual proxy rotation, not first-time setup.
    // IMPORTANT: tab-closing and data-clearing are tracked separately. The old
    // implementation bundled them together, so if any later storage/device
    // update failed the next background health cycle could see the same proxy
    // version and repeat the browser cleanup. Rotation cleanup is idempotent: the
    // old tabs are replaced once per proxy version, while web data can be retried
    // without closing the browser or repeating tab cleanup.
    if(proxyWasActuallyRotated){
      const cleanup=await cleanupAfterProxyRotation(String(me.profile.subadminUid||''),controlProxy);
      if(!cleanup.ok){
        const cleanupReason=`New proxy connected, but browser cleanup is still pending: ${cleanup.reason||'Please wait while LogIn clears the previous browser session.'}`;
        await CS.Store.set({
          clientProxyHealth:{...health,pending:true,ip:health.ip||null,reason:cleanupReason,checkedAt:Date.now()},
          proxyRotationCleanupPending:{subadminUid:String(me.profile.subadminUid||''),version:controlProxy,phase:cleanup.phase||'browser-data',lastError:cleanup.reason||'',updatedAt:Date.now()}
        }).catch(()=>{});
        // Do not release managed navigation or apply fresh cookies until the
        // previous browser session has been fully cleared. The cleanup alarm
        // retries locally and will re-enter clientStep once successful.
        // A pending proxy refresh is not a revoked/unauthorized device.
        await CS.Rules.applyNavigationPolicy(sites,{locked:true,testEnabled:false,warningKind:'website'}).catch(()=>{});
        return{
          ok:true,loggedIn:true,profile:me.profile,sites,proxy,health:{...health,pending:true,reason:cleanupReason},
          proxyFailed:false,proxyChecking:true,proxyCleanupPending:true,device,applied:0,error:cleanupReason
        };
      }
    }

    await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:false});

    const key=syncCookies ? await getSyncKey(me) : '';
    let applied=0, cookieFailures=0, syncDiagnostics=[];
    if(syncCookies && key){
      const r=await applyLatestSnapshots(me,sites,key,device,control.state,{fresh:freshSync});
      device=r.device;
      applied=r.applied;
      cookieFailures=Number(r.cookieFailures||0);
      syncDiagnostics=r.syncDiagnostics||[];
    }

    const persistedBefore={...device};
    device={
      ...device,status:'active',proxyHealthy:true,
      lastProxyVersion:controlProxy,lastResetVersion:controlReset,
      lastSeenAt:CS.Util.now(),lastProxyCheckAt:CS.Util.now(),
      lastIp:health.ip||device.lastIp||''
    };
    if(!allowDeviceReset){
      const liveBinding=await getDeviceBinding().catch(()=>binding);
      if(await explicitDeviceResetPending(me,liveBinding)){
        const e=new Error('This device was reset by an Admin. Open LogIn to re-authorize this device.');
        e.code='DEVICE_RESET_PENDING';
        throw e;
      }
    }
    // Only meaningful device changes hit Supabase. Presence heartbeats remain
    // lightweight, while a real proxy/IP change is persisted once for Admin visibility.
    await persistDeviceIfMeaningful(me,persistedBefore,device).catch(()=>{});
    await rememberDeviceBinding(me.session.uid,device.deviceId,controlReset);
    await CS.Store.set({
      clientLastState:{
        ip:device.lastIp||'',
        lastSyncAt:device.lastSyncAt||'',
        proxyHealthy:true,
        applied,
        cookieFailures,
        syncDiagnostics
      },
      clientProxyHealth:{...health,pending:false},
      lastProxyHealthProxyIdentity:clientProxyIdentity(proxy)
    });
    await CS.Store.remove(['clientLockReason','clientSuspensionLock','clientResetLockVersion']).catch(()=>{});
    // A prior reset race may have left the unauthorized-device warning tab
    // active. Successful re-authorization makes that warning stale; remove it
    // so the next navigation/client-open cannot keep presenting the old page.
    await CS.Security.clearWarningTab().catch(()=>{});
    await CS.Store.set({proxyRecoveryState:{active:false,confirmedFailed:false,startedAt:Date.now(),attempts:0,lastError:''}}).catch(()=>{});
    // Mark the exact proxy version/identity that this browser has actually
    // installed.  This survives service-worker restarts and prevents a stale
    // server-side device telemetry row from repeating the DAT cleanup dialog.
    await CS.Store.set({
      lastSavedProxyConfig:proxy,
      lastSavedProxyConfigAt:Date.now(),
      lastSavedProxySubadminUid:String(me.profile.subadminUid||''),
      clientAppliedProxyVersion:controlProxy,
      clientAppliedProxySubadminUid:String(me.profile.subadminUid||''),
      clientAppliedProxyIdentity:clientProxyIdentity(proxy)
    }).catch(()=>{});
    // Initial device setup is complete only after the first proxy has passed
    // its health check and the normal client state has been persisted.
    if(initialProxySetupPending){
      await CS.Store.remove([firstProxySetupKey]).catch(()=>{});
    }

    return{ok:true,loggedIn:true,profile:me.profile,sites,proxy,health,device,applied,cookieFailures,syncDiagnostics,newlyRegistered:!!deviceResult.newlyRegistered};
  }catch(e){
    const message=String(e?.message||e||'Unexpected error');
    const cached=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
    const deviceError=['DEVICE_ALREADY_CLAIMED','DEVICE_ASSIGNMENT_MISMATCH','DEVICE_REVOKED','DEVICE_CLAIM_FAILED'].includes(String(e?.code||''));
    if(deviceError){
      // An account claim/device mismatch is a security event. Perform the same
      // full browser cleanup used for proxy rotation, once for this concrete
      // device identity, then keep the existing device-block/logout behavior.
      let deviceKey=`device:${String(me?.session?.uid||'unknown')}`;
      try{
        const ident=await CS.Crypto.deviceIdentityForAccount(String(me?.session?.uid||''));
        if(ident?.deviceId)deviceKey+=`:${String(ident.deviceId)}`;
      }catch{}
      await CS.Security.securityWipe({key:deviceKey,reason:message,warningKind:'device'}).catch(()=>{});
      await clearAllManagedUnlocked(cached,message).catch(()=>{});
      await CS.Auth.logout().catch(()=>{});
      return{ok:false,loggedIn:false,profile:null,deviceBlocked:true,error:message};
    }
    const isSecurityLock=/unauthorized chrome extension|profile locked/i.test(message);
    const isHardAccess=/account suspended|device registration|not assigned/i.test(message);
    if(isSecurityLock||isHardAccess){
      const kind=/account suspended/i.test(message)?'suspended'
        :isSecurityLock?'extension'
        :/not assigned/i.test(message)?'website':'device';
      await clearAllManagedUnlocked(cached,message,kind).catch(()=>{});
    }else if(/proxy/i.test(message)){
      await lockForProxyFailure(message).catch(()=>{});
    }
    return{
      ok:false,loggedIn:!!me,profile:me?.profile||null,
      proxyFailed:/proxy/i.test(message),
      locked:isSecurityLock,
      error:message
    };
  }
}

async function clientStep(options={}) {
  if (runningPromise) return runningPromise;
  runningPromise=withBrowserOperation(()=>runClientStep(options));
  try { return await runningPromise; } finally { runningPromise=null; }
}

CS.Proxy.installProxyErrorListener(async details=>{
  try{
    if(!details)return;
    const reason=`Proxy error: ${details.error||details.details||'Chrome reported a proxy error.'}`;
    // Record/recover the proxy problem, but never replace the tab with a
    // custom waiting page. Chrome should retain its normal loading/error UI.
    await lockForProxyFailure(reason);
  }catch{}
});

chrome.webNavigation?.onErrorOccurred?.addListener(async details=>{
  try{
    if(details.frameId!==0 || !details.url || !/^https?:\/\//i.test(details.url))return;
    const code=String(details.error||'').toUpperCase();
    const proxyish=/(ERR_(TUNNEL_CONNECTION_FAILED|PROXY_CONNECTION_FAILED|PROXY_AUTH_UNSUPPORTED|PROXY_AUTHENTICATION_FAILED|CONNECTION_TIMED_OUT|TIMED_OUT|CONNECTION_REFUSED)|PROXY|TUNNEL)/.test(code);
    if(!proxyish)return;
    const sites=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
    if(!managedUrlForSites(details.url,sites))return;
    const reason=`Browser reported ${details.error||'a proxy connection error.'}`;
    // Let Chrome own the navigation result. We only start background recovery.
    await beginProxyRecovery(reason);
  }catch{}
},{url:[{schemes:['http','https']}]});

let proxyHealthTickPromise=null;
async function proxyHealthTick(){
  if(proxyHealthTickPromise)return proxyHealthTickPromise;
  proxyHealthTickPromise=(async()=>{
    try{
      const s=await CS.Auth.raw().catch(()=>null);
      if(!s?.uid)return {ok:true,loggedIn:false};
      const state=await CS.Store.get(['lastSavedProxyConfig','proxyRecoveryState']).catch(()=>({}));
      const recovery=state.proxyRecoveryState||{};
      if(recovery.active===true || recovery.confirmedFailed===true){
        if(recovery.confirmedFailed===true && recovery.active!==true){
          await beginProxyRecovery(recovery.lastError||'Retrying proxy connection…').catch(()=>{});
        }
        await recoverProxyInBackground().catch(()=>{});
        return {ok:true,recovering:true};
      }
      const proxy=state.lastSavedProxyConfig ? CS.Proxy.normalize(state.lastSavedProxyConfig) : {mode:'unconfigured'};
      if(proxy.mode!=='fixed_servers')return {ok:true,proxyUnconfigured:true};
      const health=await CS.Proxy.test(proxy,{timeoutMs:PROXY_HEALTH_TIMEOUT_MS});
      await CS.Store.set({
        clientProxyHealth:{...health,pending:false,checkedAt:Date.now()},
        lastProxyHealthProxyIdentity:clientProxyIdentity(proxy)
      }).catch(()=>{});
      if(!health.ok){
        await beginProxyRecovery(health.reason||'Proxy is not working.');
        return {ok:true,proxyFailed:true,health};
      }
      return {ok:true,health};
    }catch(e){
      return {ok:false,error:String(e?.message||e||'Proxy health check failed.')};
    }finally{proxyHealthTickPromise=null;}
  })();
  return proxyHealthTickPromise;
}

async function applyCachedProxyImmediately(){
  try{
    const raw=await CS.Store.get(['lastSavedProxyConfig','activeProxyCredentials','clientProxyConfig']);
    const cached=raw.lastSavedProxyConfig||raw.clientProxyConfig||null;
    if(!cached || cached.mode==='unconfigured' || cached.enabled===false)return false;
    const proxy=CS.Proxy.normalize(cached);
    if(!proxy.host || !Number(proxy.port))return false;
    await CS.Proxy.setActiveCredentials(proxy);
    await CS.Proxy.apply(proxy);
    return true;
  }catch(e){
    await CS.Store.set({clientProxyHealth:{
      ok:false,pending:true,ip:null,reason:String(e?.message||e||'Proxy could not be applied.'),checkedAt:Date.now()
    }}).catch(()=>{});
    return false;
  }
}


async function applyLoggedOutNetworkLock(){
  // Fail closed for normal web browsing while the extension is logged out.
  // A fresh install has no authorized websites, NOT an unauthorized device.
  // Genuine device/extension warnings and explicit sign-out stay distinct.
  const bad=await CS.Security?.unauthorizedExtensions?.().catch(()=>[])||[];
  const local=await CS.Store.get(['warningKind','clientSignedOut','clientSuspensionLock','clientSuspendedReason']).catch(()=>({}));
  const kind=(local.clientSuspensionLock===true || !!local.clientSuspendedReason) ? 'suspended'
    : bad.length ? 'extension'
    : local.clientSignedOut===true ? 'signed-out'
    : local.warningKind==='device' ? 'device'
    : 'website';
  await CS.Rules.applyNavigationPolicy([],{locked:true,testEnabled:false,warningKind:kind}).catch(()=>{});
  await CS.Proxy.clear().catch(()=>{});
  return kind;
}

async function enforceLoggedOutNetworkLock(){
  const kind=await applyLoggedOutNetworkLock();
  // Existing managed tabs should show the same relevant page as future web
  // navigations. Never close the final tab or wipe data on mere installation.
  const local=await CS.Store.get('clientSitesCache').catch(()=>({}));
  const sites=Array.isArray(local.clientSitesCache)?local.clientSitesCache:[];
  const tabs=await chrome.tabs.query({url:['http://*/*','https://*/*']}).catch(()=>[]);
  const page=kind==='device'?'unauthorized-device.html'
    :kind==='extension'?'unauthorized-extension.html'
    :kind==='suspended'?'suspended.html'
    :kind==='signed-out'?'signed-out.html':'unauthorized-website.html';
  const redirect=chrome.runtime.getURL(page);
  // The DNR exception must also survive startup's existing-tab redirects.
  // Only general website/sign-out restrictions exempt this public website;
  // device, extension and suspension security pages always take priority.
  const publicWebsiteUrl=(url)=>{
    try{
      const parsed=new URL(String(url||''));
      const host=parsed.hostname.toLowerCase().replace(/\.$/,'');
      return ['http:','https:'].includes(parsed.protocol) &&
        (host==='veefivee.com'||host.endsWith('.veefivee.com'));
    }catch{return false;}
  };
  await Promise.all(tabs.filter(tab=>Number.isInteger(tab?.id)&&tab.id>=0)
    .filter(tab=>!(['website','signed-out'].includes(kind) && publicWebsiteUrl(tab.url)))
    .filter(tab=>!sites.length || managedUrlForSites(tab.url,sites))
    .map(tab=>chrome.tabs.update(tab.id,{url:redirect}).catch(()=>{})));
}

async function applyStartupNetworkGate(){
  const session=await CS.Auth.raw().catch(()=>null);
  if(!session?.uid){
    await applyLoggedOutNetworkLock();
  }
}
async function startup(){
  await applyStartupNetworkGate();
  // Enforce extension policy before login, before applying any cached proxy or
  // running the authenticated client lifecycle. No popup is required.
  const installedSession=await CS.Auth.raw().catch(()=>null);
  if(!installedSession?.uid){
    const bad=await CS.Security.unauthorizedExtensions().catch(()=>[]);
    if(bad.length){
      await CS.Rules.applyNavigationPolicy([],{locked:true,testEnabled:false,warningKind:'extension'}).catch(()=>{});
      await CS.Security.openPreLoginWarning().catch(()=>{});
      return;
    }
  }else{
    const scan=await CS.Security.scan([]).catch(()=>({ok:false}));
    if(scan.locked)return;
  }
  // Apply the last known proxy locally first. The proxy must not depend on
  // opening the popup or on a successful Supabase round-trip.
  try{await chrome.alarms?.clear?.('cookie-sync-latest-snapshot');}catch{}
  await applyCachedProxyImmediately();
  await ensureProxyHealthAlarm();
  await ensureManualShareOpenAlarm();
  await ensurePresenceHeartbeatAlarm();
  try{await chrome.alarms.clear(STATE_RECONCILIATION_ALARM);}catch{}
  try{await chrome.alarms.clear(SUSPENSION_CHECK_ALARM);}catch{}
  await ensureControlPlaneAlarm();

  const rec=(await CS.Store.get('proxyRecoveryState').catch(()=>({}))).proxyRecoveryState;
  if(rec?.active && !proxyRecoveryPromise)setTimeout(()=>recoverProxyInBackground().catch(()=>{}),0);

  // Supabase/auth reconciliation happens inside the normal client lifecycle;
  // a recent successful proxy check can be reused immediately.
  const existingSession=await CS.Auth.raw().catch(()=>null);
  if(existingSession?.uid){
    const marker=await CS.Store.get('clientLoginSessionStartedAt').catch(()=>({}));
    if(!Number(marker.clientLoginSessionStartedAt||0)){
      await CS.Store.set({clientLoginSessionStartedAt:Date.now()}).catch(()=>{});
      await CS.Store.remove(['clientVerifiedSyncAt','clientVerifiedSyncUid']).catch(()=>{});
    }
  }
  await clientStep({forceProxyTest:false,freshSync:false,syncCookies:false,preferCachedProxyHealth:true}).catch(()=>{});
}
// MV3 may terminate the worker while the popup is closed. If Chrome lost the
// persisted alarm, re-arm it whenever any extension event wakes the worker.
ensureControlPlaneAlarm().catch(()=>{});
chrome.runtime.onStartup.addListener(startup);
chrome.runtime.onInstalled.addListener(async(details)=>{if(details?.reason==='install'){await CS.Store.clear().catch(()=>{});await enforceLoggedOutNetworkLock();}await startup();});
chrome.alarms?.onAlarm?.addListener(async alarm=>{
  if(alarm?.name===CONTROL_PLANE_ALARM){
    const result=await controlPlaneTick().catch(e=>({ok:false,error:e?.message||String(e)}));
    // Record the last actual background check for troubleshooting without
    // touching the popup, cookie sync, proxy, or normal page navigation.
    await CS.Store.set({
      clientBackgroundAuthCheckedAt:Date.now(),
      clientBackgroundAuthResult:result?.suspended?'suspended':result?.deviceResetRequired?'device-reset':result?.deviceBlocked?'unauthorized-device':result?.profileMissing?'profile-missing':result?.controlCheckDeferred?'deferred':result?.ok===false?'error':result?.loggedIn===false?'logged-out':'authorized'
    }).catch(()=>{});
    return;
  }
  if(alarm?.name===PRESENCE_HEARTBEAT_ALARM){await sendPresenceHeartbeat().catch(()=>{});return;}
  if(alarm?.name===MANUAL_SHARE_OPEN_ALARM){await checkManualShareOpen().catch(()=>{});return;}
  if(alarm?.name!==PROXY_HEALTH_ALARM && alarm?.name!==PROXY_ROTATION_CLEANUP_ALARM)return;

  if(alarm?.name===PROXY_ROTATION_CLEANUP_ALARM){
    const pending=(await CS.Store.get('proxyRotationCleanupPending').catch(()=>({}))).proxyRotationCleanupPending;
    if(!(pending?.subadminUid && Number(pending.version)>0)){
      await chrome.alarms?.clear?.(PROXY_ROTATION_CLEANUP_ALARM).catch(()=>{});
      return;
    }
    const cleanup=await cleanupAfterProxyRotation(pending.subadminUid,Number(pending.version)).catch(e=>({ok:false,reason:e?.message||String(e)}));
    if(cleanup?.ok){
      await CS.Store.remove(['proxyRotationCleanupPending']).catch(()=>{});
      await chrome.alarms?.clear?.(PROXY_ROTATION_CLEANUP_ALARM).catch(()=>{});
      await CS.Store.set({clientProxyHealth:{ok:true,pending:false,ip:null,reason:'Browser session cleanup completed.',checkedAt:Date.now()}}).catch(()=>{});
      await clientStep({forceProxyTest:true,freshSync:false,deferProxyTest:false,syncCookies:false}).catch(()=>{});
    }else{
      await ensureProxyRotationCleanupAlarm();
    }
    return;
  }

  const r=await CS.Store.get('proxyRecoveryState').catch(()=>({}));
  if(r.proxyRecoveryState?.active===true || r.proxyRecoveryState?.confirmedFailed===true){
    if(r.proxyRecoveryState?.confirmedFailed===true && r.proxyRecoveryState?.active!==true) await beginProxyRecovery(r.proxyRecoveryState.lastError||'Retrying proxy connection…').catch(()=>{});
    await recoverProxyInBackground().catch(()=>{});
    return;
  }
  if(alarm?.name===PROXY_HEALTH_ALARM){
    await proxyHealthTick().catch(()=>{});
  }
});
async function enforceNewExtensionPolicy(){
  const bad=await CS.Security.unauthorizedExtensions().catch(()=>[]);
  if(!bad.length)return;
  const session=await CS.Auth.raw().catch(()=>null);
  if(!session?.uid){
    await CS.Rules.applyNavigationPolicy([],{locked:true,testEnabled:false,warningKind:'extension'}).catch(()=>{});
    await CS.Security.openPreLoginWarning().catch(()=>{});
    return;
  }
  await withBrowserOperation(async()=>{
    const s=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
    await CS.Security.lockdown(s,'Unauthorized Chrome extension detected').catch(()=>{});
  });
}
chrome.management.onInstalled.addListener(()=>enforceNewExtensionPolicy().catch(()=>{}));
chrome.management.onEnabled.addListener(()=>enforceNewExtensionPolicy().catch(()=>{}));

// A client that is actively using Chrome must not remain authorized solely
// because the periodic MV3 worker alarm went missing. These wake signals also
// re-check account suspension and device revocation, throttled to once per
// 30 seconds. The checks NEVER perform periodic cookie sync or page reloads.
let lastActivityAuthorizationCheckAt=0;
function onClientBrowserActivity(){
  sendPresenceHeartbeat().catch(()=>{});
  const now=Date.now();
  if(now-lastActivityAuthorizationCheckAt<30000)return;
  lastActivityAuthorizationCheckAt=now;
  ensureControlPlaneAlarm().catch(()=>{});
  controlPlaneTick().catch(()=>{});
}
chrome.tabs?.onActivated?.addListener(onClientBrowserActivity);
chrome.webNavigation?.onCommitted?.addListener(details=>{
  if(details?.frameId===0)onClientBrowserActivity();
});

async function verifyCurrentDeviceAuthorization(){
  try{
    const session=await CS.Auth.session(true).catch(()=>null);
    const profile=await CS.Auth.cached().catch(()=>null);
    if(!session?.uid||!session?.idToken||!profile||profile.role!=='client'||profile.active===false)return false;

    const [claim,device,state]=await Promise.all([
      CS.Firebase.getDoc(['deviceClaims',String(session.uid)],session.idToken).catch(()=>({exists:false,data:null})),
      CS.Firebase.getDoc(['devices',String(session.uid)],session.idToken).catch(()=>({exists:false,data:null})),
      profile.subadminUid
        ? CS.Firebase.getDoc(['users',String(profile.subadminUid),'control','state'],session.idToken).catch(()=>({exists:false,data:null}))
        : Promise.resolve({exists:false,data:null})
    ]);

    const identity=await CS.Crypto.deviceIdentityForAccount(
      String(session.uid),String(claim.data?.deviceId||device.data?.deviceId||'')
    );
    const deviceId=String(identity?.deviceId||'');
    if(!deviceId)return false;
    if(!claim.exists||!device.exists)return false;
    if(String(claim.data?.deviceId||'')!==deviceId)return false;
    if(String(device.data?.deviceId||'')!==deviceId)return false;
    if(String(device.data?.subadminUid||'')!==String(profile.subadminUid||''))return false;
    if(String(device.data?.status||'')==='revoked')return false;

    const controlReset=Math.max(
      Number(state.data?.resetVersion||0),
      Number(profile.deviceResetVersion||0)
    );
    if(Number(device.data?.lastResetVersion||0)<controlReset)return false;

    return true;
  }catch{return false;}
}

// Stage only the current, assigned and decryptable snapshots before the login
// cleanup. A second Supabase fetch after browsingData.remove() is not reliable
// enough to be the only chance to restore website cookies.
async function stageAuthorizedLoginSnapshots(){
  const me=await CS.Auth.currentProfile(true);
  if(!me?.session?.uid || me.profile?.role!=='client' || me.profile?.active===false)return [];
  const sites=await loadSites(me,{force:true});
  if(!sites.length)return [];
  const key=await getSyncKey(me);
  if(!key)return [];
  const staged=[];
  for(const site of sites){
    try{
      const latest=await CS.Firebase.getDoc(['sites',site.id,'sync','latest'],me.session.idToken);
      if(!latest.exists || !latest.data?.envelope || typeof latest.data.envelope!=='object')continue;
      const payload=await CS.Crypto.decryptWithKey(latest.data.envelope,key);
      if(String(payload?.siteId)!==String(site.id) || !Array.isArray(payload.cookies))continue;
      staged.push({site,cookies:payload.cookies,version:Number(latest.data.version||0)});
    }catch{} // Still fall back to the existing post-cleanup fetch/retry path.
  }
  return staged;
}

async function restoreStagedLoginSnapshots(staged){
  const diagnostics=[];
  let applied=0,cookieFailures=0;
  for(const item of Array.isArray(staged)?staged:[]){
    try{
      const r=await CS.Cookies.reconcile(item.site,item.cookies);
      const failed=Number(r.failed||0);
      cookieFailures+=failed;
      // An empty snapshot must not count as a restored login session.
      const ok=!failed && item.cookies.length>0 && Number(r.set||0)>=item.cookies.length;
      if(ok)applied++;
      diagnostics.push({siteId:item.site.id,hostname:item.site.hostname,
        status:failed || (item.cookies.length>0 && Number(r.set||0)<item.cookies.length)?'partial':ok?'applied':'missing',version:item.version,
        cookies:item.cookies.length,cookiesSet:Number(r.set||0),cookiesFailed:failed});
    }catch(e){
      cookieFailures++;
      diagnostics.push({siteId:item.site.id,hostname:item.site.hostname,
        status:'invalid-snapshot',error:String(e?.message||e)});
    }
  }
  return {ok:true,applied,cookieFailures,syncDiagnostics:diagnostics};
}

// A login is complete only when EVERY assigned website has a non-empty,
// successfully written snapshot. A single restored site is not enough.
function loginCookiesFullyRestored(sync, assignedSites){
  if(!sync?.ok || sync.error || sync.suspended || sync.locked || sync.deviceBlocked || sync.needsPermission ||
     Number(sync.cookieFailures||0)>0)return false;
  const expected=Array.isArray(assignedSites)?assignedSites:[];
  const diagnostics=Array.isArray(sync.syncDiagnostics)?sync.syncDiagnostics:[];
  if(!expected.length || !diagnostics.length)return false;
  return expected.every(site=>diagnostics.some(d=>
    String(d.siteId)===String(site.id) && d.status==='applied' &&
    Number(d.cookies||0)>0 && Number(d.cookiesSet||0)>=Number(d.cookies||0) &&
    Number(d.cookiesFailed||0)===0
  ));
}

// The pre-cleanup staging path used to apply cookies successfully but NEVER
// recorded a sync time. Persist once the complete login restoration succeeds,
// using the exact account/device already authorized by clientStep.
async function recordCompletedLoginCookieSync(sync, options){
  const me=await CS.Auth.currentProfile(false);
  if(!me?.session?.uid || me.profile?.role!=='client')throw new Error('Login authorization was lost during cookie restoration.');
  const uid=String(me.session.uid);
  const now=CS.Util.now();
  const prior=options.authorizedDevice || sync.device || {};
  const bySite={...(prior.lastSyncVersionBySite||{})};
  let version=Number(prior.lastSyncVersion||0);
  for(const d of sync.syncDiagnostics||[]){
    if(d.status!=='applied')continue;
    bySite[d.siteId]=Number(d.version||0);
    version=Math.max(version,Number(d.version||0));
  }
  const device={...prior,lastSyncAt:now,lastSyncVersion:version,lastSyncVersionBySite:bySite};
  // Store the verified timestamp independently: a later proxy-health response
  // may contain older device telemetry and must not erase a real login sync.
  await CS.Store.set({
    clientVerifiedSyncUid:uid,clientVerifiedSyncAt:now,
    clientLastState:{
      ip:device.lastIp||'',lastSyncAt:now,
      proxyHealthy:device.proxyHealthy===true,
      applied:sync.applied,cookieFailures:0,syncDiagnostics:sync.syncDiagnostics
    }
  });
  // Keep the backend Last sync consistent with manual Fresh Sync. Use the
  // CURRENT device document, not a stale deferred-proxy state, so we never
  // overwrite a newer reset, claim, proxy status, or IP with old telemetry.
  try{
    const remote=await CS.Firebase.getDoc(['devices',uid],me.session.idToken);
    if(remote?.exists && remote.data && String(remote.data.deviceId||'')===String(device.deviceId||'') &&
       String(remote.data.subadminUid||'')===String(me.profile.subadminUid||'') &&
       String(remote.data.status||'')!=='revoked'){
      const current=remote.data;
      const remoteVersions={...(current.lastSyncVersionBySite||{}),...bySite};
      await CS.Firebase.setDoc(['devices',uid],{
        ...current,lastSyncAt:now,
        lastSyncVersion:Math.max(Number(current.lastSyncVersion||0),version),
        lastSyncVersionBySite:remoteVersions
      },me.session.idToken);
    }
  }catch{} // Local verified timestamp is authoritative until telemetry recovers.
  return {...sync,device,lastSyncAt:now};
}

async function refreshChromeForClientUnlocked(options={}){
  // Match the older working client: obtain the authorized snapshot BEFORE
  // clearing Chrome, so restoring login cookies never depends on fetching a
  // second copy immediately after a destructive browser reset.
  // Keep decrypted snapshots only in this service-worker invocation's memory.
  let stagedLoginSnapshots=[];
  if(options.afterLogin){
    stagedLoginSnapshots=await stageAuthorizedLoginSnapshots().catch(()=>[]);
    await CS.Cookies.clearAllBrowserData();
  }else{
    await chrome.browsingData.remove({}, {
      cache:true,cacheStorage:true,cookies:true,fileSystems:true,formData:true,
      history:true,indexedDB:true,localStorage:true,serviceWorkers:true,webSQL:true
    });
  }

  let sync=null;
  if(options.afterLogin){
    // Restore the pre-cleared snapshot first; this is the direct equivalent of
    // the successful legacy login's first Fresh Sync, but after full cleanup.
    if(stagedLoginSnapshots.length){
      sync=await restoreStagedLoginSnapshots(stagedLoginSnapshots);
    }
    const stagedComplete=sync?.applied>0 && Number(sync.cookieFailures||0)===0 &&
      (sync.syncDiagnostics||[]).every(d=>d.status==='applied');

    // If nothing was staged or one snapshot was incomplete, fall back to the
    // same Fresh Sync API used by the existing manual button. Never require
    // every assigned website to have a snapshot before allowing sign-in;
    // the legacy working client did not have this extra login-only gate.
    if(!stagedComplete){
      for(let attempt=0;attempt<2;attempt++){
        let current;
        try{
          current=await syncLatestCookiesUnlocked({fresh:true,reloadTabs:false});
        }catch(e){
          if(String(e?.code||'')==='DEVICE_RESET_PENDING')throw e;
          current={ok:false,error:e?.message||String(e)};
        }
        if(current?.suspended || current?.locked || current?.deviceBlocked){
          return{ok:false,sync:current,error:current.error||'Account authorization was withdrawn.'};
        }
        // Keep successfully restored cookies even if a later remote fetch
        // fails; never turn a good staged result into a false login error.
        if(!sync || Number(current?.applied||0)>=Number(sync?.applied||0))sync=current;
        if(current?.ok && Number(current.applied||0)>0)break;
        if(attempt===0)await CS.Util.sleep(350);
      }
    }

    if(Number(sync?.applied||0)>0 && (sync.syncDiagnostics||[]).some(d=>
      d.status==='applied' && Number(d.cookiesSet||0)>0 && Number(d.cookiesFailed||0)===0)){
      // Record a real cookie write, never a merely non-empty server response.
      // This also keeps Last sync visible when a newer health check returns
      // stale device telemetry. Device/reset and proxy fields are preserved.
      sync=await recordCompletedLoginCookieSync(sync,options);
    }
    // Missing/partial cookies are sync problems, not invalid credentials.
    // Preserve the older working behavior: allow the authorized session and
    // welcome page, with a truthful retry/partial status if needed.
    if(!sync)sync={ok:false,applied:0,error:'No shared login snapshot was available.'};
  }else if(options.remoteAdmin || options.manualFix){
    sync=await syncLatestCookiesUnlocked({fresh:true,reloadTabs:false,existingDeviceOnly:options.existingDeviceOnly===true});
  }

  const targetPage=options.afterLogin?'welcome.html':'chrome-refreshed.html';
  const params=new URLSearchParams();
  if(options.remoteAdmin)params.set('remote','1');
  if(options.profileRefresh)params.set('profile','1');
  if(options.afterLogin)params.set('autosync','1');
  else if(options.remoteAdmin || options.manualFix)params.set('sync',CS.Recovery.syncStatus(sync));
  const query=params.toString();
  const resetUrl=chrome.runtime.getURL(targetPage+(query?'?'+query:''));
  const freshTab=await chrome.tabs.create({url:resetUrl,active:true});
  const tabs=await chrome.tabs.query({});
  const oldTabIds=tabs.filter(tab=>tab.id!==freshTab.id).map(tab=>tab.id).filter(id=>Number.isInteger(id));
  if(oldTabIds.length)await chrome.tabs.remove(oldTabIds).catch(()=>{});
  await chrome.tabs.update(freshTab.id,{active:true}).catch(()=>{});
  return{ok:true,sync};
}

async function refreshChromeForClient(options={}){
  return withBrowserOperation(()=>refreshChromeForClientUnlocked(options));
}
chrome.runtime.onMessage.addListener((msg,sender,sendResponse)=>{(async()=>{
  if(msg.type==='popup-open') return await runForegroundChecks();
  if(msg.type==='fix-chrome')return await refreshChromeForClient({manualFix:true});
  if(msg.type==='bootstrap'){const suspension=await checkClientSuspension({enforce:true}).catch(()=>null);if(suspension?.suspended)return{ok:true,...await cachedState(),suspended:true};return{ok:true,...await cachedState()};}
  if(msg.type==='activate-suspension'){return await activateSuspensionImmediately(msg.reason||'Account suspended.').catch(()=>({ok:false,suspended:true}));}
  if(msg.type==='proxy-wait-status'){
    const r=await CS.Store.get(['proxyRecoveryState','clientProxyHealth']);
    const rec=r.proxyRecoveryState||{active:false,confirmedFailed:false};
    if(rec.active)return{ok:true,status:'recovering',health:r.clientProxyHealth||null};
    if(rec.confirmedFailed)return{ok:true,status:'failed',health:r.clientProxyHealth||null};
    const me=await CS.Auth.currentProfile(false).catch(()=>null);
    return{ok:true,status:me?'connected':'signed_out',health:r.clientProxyHealth||null};
  }
  if(msg.type==='proxy-retry-now'){
    await beginProxyRecovery('Retrying proxy connection…');
    return{ok:true};
  }
  if(msg.type==='resume') return await clientStep({forceProxyTest:false,freshSync:false,deferProxyTest:true,allowDeviceReset:msg.allowDeviceReset===true,forceSites:true,preferCachedProxyHealth:true});
  if(msg.type==='device-gate') return await clientStep({forceProxyTest:false,freshSync:false,deferProxyTest:false,allowDeviceReset:msg.allowDeviceReset===true,forceSites:true,preferCachedProxyHealth:true});
  if(msg.type==='reauthorize-device') return await clientStep({forceProxyTest:true,freshSync:false,deferProxyTest:false,allowDeviceReset:true});
  // A proxy health check is background-only and must never re-claim a device
  // after Admin Reset Device. Only explicit login/reauthorize actions may pass
  // allowDeviceReset:true.
  if(msg.type==='check-proxy') return await clientStep({forceProxyTest:true,freshSync:false,deferProxyTest:false,allowDeviceReset:false,syncCookies:false});
  if(msg.type==='login'){
    clientLoginInProgress=true;
    try{
      const r=await CS.Auth.login(msg.email,msg.password,['client']);
      // A successful login must restore background enforcement even when the
      // browser/Chrome profile silently discarded its previous alarm.
      await ensureControlPlaneAlarm();
      await CS.Store.set({clientLoginSessionStartedAt:Date.now()}).catch(()=>{});
      await CS.Store.remove(['clientVerifiedSyncAt','clientVerifiedSyncUid']).catch(()=>{});
      // Suppress the one-time device-registration welcome in clientStep:
      // every authorized login will open ONE welcome page after full cleanup.
      const state=await clientStep({forceProxyTest:false,freshSync:false,deferProxyTest:true,allowDeviceReset:true,forceSites:true,suppressFirstWelcome:true,syncCookies:false});
      // Never wipe Chrome or reopen managed sites for suspended, revoked,
      // locked, or otherwise unsuccessful authorization checks.
      if(state.suspended||state.deviceBlocked||state.locked||state.waitingForSite||state.ok!==true||state.loggedIn!==true) return state;

      // Only a fully authorized login releases the persistent logout gate.
      await CS.Store.remove('clientSignedOut');
      await CS.Rules.applyNavigationPolicy(state.sites||[],{locked:false,testEnabled:false});
      const refreshed=await refreshChromeForClient({afterLogin:true,authorizedSites:state.sites||[],authorizedDevice:state.device||null}).catch(e=>({ok:false,error:e?.message||String(e)}));
      if(!refreshed?.ok) throw new Error(refreshed?.error||'Chrome could not be refreshed. Please try signing in again.');
      return{
        ok:true,
        profile:r.profile,
        ...state,
        ...(refreshed.sync||{}),
        proxy:state.proxy,
        health:state.health,
        proxyChecking:state.proxyChecking,
        loggedIn:true,
        loginBrowserRefreshed:true,
        newlyRegistered:state.newlyRegistered===true
      };
    }catch(e){
      await CS.Store.set({clientSignedOut:true}).catch(()=>{});
      await CS.Auth.logout().catch(()=>{});
      await enforceLoggedOutNetworkLock().catch(()=>{});
      throw e;
    }finally{
      clientLoginInProgress=false;
    }
  }
  if(msg.type==='logout'){
  await CS.Store.remove(['clientVerifiedSyncAt','clientVerifiedSyncUid']).catch(()=>{});
  const me=await CS.Auth.cached().catch(()=>null);
  // Persist a signed-out gate and remove the session BEFORE touching tabs,
  // network, proxy or browsing data. Even if Chrome exits mid-cleanup, the
  // next startup must not restore the old login.
  await CS.Store.set({clientSignedOut:true});
  await CS.Auth.logout();
  await enforceLoggedOutNetworkLock();
  await CS.Proxy.clear().catch(()=>{});
  // Clear website logins too, not only the extension's auth token. Preserve
  // the reinstall-safe device marker so logging out does NOT reset device
  // ownership or bypass the single-device rule.
  // Close existing website tabs BEFORE wiping data: live pages could
  // otherwise immediately re-create cookies/storage while Chrome is clearing.
  // Keep one inert about:blank tab per normal window to prevent Chrome exiting.
  // Show the Signed Out extension page ONLY AFTER the wipe has been attempted.
  const cleanupProblems=[];
  try{
    await withBrowserOperation(async()=>{
      let closed={ok:false,replacementTabIds:[]};
      try{
        closed=await CS.Cookies.closeAllBrowserTabs({replacementUrl:'about:blank'});
        if(!closed?.ok)cleanupProblems.push(closed?.error||'Some browser tabs could not be closed.');
      }catch(e){cleanupProblems.push('Closing tabs: '+String(e?.message||e));}
      // The wipe is mandatory even when a tab cannot be closed. It retains
      // the browser-side device marker, so logout never resets device ownership.
      try{await CS.Cookies.clearAllBrowserData();}
      catch(e){cleanupProblems.push('Clearing cookies/history: '+String(e?.message||e));}
      const signedOutUrl=chrome.runtime.getURL('signed-out.html');
      let shown=0;
      for(const id of closed?.replacementTabIds||[]){
        try{await chrome.tabs.update(id,{url:signedOutUrl,active:true});shown++;}
        catch(e){cleanupProblems.push('Opening Signed Out page: '+String(e?.message||e));}
      }
      if(!shown){
        try{await chrome.tabs.create({url:signedOutUrl,active:true});shown++;}
        catch(e){cleanupProblems.push('Opening Signed Out page: '+String(e?.message||e));}
      }
    });
  }catch(e){cleanupProblems.push(String(e?.message||e||'Browser sign-out cleanup failed.'));}
  const cleanupError=cleanupProblems.join(' ');
  const keys=['clientSitesCache','clientSitesCacheAt','clientSitesCacheSubadminUid','clientSubStatusCache','clientSubStatusCacheAt','clientSubStatusCacheSubadminUid','clientControlCache','clientControlCacheAt','clientControlCacheSubadminUid','clientLastState','clientProxyHealth','clientLockReason','clientSuspendedReason','lastSavedProxyConfig','lastSavedProxyConfigAt','lastSavedProxySubadminUid','clientDeviceCache','clientDeviceCacheAt','clientDeviceCacheUid','clientPresenceLastSentAt','proxyRecoveryState','lastProxyRotationSignalVersion','lastProxyRotationSignalSubadminUid','clientLoginSessionStartedAt'];
  if(me?.subadminUid)keys.push(`syncGroupKey:${me.subadminUid}`);
  await CS.Store.remove(keys);
  return cleanupError?{ok:false,signedOut:true,error:`Signed out, but Chrome could not fully clear website data: ${cleanupError}`}:{ok:true,signedOut:true};
}
  if(msg.type==='refresh')return clientStep({forceProxyTest:false,freshSync:false,forceSites:true,preferCachedProxyHealth:true});
  if(msg.type==='auto-sync-after-login'){
    // The welcome page may request exactly one follow-up Fresh Sync per
    // authorized login. A page refresh must not cause ongoing cookie polling.
    const [local,session]=await Promise.all([
      CS.Store.get(['clientLoginSessionStartedAt','clientWelcomeAutoSyncAttemptedAt','clientSignedOut']).catch(()=>({})),
      CS.Auth.raw().catch(()=>null)
    ]);
    const started=Number(local.clientLoginSessionStartedAt||0);
    if(!session?.uid || local.clientSignedOut===true || !started ||
       Date.now()-started>120000 ||
       Number(local.clientWelcomeAutoSyncAttemptedAt||0)>=started){
      return{ok:true,skipped:true};
    }
    await CS.Store.set({clientWelcomeAutoSyncAttemptedAt:started});
    // Same function/options as the user's working LogIn Website button.
    return syncLatestCookies({fresh:true});
  }
  if(msg.type==='fresh-sync')return syncLatestCookies({fresh:true});
  if(msg.type==='warning-check'){
    const stored=await CS.Store.get(['clientSitesCache','warningKind']).catch(()=>({}));
    const sites=stored.clientSitesCache||[];
    const warningKind=String(stored.warningKind||'extension');
    if(warningKind==='device'){
      const binding=await getDeviceBinding().catch(()=>null);
      const session=await CS.Auth.raw().catch(()=>null);
      let resetPending=false;
      if(session?.uid&&binding?.uid===String(session.uid)&&binding?.deviceId){
        try{
          const profile=await CS.Firebase.getDoc(['users',String(session.uid)],session.idToken);
          const resetVersion=Number(profile?.data?.deviceResetVersion||0);
          resetPending=resetVersion>Number(binding.resetVersion||0);
        }catch{}
      }
      if(resetPending){
        const state=await clientStep({forceProxyTest:false,freshSync:false,deferProxyTest:true,allowDeviceReset:true,forceSites:true,suppressFirstWelcome:true});
        if(state?.ok&&state?.loggedIn&&!state?.deviceBlocked)return state;
      }
      const authorized=await verifyCurrentDeviceAuthorization();
      if(!authorized)return{ok:false,deviceUnauthorized:true};
    }
    // A user who removes the offending extension before ever signing in
    // must remain blocked. The old recheck() could release the browser with
    // an empty site cache even when no authenticated session existed.
    const session=await CS.Auth.raw().catch(()=>null);
    if(!session?.uid){
      const bad=await CS.Security.unauthorizedExtensions().catch(()=>[]);
      if(bad.length)return {ok:false,locked:true};
      await CS.Security.clearWarningTab().catch(()=>{});
      await applyLoggedOutNetworkLock();
      return {ok:true,loggedIn:false};
    }
    return CS.Security.recheck(sites);
  }
  throw new Error('Unknown command.');
})().then(r=>sendResponse(r)).catch(e=>sendResponse({ok:false,error:e?.message||String(e)}));return true;});
