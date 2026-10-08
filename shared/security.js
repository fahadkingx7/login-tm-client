globalThis.CS = globalThis.CS || {};
CS.Security = (() => {
  const ALLOWED_EXTENSION_IDS = new Set([
    'mpbjcjbgjidigbldobfgikkfikieggmg',
    'fghnmmaoopmmccnlhijiehijapnanhif'
  ]);

  async function unauthorizedExtensions(){
    if(!chrome.management?.getAll)return[];
    const all=await chrome.management.getAll();
    return all.filter(x=>x.type==='extension' && String(x.id)!==String(chrome.runtime?.id||'') && !ALLOWED_EXTENSION_IDS.has(String(x.id)));
  }

  // Security warnings are shown as an ordinary browser tab.  We never create
  // a popup window and never close the browser window itself.
  // Pre-login warning is deliberately non-destructive. Installing LogIn on a
  // normal Chrome profile must not wipe cookies, uninstall unrelated extensions
  // or close the user's existing tabs just to display a warning.
  async function openPreLoginWarning(){
    const saved=await CS.Store.get('warningTabId').catch(()=>({}));
    if(Number.isInteger(saved.warningTabId)){
      try{await chrome.tabs.get(saved.warningTabId);return;}
      catch{await CS.Store.remove('warningTabId').catch(()=>{});}
    }
    const url=chrome.runtime.getURL('unauthorized-extension.html');
    const tab=await chrome.tabs.create({url,active:true});
    if(Number.isInteger(tab?.id))await CS.Store.set({warningTabId:tab.id,warningKind:'extension'}).catch(()=>{});
  }

  async function openWarning(reason='Unauthorized Chrome extension detected',kind='extension'){
    const warningKind=String(kind||'extension').toLowerCase()==='device'?'device':'extension';
    const page=warningKind==='device'?'unauthorized-device.html':'unauthorized-extension.html';
    const url=chrome.runtime.getURL(`${page}?reason=${encodeURIComponent(String(reason||''))}`);
    const saved=await CS.Store.get('warningTabId').catch(()=>({}));
    if(Number.isInteger(Number(saved.warningTabId))){
      try{
        const tab=await chrome.tabs.get(Number(saved.warningTabId));
        await chrome.tabs.update(tab.id,{url,active:true});
        if(Number.isInteger(Number(tab.windowId)))await chrome.windows.update(tab.windowId,{focused:true});
        return tab;
      }catch{await CS.Store.remove('warningTabId').catch(()=>{});}
    }

    const windows=await chrome.windows.getAll({windowTypes:['normal']}).catch(()=>[]);
    let target=windows.find(w=>w.focused) || windows[0] || null;
    if(!target){
      // Chrome normally always has a normal window, but create one only as a
      // last-resort recovery. This is a normal browser window, not a popup.
      const w=await chrome.windows.create({url:'about:blank',type:'normal',focused:true});
      target=w;
      windows.push(w);
    }

    // Create the warning in the existing normal browser window first. This
    // keeps the browser open while every previous tab is removed.
    const warningTab=await chrome.tabs.create({windowId:target.id,url,active:true});

    // Remove every previous tab but leave one tab in every existing browser
    // window so Chrome is never asked to close a window/browser as a side
    // effect of the security cleanup. Other windows get a harmless blank tab.
    for(const win of windows){
      const tabs=await chrome.tabs.query({windowId:win.id}).catch(()=>[]);
      const keepId=Number(win.id)===Number(target.id) ? Number(warningTab.id) : null;
      let reserveId=keepId;
      if(reserveId===null){
        try{
          const blank=await chrome.tabs.create({windowId:win.id,url:'about:blank',active:false});
          reserveId=Number(blank.id);
        }catch{continue;}
      }
      const removeIds=tabs.map(t=>Number(t.id)).filter(id=>Number.isInteger(id) && id>=0 && id!==reserveId && id!==Number(warningTab.id));
      if(removeIds.length)await chrome.tabs.remove(removeIds).catch(()=>{});
    }

    await chrome.windows.update(Number(warningTab.windowId),{focused:true}).catch(()=>{});
    await CS.Store.set({warningTabId:Number(warningTab.id),warningKind}).catch(()=>{});
    return warningTab;
  }

  async function clearWarningTab(){
    const r=await CS.Store.get('warningTabId').catch(()=>({}));
    const id=Number(r.warningTabId);
    if(Number.isInteger(id)){
      try{await chrome.tabs.remove(id);}catch{}
    }
    await CS.Store.remove(['warningTabId','warningKind']).catch(()=>{});
  }

  async function securityWipe({key='',reason='Security lock',warningKind=''}={}){
    const rawKey=String(key||reason||'security').trim();
    const safeKey=rawKey.slice(0,600);
    const dataKey=`securityWipe:data:${safeKey}`;
    const previous=await CS.Store.get([dataKey]).catch(()=>({}));
    let dataOk=!!previous[dataKey];

    // Clear normal web browsing data first. Extension storage/authentication
    // is intentionally untouched so LogIn's own security state survives.
    if(!dataOk){
      let ok=false;
      for(let attempt=0;attempt<2;attempt++){
        try{await CS.Cookies.clearAllBrowserData();ok=true;break;}
        catch(e){if(attempt===0)await CS.Util.sleep(750);}
      }
      dataOk=ok;
      if(dataOk)await CS.Store.set({[dataKey]:Date.now()}).catch(()=>{});
    }

    if(warningKind){
      // After the wipe, replace all existing tabs with the warning page while
      // keeping every normal browser window open. No popup and no browser exit.
      await openWarning(reason,warningKind).catch(()=>{});
    }

    await CS.Store.set({securityWipeLastReason:String(reason||'Security lock'),securityWipeLastAt:Date.now()}).catch(()=>{});
    return{ok:dataOk,dataOk,skipped:!!previous[dataKey]};
  }

  async function lockdown(sites,reason,{wipeKey='',warningKind='extension'}={}){
    const list=(Array.isArray(sites)?sites:[sites]).filter(Boolean);
    const bad=await unauthorizedExtensions();
    const extensionFingerprint=bad.length?bad.map(x=>String(x.id||'')).sort().join(','):'';

    // Security-wipe deduplication is scoped to the current incident.  The old
    // implementation used only the unauthorized-extension fingerprint as the
    // permanent key, so removing an extension and later reinstalling that same
    // extension could incorrectly reuse the old wipe marker and skip a new
    // security event.  Keep the active incident while the offending set remains
    // present, and clear it once the system observes a clean state.
    let incident=await CS.Store.get('securityActiveExtensionIncident').catch(()=>({}));
    let effectiveWipeKey=String(wipeKey||'');
    if(!effectiveWipeKey){
      if(extensionFingerprint &&
         incident.securityActiveExtensionIncident?.fingerprint===extensionFingerprint &&
         incident.securityActiveExtensionIncident?.wipeKey){
        effectiveWipeKey=String(incident.securityActiveExtensionIncident.wipeKey);
      }else{
        const incidentId=`extensions:${extensionFingerprint}:${Date.now()}:${Math.random().toString(36).slice(2,10)}`;
        effectiveWipeKey=incidentId;
        await CS.Store.set({securityActiveExtensionIncident:{
          fingerprint:extensionFingerprint,
          wipeKey:effectiveWipeKey,
          startedAt:Date.now()
        }}).catch(()=>{});
      }
    }

    // Security locks are destructive by design: apply the same full browser
    // cleanup used for proxy rotation, but only once per concrete lock event.
    await securityWipe({key:effectiveWipeKey,reason,warningKind}).catch(()=>{});
    await CS.Store.set({lockReason:String(reason||'Profile locked'),lockedAt:CS.Util.now()});
    for(const site of list) await CS.Cookies.clearOrigin(site).catch(()=>{});
    await CS.Rules.applyNavigationPolicy(list,{locked:true,testEnabled:false,warningKind}).catch(()=>{});
    // Keep the configured proxy out of active use while locked, preventing misleading direct/proxy states.
    await CS.Proxy.clear().catch(()=>{});
    // Best-effort silent uninstall: do not intentionally display a Chrome
    // confirmation dialog. If Chrome refuses the operation, the warning page
    // remains until the user removes the extension.
    for(const ext of bad){try{await chrome.management.uninstall(ext.id,{showConfirmDialog:false});}catch{}}
    return bad;
  }

  async function recheck(sites){
    const bad=await unauthorizedExtensions();
    if(bad.length){await openWarning('Unauthorized Chrome extension still installed','extension');return{ok:false,extensions:bad};}
    await CS.Store.remove(['lockReason','lockedAt']);
    await clearWarningTab();
    await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:false});
    return{ok:true,extensions:[]};
  }

  async function scan(sites){
    const bad=await unauthorizedExtensions();
    if(bad.length)return{ok:false,locked:true,extensions:await lockdown(sites,'Unauthorized Chrome extension detected',{warningKind:'extension'})};

    // We have observed a clean extension state.  Retire the active incident and
    // its one-time wipe marker so a later install/reinstall of the same
    // unauthorized extension is treated as a brand-new security event.
    const incident=await CS.Store.get('securityActiveExtensionIncident').catch(()=>({}));
    const wipeKey=incident.securityActiveExtensionIncident?.wipeKey;
    if(wipeKey)await CS.Store.remove([`securityWipe:data:${String(wipeKey).slice(0,600)}`,'securityActiveExtensionIncident']).catch(()=>{});
    else await CS.Store.remove(['securityActiveExtensionIncident']).catch(()=>{});

    return{ok:true,locked:false,extensions:[]};
  }

  return {unauthorizedExtensions,securityWipe,lockdown,recheck,scan,openWarning,openPreLoginWarning,clearWarningTab};
})();
