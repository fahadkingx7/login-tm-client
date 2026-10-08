globalThis.CS = globalThis.CS || {};
CS.Rules = (() => {
  const SUPABASE_HOSTS=['thdxsonrjazeoadhidbx.supabase.co'];
  const HTTP_TYPES=['main_frame','sub_frame','xmlhttprequest','script','image','stylesheet','font','media','object','other','ping','websocket'];
  const MAIN=['main_frame'];
  let updateQueue = Promise.resolve();
  async function applyDynamicRules(resolvePolicy){
    const run = async () => {
      // Decide under the same queue that writes Chrome's DNR rules. Proxy
      // recovery, popup health checks and an in-flight normal sync must never
      // replace a confirmed suspension lock with an "allow" policy.
      const policy = await resolvePolicy();
      const current = await chrome.declarativeNetRequest.getDynamicRules();
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: current.map(x=>x.id),
        addRules: policy.rules
      });
      await CS.Store.set({networkLockdown:policy.locked});
    };
    const next = updateQueue.then(run, run);
    updateQueue = next.catch(() => {});
    return next;
  }
  function hostRegex(host){
    const h=String(host||'').replace(/^\./,'').toLowerCase();
    const escaped=h.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    return `^https?:\\/\\/(?:[^\\/]+\\.)?${escaped}(?::\\d+)?(?:[\\/]|$)`;
  }
  function allowHost(id,host,types=MAIN){
    return{id,priority:4000,action:{type:'allow'},condition:{regexFilter:hostRegex(host),resourceTypes:types}};
  }
  function blockAllWeb(){return{id:2,priority:1,action:{type:'block'},condition:{regexFilter:'^https?://',resourceTypes:HTTP_TYPES}};}
  function blockUnauthorizedWebsites(){
    return{
      id:1,
      priority:1,
      action:{type:'redirect',redirect:{extensionPath:'/unauthorized-website.html'}},
      condition:{regexFilter:'^https?://',resourceTypes:MAIN}
    };
  }
  function blockSecurityNavigations(warningKind='device'){
    const kind=String(warningKind||'device').toLowerCase();
    const page=kind==='extension'
      ? 'unauthorized-extension.html'
      : (kind==='suspended' ? 'suspended.html' : kind==='signed-out' ? 'signed-out.html' : 'unauthorized-device.html');
    return{
      id:1,
      priority:3000,
      action:{type:'redirect',redirect:{extensionPath:`/${page}`}},
      condition:{regexFilter:'^https?://',resourceTypes:MAIN}
    };
  }
  function infra(){return SUPABASE_HOSTS.map((h,i)=>allowHost(10+i,h,['xmlhttprequest','script','other']));}
  function ipTestRules(){
    const hosts=[...new Set((CS.CONFIG.ipCheckUrls||[]).map(url=>{try{return new URL(url).hostname;}catch{return '';}}).filter(Boolean))];
    return hosts.map((host,i)=>allowHost(20+i,host,['xmlhttprequest','other']));
  }
  function uniqueSites(sites){const seen=new Set();return(sites||[]).filter(s=>s&&s.hostname&&(!seen.has(s.id)&&(seen.add(s.id),true))).slice(0,100);}
  function siteScopeHostname(hostname){
    return CS.Util.scopeHostname(hostname);
  }
  function siteAllows(sites){
    return uniqueSites(sites).map(s=>siteScopeHostname(s.hostname)).filter(Boolean).map((host,i)=>allowHost(100+i,host,MAIN));
  }
  function blockedPatterns(sites){
    const rules=[];let id=2000;
    for(const site of uniqueSites(sites)) for(const pattern of (site.blockedPatterns||[]).slice(0,500)){
      rules.push({
        id:id++,
        priority:5000,
        action:{type:'redirect',redirect:{extensionPath:'/unauthorized-website.html'}},
        condition:{urlFilter:String(pattern),resourceTypes:MAIN}
      });
      if(id>=3900) return rules;
    }
    return rules;
  }
  async function applyNavigationPolicy(sites,{locked=false,testEnabled=false,warningKind='device'}={}){
    return applyDynamicRules(async()=>{
      // Check persistent status at *execution* time rather than at enqueue
      // time; otherwise an older proxy health request can unlock the browser
      // after an account was suspended while that request was waiting.
      const local=await CS.Store.get(['clientSuspensionLock','clientSuspendedReason','clientSignedOut']);
      const suspended=local.clientSuspensionLock===true || !!local.clientSuspendedReason;
      // An old proxy health check must never re-authorize web access after
      // explicit sign-out, even if it finished after the logout request.
      const effectiveLocked=locked===true || suspended || local.clientSignedOut===true;
      const kind=suspended?'suspended':warningKind==='extension'?'extension':local.clientSignedOut===true?'signed-out':warningKind;
      const rules=effectiveLocked
        ? [blockSecurityNavigations(kind),blockAllWeb(),...infra()]
        : [blockUnauthorizedWebsites(),...infra()];
      if(!suspended && testEnabled)rules.push(...ipTestRules());
      if(!effectiveLocked)rules.push(...siteAllows(sites),...blockedPatterns(sites));
      return {rules,locked:effectiveLocked};
    });
  }
  return {applyNavigationPolicy};
})();
