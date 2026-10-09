globalThis.CS = globalThis.CS || {};
CS.Rules = (() => {
  const SUPABASE_HOSTS=['thdxsonrjazeoadhidbx.supabase.co'];
  const HTTP_TYPES=['main_frame','sub_frame','xmlhttprequest','script','image','stylesheet','font','media','object','other','ping','websocket'];
  const MAIN=['main_frame'];
  // Public company website: independent of managed-site assignments and cookie sync.
  const PUBLIC_ALWAYS_ALLOWED_HOST='veefivee.com';
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
  function publicWebsiteAllow(){
    // Higher than blockedPatterns and every generic website redirect.
    // The rule is omitted for real device, extension or suspension locks.
    // Allow the site's entire frame (including its third-party images, fonts,
    // scripts and stylesheet requests), while keeping every other tab locked.
    // This is a DNR frame permission, NOT a Chrome proxy/direct-mode exception.
    return [
      {...allowHost(40,PUBLIC_ALWAYS_ALLOWED_HOST,HTTP_TYPES),priority:6000},
      {...allowHost(42,PUBLIC_ALWAYS_ALLOWED_HOST,MAIN),priority:6100,
        action:{type:'allowAllRequests'}}
    ];
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
      : (kind==='suspended' ? 'suspended.html' : kind==='signed-out' ? 'signed-out.html' : kind==='website' ? 'unauthorized-website.html' : 'unauthorized-device.html');
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
  function extraAllowRules(policy){
    const allowAll=policy && policy.allowAll===true;
    if(allowAll){
      // Only top-level website navigation; Chrome's existing proxy is unchanged.
      return [{id:41,priority:3000,action:{type:'allow'},
        condition:{regexFilter:'^https?://',resourceTypes:MAIN}}];
    }
    const domains=Array.isArray(policy?.domains)?policy.domains:[];
    const seen=new Set();
    return domains.filter(h=>{
      const host=String(h||'').trim().toLowerCase();
      if(!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host) ||
         !host.includes('.') || host.length>253 || seen.has(host))return false;
      seen.add(host);return true;
    }).slice(0,100).map((host,i)=>({...allowHost(500+i,host),priority:4500}));
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
      const local=await CS.Store.get(['clientSuspensionLock','clientSuspendedReason','clientSignedOut','clientWebsiteAccess']);
      const suspended=local.clientSuspensionLock===true || !!local.clientSuspendedReason;
      // An old proxy health check must never re-authorize web access after
      // explicit sign-out, even if it finished after the logout request.
      const effectiveLocked=locked===true || suspended || local.clientSignedOut===true;
      const kind=suspended?'suspended':warningKind==='extension'?'extension':local.clientSignedOut===true?'signed-out':warningKind;
      const rules=effectiveLocked
        ? [blockSecurityNavigations(kind),blockAllWeb(),...infra()]
        : [blockUnauthorizedWebsites(),...infra()];
      if(!suspended && testEnabled)rules.push(...ipTestRules());
      // A public corporate site is not a synced login. Allow it even before
      // sign-in or after sign-out, but never defeat confirmed security locks.
      const securityWarning=locked===true && ['device','extension','suspended'].includes(warningKind);
      if(!suspended && !securityWarning &&
         (!effectiveLocked || kind==='website' || kind==='signed-out')){
        rules.push(...publicWebsiteAllow());
      }
      if(!effectiveLocked){
        rules.push(...siteAllows(sites),...extraAllowRules(local.clientWebsiteAccess),...blockedPatterns(sites));
      }
      return {rules,locked:effectiveLocked};
    });
  }
  return {applyNavigationPolicy};
})();
