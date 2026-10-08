globalThis.CS = globalThis.CS || {};
CS.Sync = (() => {
  async function getGroupKey(subadminUid, token){
    const uid=String(subadminUid||'').trim();
    if(!uid)return '';
    const cacheKey=`syncGroupKey:${uid}`;
    const local=await CS.Store.get(cacheKey).catch(()=>({}));
    if(local[cacheKey])return String(local[cacheKey]);

    const r=await CS.Firebase.getDoc(['users',uid,'syncKey','config'],token);
    const key=r.exists?String(r.data.key||''):'';
    if(key)await CS.Store.set({[cacheKey]:key}).catch(()=>{});
    return key;
  }
  async function ensureGroupKey(subadminUid, token){
    const uid=String(subadminUid||'').trim();
    const current=await getGroupKey(uid,token);
    if(current)return current;
    const key=await CS.Crypto.newKeyBase64();
    await CS.Firebase.setDoc(['users',uid,'syncKey','config'],{key,createdAt:CS.Util.now(),version:1},token);
    await CS.Store.set({[`syncGroupKey:${uid}`]:key}).catch(()=>{});
    return key;
  }
  return {getGroupKey,ensureGroupKey};
})();
