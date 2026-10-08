globalThis.CS = globalThis.CS || {};
CS.Crypto = (() => {
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64 = bytes => {
    const data=new Uint8Array(bytes);
    let binary='';
    for(let i=0;i<data.length;i+=32768)binary+=String.fromCharCode(...data.subarray(i,i+32768));
    return btoa(binary);
  };
  const unb64 = s => Uint8Array.from(atob(String(s)), c => c.charCodeAt(0));

  const KEY='deviceIdentity';

  async function generateKeyMaterial(){
    const kp=await crypto.subtle.generateKey(
      {name:'ECDH',namedCurve:'P-256'},
      true,
      ['deriveBits']
    );
    return {
      privateJwk:await crypto.subtle.exportKey('jwk',kp.privateKey),
      publicJwk:await crypto.subtle.exportKey('jwk',kp.publicKey)
    };
  }

  async function readIdentity(){
    const r=await CS.Store.get(KEY);
    return r[KEY]||null;
  }

  const DEVICE_MARKER_URL='https://thdxsonrjazeoadhidbx.supabase.co/';
  const DEVICE_MARKER_NAME='__Host-loginDeviceMarkerV1';
  const DEVICE_MARKER_MAX_AGE_DAYS=399;

  function getPersistentDeviceMarker(){
    return new Promise(resolve=>{
      try{
        chrome.cookies.get({url:DEVICE_MARKER_URL,name:DEVICE_MARKER_NAME},cookie=>{
          const err=chrome.runtime.lastError;
          if(err||!cookie?.value)return resolve(null);
          resolve({value:String(cookie.value),expirationDate:Number(cookie.expirationDate||0)});
        });
      }catch{resolve(null);}
    });
  }

  function setPersistentDeviceMarker(deviceId, existing=null){
    return new Promise(resolve=>{
      const now=Math.floor(Date.now()/1000);
      const currentExpiry=Number(existing?.expirationDate||0);
      const needsRefresh=!currentExpiry || currentExpiry-now < 60*60*24*30;
      if(existing?.value===String(deviceId) && !needsRefresh)return resolve(true);
      try{
        chrome.cookies.set({
          url:DEVICE_MARKER_URL,
          name:DEVICE_MARKER_NAME,
          value:String(deviceId),
          path:'/',
          secure:true,
          httpOnly:true,
          sameSite:'strict',
          expirationDate:now + DEVICE_MARKER_MAX_AGE_DAYS*24*60*60
        },()=>{
          const err=chrome.runtime.lastError;
          resolve(!err);
        });
      }catch{resolve(false);}
    });
  }

  function validDeviceId(value){
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value||''));
  }

  let identityPromise=null;
  async function ensureDeviceIdentity(){
    if(identityPromise)return identityPromise;
    identityPromise=loadOrCreateDeviceIdentity();
    try{return await identityPromise;}finally{identityPromise=null;}
  }
  async function loadOrCreateDeviceIdentity(){
    const existing=await readIdentity();

    // Keep the durable browser marker alive so a remove/reinstall can recover
    // the same server-side device claim. Extension storage itself is cleared
    // by Chrome when the extension is removed.
    const marker=await getPersistentDeviceMarker();

    // Never generate a new deviceId merely because the popup reopened,
    // service worker restarted, or the user signed out/in.
    if(existing?.deviceId){
      await setPersistentDeviceMarker(existing.deviceId,marker).catch(()=>{});
      return existing;
    }

    // On a reinstall, recover the same deviceId from the browser-level marker.
    // A fresh key pair is fine because device authorization is deviceId-based
    // and synchronization keys are stored server-side.
    if(validDeviceId(marker?.value)){
      const identity={
        deviceId:String(marker.value),
        ...await generateKeyMaterial(),
        createdAt:CS.Util.now(),
        restoredAfterReinstall:true
      };
      await CS.Store.set({[KEY]:identity});
      await setPersistentDeviceMarker(identity.deviceId,marker).catch(()=>{});
      return identity;
    }

    const identity={
      deviceId:CS.Util.uuid(),
      ...await generateKeyMaterial(),
      createdAt:CS.Util.now()
    };
    await CS.Store.set({[KEY]:identity});
    await setPersistentDeviceMarker(identity.deviceId).catch(()=>{});
    return identity;
  }

  // Device ownership is per client account, not globally per Chrome profile.
  // The browser's durable root identity/keypair is unchanged (including its
  // reinstall cookie marker), but new account claims use a reproducible UUID
  // scoped to the authenticated user. This avoids a different account's claim
  // to the old unscoped device ID blocking a legitimate post-reset login.
  // Existing unscoped registrations are recognized from their server record.
  async function deviceIdentityForAccount(uid,serverDeviceId='',{preserveLocalBinding=true}={}){
    const root=await ensureDeviceIdentity();
    const account=String(uid||'').trim();
    if(!account)return root;
    const digest=new Uint8Array(await crypto.subtle.digest(
      'SHA-256',enc.encode(`LogIn/Chrome-device/account-v1/${root.deviceId}/${account}`)
    ));
    // RFC 4122 name-based UUID structure, using a SHA-256-derived name.
    digest[6]=(digest[6]&0x0f)|0x50;
    digest[8]=(digest[8]&0x3f)|0x80;
    const hex=Array.from(digest.subarray(0,16),b=>b.toString(16).padStart(2,'0')).join('');
    const scopedId=`${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20,32)}`;
    const remote=String(serverDeviceId||'');
    if(remote===String(root.deviceId))return root; // legacy account still bound here
    if(remote===scopedId)return {...root,deviceId:scopedId};
    // Never trust a different remote claim as authorization for this browser.
    // The caller compares it to the returned identity and denies mismatches.
    if(remote)return {...root,deviceId:scopedId};
    if(preserveLocalBinding){
      const binding=await CS.Store.get(['deviceBindingUid','deviceBindingId']).catch(()=>({}));
      if(String(binding.deviceBindingUid||'')===account &&
         String(binding.deviceBindingId||'')===String(root.deviceId))return root;
    }
    return {...root,deviceId:scopedId};
  }

  async function getStoredDeviceIdentityCandidates(){
    const identity=await readIdentity();
    return identity?.deviceId?[identity]:[];
  }

  async function getStoredDeviceIdentity(){
    const list=await getStoredDeviceIdentityCandidates();
    return list[0]||null;
  }

  async function persistDeviceIdentity(identity){
    if(!identity?.deviceId) throw new Error('Invalid device identity.');
    await CS.Store.set({[KEY]:identity});
    return identity;
  }

  async function importPrivate(jwk){
    return crypto.subtle.importKey(
      'jwk',jwk,
      {name:'ECDH',namedCurve:'P-256'},
      false,
      ['deriveBits']
    );
  }

  async function importPublic(jwk){
    return crypto.subtle.importKey(
      'jwk',jwk,
      {name:'ECDH',namedCurve:'P-256'},
      false,
      []
    );
  }

  async function deriveAes(privateKey,publicKey,salt,info){
    const bits=await crypto.subtle.deriveBits(
      {name:'ECDH',public:publicKey},
      privateKey,
      256
    );
    const material=await crypto.subtle.importKey(
      'raw',bits,{name:'HKDF'},false,['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name:'HKDF',
        hash:'SHA-256',
        salt,
        info:new TextEncoder().encode(info)
      },
      material,
      {name:'AES-GCM',length:256},
      false,
      ['encrypt','decrypt']
    );
  }

  async function encryptForPublic(value,recipientPublicJwk,aadValue=''){
    const eph=await crypto.subtle.generateKey(
      {name:'ECDH',namedCurve:'P-256'},
      true,
      ['deriveBits']
    );
    const ephPublicJwk=await crypto.subtle.exportKey('jwk',eph.publicKey);
    const salt=crypto.getRandomValues(new Uint8Array(16));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const key=await deriveAes(
      eph.privateKey,
      await importPublic(recipientPublicJwk),
      salt,
      'cookie-sync-v2'
    );
    const plaintext=new TextEncoder().encode(JSON.stringify(value));
    const aad=new TextEncoder().encode(String(aadValue||''));
    const ciphertext=await crypto.subtle.encrypt(
      {name:'AES-GCM',iv,additionalData:aad},
      key,
      plaintext
    );
    return {
      v:2,
      ephemeralPublicJwk:ephPublicJwk,
      salt:b64(salt),
      iv:b64(iv),
      ciphertext:b64(ciphertext),
      aad:String(aadValue||'')
    };
  }

  async function decryptEnvelope(envelope,privateJwk){
    if(!envelope||envelope.v!==2) throw new Error('Unsupported encrypted payload.');
    const ub=s=>Uint8Array.from(atob(String(s)),c=>c.charCodeAt(0));
    const priv=await importPrivate(privateJwk);
    const peer=await importPublic(envelope.ephemeralPublicJwk);
    const key=await deriveAes(
      priv,
      peer,
      ub(envelope.salt),
      'cookie-sync-v2'
    );
    const plaintext=await crypto.subtle.decrypt(
      {
        name:'AES-GCM',
        iv:ub(envelope.iv),
        additionalData:new TextEncoder().encode(String(envelope.aad||''))
      },
      key,
      ub(envelope.ciphertext)
    );
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  async function newKeyBase64(){
    const bytes=crypto.getRandomValues(new Uint8Array(32));
    return btoa(String.fromCharCode(...bytes));
  }

  async function importRawKey(base64){
    const bytes=Uint8Array.from(atob(String(base64)),c=>c.charCodeAt(0));
    if(bytes.byteLength!==32) throw new Error('Invalid synchronization key.');
    return crypto.subtle.importKey(
      'raw',bytes,{name:'AES-GCM'},false,['encrypt','decrypt']
    );
  }

  async function encryptWithKey(value,base64,aad=''){
    const key=await importRawKey(base64);
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const ciphertext=await crypto.subtle.encrypt(
      {name:'AES-GCM',iv,additionalData:new TextEncoder().encode(String(aad||''))},
      key,
      new TextEncoder().encode(JSON.stringify(value))
    );
    return {
      v:1,
      iv:b64(iv),
      ciphertext:b64(ciphertext),
      aad:String(aad||'')
    };
  }

  async function decryptWithKey(envelope,base64){
    if(envelope?.v===2){
      const identity=await ensureDeviceIdentity();
      return decryptEnvelope(envelope,identity.privateJwk);
    }
    if(!envelope||envelope.v!==1) throw new Error('Unsupported synchronization payload.');
    const key=await importRawKey(base64);
    const ub=s=>Uint8Array.from(atob(String(s)),c=>c.charCodeAt(0));
    const plaintext=await crypto.subtle.decrypt(
      {
        name:'AES-GCM',
        iv:ub(envelope.iv),
        additionalData:new TextEncoder().encode(String(envelope.aad||''))
      },
      key,
      ub(envelope.ciphertext)
    );
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  return {
    ensureDeviceIdentity,
    deviceIdentityForAccount,
    getStoredDeviceIdentityCandidates,
    getStoredDeviceIdentity,
    persistDeviceIdentity,
    encryptForPublic,
    decryptEnvelope,
    newKeyBase64,
    encryptWithKey,
    decryptWithKey
  };
})();
