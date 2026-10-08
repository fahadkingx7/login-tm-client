globalThis.CS = globalThis.CS || {};
CS.Auth = (() => {
  const SESSION = 'authSession', PROFILE = 'profileCache';
  let authVersion = 0;
  let mutationQueue = Promise.resolve();
  let refreshOperation = null;

  // Serialize local writes so a refresh cannot restore a session after logout.
  function mutate(work) {
    const next = mutationQueue.then(work, work);
    mutationQueue = next.catch(() => {});
    return next;
  }
  async function raw() { const r = await CS.Store.get(SESSION); return r[SESSION] || null; }
  async function cached() { const r = await CS.Store.get(PROFILE); return r[PROFILE] || null; }
  function sameSession(a, b) {
    return !!a && !!b && a.uid === b.uid && a.idToken === b.idToken && a.refreshToken === b.refreshToken;
  }
  async function save(s) {
    authVersion += 1;
    return mutate(async () => {
      const old = await raw();
      if (old?.uid !== s?.uid) await CS.Store.remove(PROFILE);
      await CS.Store.set({ [SESSION]: s });
    });
  }
  async function clear(expected) {
    if (!expected) authVersion += 1;
    return mutate(async () => {
      if (expected && !sameSession(await raw(), expected)) return false;
      await CS.Store.remove([SESSION, PROFILE]);
      return true;
    });
  }
  function invalidRefresh(error) {
    return [
      'invalid_grant', 'invalid_refresh_token', 'refresh_token_not_found',
      'refresh_token_already_used', 'session_not_found', 'session_expired',
      'user_not_found', 'user_banned', 'user_disabled'
    ].includes(String(error?.code || '').toLowerCase());
  }
  async function refreshIfNeeded(s) {
    if (!s) return null;
    if (Number(s.expiresAt || 0) - Date.now() > 5 * 60 * 1000) return s;
    if (!s.refreshToken) { await clear(s); return null; }
    if (refreshOperation && sameSession(refreshOperation.session, s)) return refreshOperation.promise;
    const operation = { session: s, promise: null };
    operation.promise = (async () => {
      try {
        const n = await CS.Firebase.refresh(s.refreshToken);
        const next = {
          uid: n.user_id || s.uid, email: s.email, idToken: n.id_token,
          refreshToken: n.refresh_token || s.refreshToken,
          expiresAt: Date.now() + Number(n.expires_in || 3600) * 1000
        };
        return mutate(async () => {
          const current = await raw();
          if (!sameSession(current, s)) return current;
          await CS.Store.set({ [SESSION]: next });
          return next;
        });
      } catch (e) {
        if (invalidRefresh(e)) { await clear(s); return raw(); }
        // Network failures must preserve a still-usable local session.
        return raw();
      }
    })();
    refreshOperation = operation;
    try { return await operation.promise; }
    finally { if (refreshOperation === operation) refreshOperation = null; }
  }
  async function session(fresh = true) { const s = await raw(); return fresh ? refreshIfNeeded(s) : s; }
  async function fetchProfile(s) {
    const r = await CS.Firebase.getDoc(['users', s.uid], s.idToken);
    if (!r.exists) { const e = new Error('Account profile is missing.'); e.code = 'PROFILE_MISSING'; throw e; }
    await mutate(async () => {
      if (!sameSession(await raw(), s)) {
        const e = new Error('Session changed; the pending request was cancelled.');
        e.code = 'AUTH_CANCELLED';
        throw e;
      }
      await CS.Store.set({ [PROFILE]: r.data });
    });
    if (r.data.active === false) {
      const e = new Error('Account suspended.'); e.code = 'ACCOUNT_SUSPENDED'; e.profile = r.data; throw e;
    }
    return r.data;
  }
  async function login(email, password, roles) {
    const version = ++authVersion;
    const a = await CS.Firebase.signIn(CS.Util.normalizeEmail(email), password);
    if (version !== authVersion) throw new Error('Sign-in was cancelled. Please try again.');
    const s = {
      uid: a.localId, email: a.email, idToken: a.idToken, refreshToken: a.refreshToken,
      expiresAt: Date.now() + Number(a.expiresIn || 3600) * 1000
    };
    await save(s);
    try {
      const p = await fetchProfile(s);
      if (!roles.includes(p.role)) throw new Error('This account cannot use this extension.');
      return { session: s, profile: p };
    } catch (e) {
      if (e.code === 'ACCOUNT_SUSPENDED' && roles.includes(e.profile?.role)) {
        return { session: s, profile: e.profile, suspended: true };
      }
      await clear(s);
      throw e;
    }
  }
  async function currentProfile(fresh = true) {
    const s = await session(fresh); if (!s) return null;
    const p = await cached();
    if (!fresh && p) return { session: s, profile: p, suspended: p.active === false };
    try { return { session: s, profile: await fetchProfile(s) }; }
    catch (e) {
      if (e.code === 'ACCOUNT_SUSPENDED') return { session: s, profile: e.profile || p, suspended: true };
      if (e.code === 'PROFILE_MISSING') await clear(s);
      throw e;
    }
  }
  async function createUser(email, password) {
    const a = await CS.Firebase.signUp(CS.Util.normalizeEmail(email), password);
    return { uid: a.localId, email: a.email, idToken: a.idToken };
  }
  async function deleteCreatedUser(idToken) { try { await CS.Firebase.deleteAuthAccount(idToken); } catch {} }
  async function logout() { await clear(); }
  return { save, raw, cached, session, currentProfile, login, logout, createUser, deleteCreatedUser };
})();
