globalThis.CS = globalThis.CS || {};
CS.Firebase = (() => {
  /*
   * Firebase-compatible facade backed by Supabase.
   *
   * The rest of the extension intentionally keeps its existing CS.Firebase
   * API so the cookie/device/proxy/sync logic does not need a risky rewrite.
   * Firestore's old nested paths are translated to the normalized Postgres
   * tables created for LogIn v4.
   */
  const cfg = CS.CONFIG;
  const base = String(cfg.supabaseUrl || '').replace(/\/+$/, '');
  const rest = `${base}/rest/v1`;
  const authBase = `${base}/auth/v1`;

  function enc(v){ return encodeURIComponent(String(v)); }

  async function request(url, options = {}) {
    const controller = new AbortController();
    const timeoutMs = Number(options.timeoutMs || 15000);
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
    const onAbort = () => controller.abort(options.signal?.reason);
    if (options.signal?.aborted) onAbort();
    else options.signal?.addEventListener('abort', onAbort, { once: true });
    const headers = { ...(options.headers || {}) };
    if (!headers.apikey) headers.apikey = cfg.supabasePublishableKey;
    const fetchOptions = {
      cache: 'no-store',
      ...options,
      headers,
      signal: controller.signal
    };
    delete fetchOptions.timeoutMs;
    try {
      const res = await fetch(url, fetchOptions);
      const text = await res.text();
      let data = null;
      try { data = text ? JSON.parse(text) : null; } catch { data = text; }
      if (!res.ok) {
        const msg =
          data?.message ||
          data?.error_description ||
          data?.error?.message ||
          data?.msg ||
          `HTTP ${res.status}`;
        const e = new Error(String(msg));
        e.status = res.status;
        e.code = data?.code || data?.error_code || `HTTP_${res.status}`;
        e.supabase = data;
        throw e;
      }
      return data;
    } catch (e) {
      if (e?.name === 'AbortError' && timedOut) {
        const x = new Error('Request timed out. Check your Internet connection and try again.');
        x.code = 'NETWORK_TIMEOUT';
        throw x;
      }
      if (e?.name === 'TypeError') {
        const x = new Error('Could not connect to the service. Check your Internet connection.');
        x.code = 'NETWORK_ERROR';
        throw x;
      }
      throw e;
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
    }
  }

  function authHeaders(token, extra = {}) {
    return {
      apikey: cfg.supabasePublishableKey,
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...extra
    };
  }

  async function auth(endpoint, body, method = 'POST') {
    return request(`${authBase}/${endpoint}`, {
      method,
      headers: authHeaders('', { 'Content-Type': 'application/json' }),
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  }

  async function signIn(email, password) {
    const a = await auth('token?grant_type=password', { email, password });
    return {
      localId: a?.user?.id,
      email: a?.user?.email || email,
      idToken: a?.access_token,
      accessToken: a?.access_token,
      refreshToken: a?.refresh_token,
      expiresIn: a?.expires_in || 3600,
      user: a?.user
    };
  }

  async function signUp(email, password) {
    const a = await auth('signup', { email, password });
    return {
      localId: a?.user?.id,
      email: a?.user?.email || email,
      idToken: a?.access_token || '',
      accessToken: a?.access_token || '',
      refreshToken: a?.refresh_token || '',
      expiresIn: a?.expires_in || 3600,
      user: a?.user
    };
  }

  async function refresh(refreshToken) {
    const a = await auth('token?grant_type=refresh_token', { refresh_token: refreshToken });
    return {
      user_id: a?.user?.id,
      id_token: a?.access_token,
      access_token: a?.access_token,
      refresh_token: a?.refresh_token,
      expires_in: a?.expires_in || 3600
    };
  }

  async function deleteAuthAccount(idToken) {
    return request(`${authBase}/user`, {
      method: 'DELETE',
      headers: authHeaders(idToken)
    });
  }

  function camelProfile(r) {
    if (!r) return null;
    return {
      uid: r.id,
      id: r.id,
      role: r.role,
      ownerUid: r.owner_id || '',
      subadminUid: r.subadmin_id || '',
      displayName: r.display_name || '',
      email: r.email || '',
      active: r.active !== false,
      accessMode: r.access_mode || '',
      visibleToSubadmin: r.visible_to_subadmin !== false,
      deviceResetVersion: Number(r.device_reset_version || 0),
      deviceResetAt: r.device_reset_at || '',
      siteIds: Array.isArray(r.site_ids) ? r.site_ids.map(String) : [],
      createdAt: r.created_at || r.created_at_legacy || '',
      createdAtLegacy: r.created_at_legacy || '',
      updatedAt: r.updated_at || ''
    };
  }

  function rowProfile(data) {
    const d = data || {};
    const row = {};
    if (d.id || d.uid) row.id = String(d.id || d.uid);
    if (d.role !== undefined) row.role = d.role;
    if (d.ownerUid !== undefined) row.owner_id = d.ownerUid || null;
    if (d.subadminUid !== undefined) row.subadmin_id = d.subadminUid || null;
    if (d.displayName !== undefined) row.display_name = d.displayName || null;
    if (d.email !== undefined) row.email = d.email || null;
    if (d.active !== undefined) row.active = d.active !== false;
    if (d.accessMode !== undefined) row.access_mode = d.accessMode || null;
    if (d.visibleToSubadmin !== undefined) row.visible_to_subadmin = d.visibleToSubadmin !== false;
    if (d.deviceResetVersion !== undefined) row.device_reset_version = Number(d.deviceResetVersion || 0);
    if (d.deviceResetAt !== undefined) row.device_reset_at = d.deviceResetAt || null;
    if (d.siteIds !== undefined) row.site_ids = Array.isArray(d.siteIds) ? d.siteIds.map(String) : [];
    if (d.createdAt !== undefined) row.created_at = d.createdAt || null;
    if (d.createdAtLegacy !== undefined) row.created_at_legacy = d.createdAtLegacy || null;
    if (d.updatedAt !== undefined) row.updated_at = d.updatedAt || new Date().toISOString();
    return row;
  }

  function camelSite(r) {
    if (!r) return null;
    return {
      id: r.id,
      name: r.name || '',
      origin: r.origin || '',
      hostname: r.hostname || '',
      ownerUid: r.owner_id || '',
      subadminUid: r.subadmin_id || '',
      active: r.active !== false,
      enabled: r.enabled !== false,
      blockedPatterns: Array.isArray(r.blocked_patterns) ? r.blocked_patterns : [],
      syncVersion: Number(r.sync_version || 0),
      lastSyncAt: r.last_sync_at || '',
      cookieFingerprint: r.cookie_fingerprint || '',
      updatedAt: r.updated_at || '',
      createdAt: r.created_at || ''
    };
  }

  function rowSite(data, id) {
    const d = data || {};
    return {
      id: String(id || d.id),
      name: d.name || '',
      origin: d.origin || '',
      hostname: d.hostname || '',
      owner_id: d.ownerUid || null,
      subadmin_id: d.subadminUid || null,
      active: d.active !== false,
      enabled: d.enabled !== false,
      blocked_patterns: Array.isArray(d.blockedPatterns) ? d.blockedPatterns : [],
      sync_version: Number(d.syncVersion || 0),
      last_sync_at: d.lastSyncAt || null,
      cookie_fingerprint: d.cookieFingerprint || null,
      created_at: d.createdAt || undefined,
      updated_at: d.updatedAt || new Date().toISOString()
    };
  }

  function camelProxy(r) {
    if (!r) return null;
    return {
      mode: r.mode || 'unconfigured',
      scheme: r.scheme || 'http',
      host: r.host || '',
      port: Number(r.port || 0),
      username: r.username || '',
      password: r.password || '',
      expectedIp: r.expected_ip || '',
      version: Number(r.version || 0),
      resetVersion: Number(r.reset_version || 0),
      healthy: r.healthy === true,
      ip: r.ip || '',
      lastError: r.last_error || '',
      lastCheckedAt: r.last_checked_at || '',
      createdAt: r.created_at || '',
      updatedAt: r.updated_at || ''
    };
  }

  function rowProxy(data, uid) {
    const d = data || {};
    return {
      user_id: String(uid || d.user_id),
      mode: d.mode || 'unconfigured',
      scheme: String(d.scheme || 'http').toLowerCase(),
      host: String(d.host || ''),
      port: Number(d.port || 0),
      username: String(d.username || ''),
      password: String(d.password || ''),
      expected_ip: String(d.expectedIp || ''),
      version: Number(d.version || 0),
      reset_version: Number(d.resetVersion || 0),
      healthy: d.healthy === true,
      ip: String(d.ip || ''),
      last_error: String(d.lastError || ''),
      last_checked_at: d.lastCheckedAt || null,
      created_at: d.createdAt || undefined,
      updated_at: d.updatedAt || new Date().toISOString()
    };
  }

  function camelControl(r) {
    if (!r) return null;
    return {
      userId: r.user_id,
      active: r.active !== false,
      proxyVersion: Number(r.proxy_version || 0),
      resetVersion: Number(r.reset_version || 0),
      updatedAt: r.updated_at || ''
    };
  }

  function rowControl(data, uid) {
    const d = data || {};
    return {
      user_id: String(uid || d.user_id),
      active: d.active !== false,
      proxy_version: Number(d.proxyVersion || 0),
      reset_version: Number(d.resetVersion || 0),
      updated_at: d.updatedAt || new Date().toISOString()
    };
  }

  function camelSyncKey(r) {
    if (!r) return null;
    return {
      userId: r.user_id,
      key: r.key || '',
      version: Number(r.version || 0),
      createdAt: r.created_at || '',
      updatedAt: r.updated_at || ''
    };
  }

  function rowSyncKey(data, uid) {
    const d = data || {};
    return {
      user_id: String(uid || d.user_id),
      key: String(d.key || ''),
      version: Number(d.version || 0),
      created_at: d.createdAt || undefined,
      updated_at: d.updatedAt || new Date().toISOString()
    };
  }

  function parseSyncEnvelope(value) {
    // Supabase stores the compatibility snapshot envelope in a TEXT column.
    // Older migration builds could accidentally persist a JavaScript object as
    // the literal string "[object Object]". Treat malformed/legacy values as
    // unavailable instead of allowing one bad site's snapshot to abort login.
    let current = value;
    for (let i = 0; i < 2 && typeof current === 'string'; i++) {
      const text = current.trim();
      if (!text || text === '[object Object]') return null;
      try { current = JSON.parse(text); }
      catch { return null; }
    }
    if (!current || typeof current !== 'object' || Array.isArray(current)) return null;
    if (Number(current.v) !== 1 && Number(current.v) !== 2) return null;
    if (Number(current.v) === 1 && (!current.iv || !current.ciphertext)) return null;
    if (Number(current.v) === 2 && (!current.ephemeralPublicJwk || !current.iv || !current.ciphertext)) return null;
    return current;
  }

  function camelSnapshot(r) {
    if (!r) return null;
    return {
      siteId: r.site_id,
      subadminUid: r.subadmin_id,
      version: Number(r.version || 0),
      requiredProxyVersion: Number(r.required_proxy_version || 0),
      requiredResetVersion: Number(r.required_reset_version || 0),
      envelope: parseSyncEnvelope(r.envelope),
      publishedAt: r.published_at || '',
      reason: r.reason || '',
      cookieFingerprint: r.cookie_fingerprint || '',
      createdAt: r.created_at || r.created_at_legacy || ''
    };
  }

  function rowSnapshot(data, siteId) {
    const d = data || {};
    return {
      site_id: String(siteId || d.site_id),
      subadmin_id: String(d.subadminUid || d.subadmin_id),
      version: Number(d.version || 0),
      required_proxy_version: Number(d.requiredProxyVersion || 0),
      required_reset_version: Number(d.requiredResetVersion || 0),
      envelope: typeof d.envelope === 'string'
        ? d.envelope
        : JSON.stringify(d.envelope || {}),
      published_at: d.publishedAt || new Date().toISOString(),
      reason: String(d.reason || ''),
      cookie_fingerprint: d.cookieFingerprint || null,
      created_at_legacy: d.createdAt || undefined
    };
  }

  function camelDevice(r) {
    if (!r) return null;
    return {
      uid: r.user_id,
      userId: r.user_id,
      subadminUid: r.subadmin_id || '',
      deviceId: r.device_id || '',
      status: r.status || '',
      extensionVersion: r.extension_version || '',
      lastSeenAt: r.last_seen_at || '',
      lastProxyVersion: Number(r.last_proxy_version || 0),
      lastResetVersion: Number(r.last_reset_version || 0),
      lastSyncVersion: Number(r.last_sync_version || 0),
      lastSyncVersionBySite: r.last_sync_version_by_site || {},
      lastSyncAt: r.last_sync_at || '',
      lastIp: r.last_ip || '',
      proxyHealthy: r.proxy_healthy === true,
      claimedAt: r.claimed_at || '',
      publicKey: r.public_key || '',
      lastProxyCheckAt: r.last_proxy_check_at || ''
    };
  }

  function rowDevice(data, uid) {
    const d = data || {};
    return {
      user_id: String(uid || d.user_id),
      subadmin_id: d.subadminUid || null,
      device_id: String(d.deviceId || ''),
      status: String(d.status || ''),
      extension_version: String(d.extensionVersion || ''),
      last_seen_at: d.lastSeenAt || null,
      last_proxy_version: Number(d.lastProxyVersion || 0),
      last_reset_version: Number(d.lastResetVersion || 0),
      last_sync_version: Number(d.lastSyncVersion || 0),
      last_sync_version_by_site: d.lastSyncVersionBySite || {},
      last_sync_at: d.lastSyncAt || null,
      last_ip: String(d.lastIp || ''),
      proxy_healthy: d.proxyHealthy === true,
      claimed_at: d.claimedAt || null,
      public_key: d.publicKey || null,
      last_proxy_check_at: d.lastProxyCheckAt || null
    };
  }

  function camelClaim(r) {
    if (!r) return null;
    return {
      uid: r.user_id,
      userId: r.user_id,
      deviceId: r.device_id || '',
      claimedAt: r.claimed_at || '',
      status: r.status || ''
    };
  }

  function rowClaim(data, uid) {
    const d = data || {};
    return {
      user_id: String(uid || d.user_id),
      device_id: String(d.deviceId || ''),
      claimed_at: d.claimedAt || new Date().toISOString(),
      status: String(d.status || 'claimed')
    };
  }

  function tableFilter(path, table, token) {
    const params = new URLSearchParams();
    params.set('select', '*');
    return { table, params };
  }

  async function selectOne(table, filters, token) {
    const params = new URLSearchParams();
    params.set('select', '*');
    for (const [k, v] of Object.entries(filters || {})) params.set(k, `eq.${v}`);
    const rows = await request(`${rest}/${table}?${params}`, {
      headers: authHeaders(token)
    });
    return Array.isArray(rows) && rows.length ? rows[0] : null;
  }

  async function selectMany(table, filters, token, order = null) {
    const params = new URLSearchParams();
    params.set('select', '*');
    for (const [k, v] of Object.entries(filters || {})) params.set(k, `eq.${v}`);
    // PostgREST caps responses (normally at 1,000 rows); page through the
    // complete collection so larger accounts do not silently lose clients/sites.
    const identity = table === 'client_site_access' ? 'site_id' : 'id';
    params.set('order', order ? `${order},${identity}.asc` : `${identity}.asc`);
    const pageSize = 500;
    const all = [];
    for (let offset = 0; ; offset += pageSize) {
      params.set('limit', String(pageSize));
      params.set('offset', String(offset));
      const rows = await request(`${rest}/${table}?${params}`, {
        headers: authHeaders(token)
      });
      if (!Array.isArray(rows)) return all;
      all.push(...rows);
      if (rows.length < pageSize) return all;
    }
  }

  async function insertOne(table, row, token) {
    return request(`${rest}/${table}`, {
      method: 'POST',
      headers: authHeaders(token, {
        'Content-Type': 'application/json',
        Prefer: 'return=representation'
      }),
      body: JSON.stringify(row)
    });
  }

  async function upsertOne(table, row, token, onConflict = 'user_id') {
    return request(`${rest}/${table}?on_conflict=${encodeURIComponent(onConflict)}`, {
      method: 'POST',
      headers: authHeaders(token, {
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates,return=representation'
      }),
      body: JSON.stringify(row)
    });
  }

  async function updateRows(table, filters, row, token) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(filters || {})) params.set(k, `eq.${v}`);
    return request(`${rest}/${table}?${params}`, {
      method: 'PATCH',
      headers: authHeaders(token, {
        'Content-Type': 'application/json',
        Prefer: 'return=representation'
      }),
      body: JSON.stringify(row)
    });
  }

  async function deleteRows(table, filters, token) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(filters || {})) params.set(k, `eq.${v}`);
    return request(`${rest}/${table}?${params}`, {
      method: 'DELETE',
      headers: authHeaders(token, { Prefer: 'return=minimal' })
    });
  }

  // Lightweight presence update used by the client heartbeat. The deviceId is
  // included in the filter so an old/reset device cannot update a newer
  // device's presence row. Only last_seen_at is changed.
  async function touchDevicePresence(uid, deviceId, token, lastSeenAt) {
    const rows = await updateRows('devices', {
      user_id: String(uid || ''),
      device_id: String(deviceId || '')
    }, {
      last_seen_at: lastSeenAt || new Date().toISOString()
    }, token);
    return Array.isArray(rows) ? rows[0] || null : null;
  }

  function wrap(exists, data) {
    return { exists: !!exists, data: data || null };
  }

  async function getDoc(path, token) {
    if (!Array.isArray(path)) path = String(path).split('/').filter(Boolean);
    if (!path.length) throw new Error('Invalid data path.');

    if (path[0] === 'users') {
      const uid = path[1];
      if (!uid) throw new Error('Invalid user path.');

      if (path.length === 2) {
        const r = await selectOne('profiles', { id: uid }, token);
        return wrap(!!r, camelProfile(r));
      }

      if (path[2] === 'proxy' && path[3] === 'config') {
        const r = await selectOne('proxy_configs', { user_id: uid }, token);
        return wrap(!!r, camelProxy(r));
      }

      if (path[2] === 'control' && path[3] === 'state') {
        const r = await selectOne('control_state', { user_id: uid }, token);
        return wrap(!!r, camelControl(r));
      }

      if (path[2] === 'control' && path[3] === 'status') {
        const r = await selectOne('control_state', { user_id: uid }, token);
        if (!r) return wrap(false, null);
        return wrap(true, {
          active: r.active !== false,
          reason: r.active === false ? 'Account suspended.' : '',
          updatedAt: r.updated_at || ''
        });
      }

      if (path[2] === 'syncKey' && path[3] === 'config') {
        const r = await selectOne('sync_keys', { user_id: uid }, token);
        return wrap(!!r, camelSyncKey(r));
      }

      if (path[2] === 'clients') {
        const r = await selectOne('profiles', { id: path[3] }, token);
        if (!r || r.subadmin_id !== uid) return wrap(false, null);
        return wrap(true, camelProfile(r));
      }

      if (path[2] === 'sites') {
        const r = await selectOne('sites', { id: path[3] }, token);
        if (!r || r.subadmin_id !== uid) return wrap(false, null);
        return wrap(true, camelSite(r));
      }
    }

    if (path[0] === 'sites') {
      const siteId = path[1];
      if (!siteId) throw new Error('Invalid site path.');
      if (path.length >= 4 && path[2] === 'sync' && path[3] === 'latest') {
        const r = await selectOne('site_sync_snapshots', { site_id: siteId }, token);
        return wrap(!!r, camelSnapshot(r));
      }
      const r = await selectOne('sites', { id: siteId }, token);
      return wrap(!!r, camelSite(r));
    }

    if (path[0] === 'clientAccess') {
      const uid = path[1];
      const rows = await selectMany('client_site_access', { client_id: uid }, token, 'created_at.asc');
      if (!rows.length) return wrap(false, null);
      return wrap(true, {
        ownerUid: rows[0].owner_id || '',
        subadminUid: rows[0].subadmin_id || '',
        siteIds: [...new Set(rows.map(r => String(r.site_id)))]
      });
    }

    if (path[0] === 'devices') {
      const r = await selectOne('devices', { user_id: path[1] }, token);
      return wrap(!!r, camelDevice(r));
    }

    if (path[0] === 'deviceClaims') {
      const r = await selectOne('device_claims', { user_id: path[1] }, token);
      return wrap(!!r, camelClaim(r));
    }

    if (path[0] === 'subadminProxyConfigs') {
      const r = await selectOne('proxy_configs', { user_id: path[1] }, token);
      return wrap(!!r, camelProxy(r));
    }

    throw new Error(`Unsupported data path: ${path.join('/')}`);
  }

  async function setDoc(path, data, token) {
    if (!Array.isArray(path)) path = String(path).split('/').filter(Boolean);
    if (!path.length) throw new Error('Invalid data path.');

    if (path[0] === 'users') {
      const uid = path[1];

      if (path.length === 2) {
        const row = rowProfile({ ...data, id: uid });
        const result = await upsertOne('profiles', row, token, 'id');
        return wrap(true, camelProfile(result?.[0] || row));
      }

      if (path[2] === 'proxy' && path[3] === 'config') {
        const row = rowProxy(data, uid);
        const result = await upsertOne('proxy_configs', row, token, 'user_id');
        return wrap(true, camelProxy(result?.[0] || row));
      }

      if (path[2] === 'control' && (path[3] === 'state' || path[3] === 'status')) {
        const current = await selectOne('control_state', { user_id: uid }, token);
        const merged = path[3] === 'status'
          ? { ...(current ? camelControl(current) : {}), active: data.active !== false, updatedAt: data.updatedAt || new Date().toISOString() }
          : { ...(current ? camelControl(current) : {}), ...data };
        const row = rowControl(merged, uid);
        const result = await upsertOne('control_state', row, token, 'user_id');
        return wrap(true, camelControl(result?.[0] || row));
      }

      if (path[2] === 'syncKey' && path[3] === 'config') {
        const row = rowSyncKey(data, uid);
        const result = await upsertOne('sync_keys', row, token, 'user_id');
        return wrap(true, camelSyncKey(result?.[0] || row));
      }

      if (path[2] === 'clients' && path[3]) {
        const row = rowProfile({ ...data, id: path[3] });
        const result = await upsertOne('profiles', row, token, 'id');
        return wrap(true, camelProfile(result?.[0] || row));
      }

      // The old nested users/{subadmin}/sites/{siteId} membership document is
      // normalized into sites.subadmin_id. The caller writes the actual site
      // separately, so this compatibility write is intentionally a no-op.
      if (path[2] === 'sites' && path[3]) {
        return wrap(true, { uid, siteId: path[3], ...data });
      }
    }

    if (path[0] === 'sites') {
      const siteId = path[1];
      if (path.length >= 4 && path[2] === 'sync' && path[3] === 'latest') {
        const row = rowSnapshot(data, siteId);
        const result = await upsertOne('site_sync_snapshots', row, token, 'site_id');
        return wrap(true, camelSnapshot(result?.[0] || row));
      }
      const row = rowSite(data, siteId);
      const result = await upsertOne('sites', row, token, 'id');
      return wrap(true, camelSite(result?.[0] || row));
    }

    if (path[0] === 'clientAccess') {
      const uid = path[1];
      const d = data || {};
      await deleteRows('client_site_access', { client_id: uid }, token);
      const siteIds = Array.isArray(d.siteIds) ? [...new Set(d.siteIds.map(String))] : [];
      if (siteIds.length) {
        const rows = siteIds.map(siteId => ({
          client_id: uid,
          site_id: siteId,
          owner_id: d.ownerUid || null,
          subadmin_id: d.subadminUid || null,
          created_at: d.updatedAt || new Date().toISOString()
        }));
        await insertOne('client_site_access', rows, token);
      }
      return wrap(true, d);
    }

    if (path[0] === 'devices') {
      const uid = path[1];
      const row = rowDevice(data, uid);
      const result = await upsertOne('devices', row, token, 'user_id');
      return wrap(true, camelDevice(result?.[0] || row));
    }

    if (path[0] === 'deviceClaims') {
      const uid = path[1];
      const row = rowClaim(data, uid);
      const result = await upsertOne('device_claims', row, token, 'user_id');
      return wrap(true, camelClaim(result?.[0] || row));
    }

    if (path[0] === 'subadminProxyConfigs') {
      const uid = path[1];
      const row = rowProxy(data, uid);
      const result = await upsertOne('proxy_configs', row, token, 'user_id');
      return wrap(true, camelProxy(result?.[0] || row));
    }

    throw new Error(`Unsupported data path: ${path.join('/')}`);
  }

  async function deleteDoc(path, token) {
    if (!Array.isArray(path)) path = String(path).split('/').filter(Boolean);
    if (!path.length) return;

    if (path[0] === 'users') {
      const uid = path[1];
      if (path.length === 2) {
        await deleteRows('profiles', { id: uid }, token);
        return;
      }
      if (path[2] === 'proxy' && path[3] === 'config') {
        await deleteRows('proxy_configs', { user_id: uid }, token);
        return;
      }
      if (path[2] === 'control' && (path[3] === 'state' || path[3] === 'status')) {
        await deleteRows('control_state', { user_id: uid }, token);
        return;
      }
      if (path[2] === 'syncKey' && path[3] === 'config') {
        await deleteRows('sync_keys', { user_id: uid }, token);
        return;
      }
      if (path[2] === 'clients' && path[3]) {
        await deleteRows('profiles', { id: path[3], subadmin_id: uid }, token);
        return;
      }
      if (path[2] === 'sites' && path[3]) {
        return;
      }
    }

    if (path[0] === 'sites') {
      const siteId = path[1];
      if (path.length >= 4 && path[2] === 'sync' && path[3] === 'latest') {
        await deleteRows('site_sync_snapshots', { site_id: siteId }, token);
        return;
      }
      await deleteRows('sites', { id: siteId }, token);
      return;
    }

    if (path[0] === 'clientAccess') {
      await deleteRows('client_site_access', { client_id: path[1] }, token);
      return;
    }

    if (path[0] === 'devices') {
      await deleteRows('devices', { user_id: path[1] }, token);
      return;
    }

    if (path[0] === 'deviceClaims') {
      await deleteRows('device_claims', { user_id: path[1] }, token);
      return;
    }

    if (path[0] === 'subadminProxyConfigs') {
      await deleteRows('proxy_configs', { user_id: path[1] }, token);
      return;
    }
  }

  async function listDocs(path, token) {
    if (!Array.isArray(path)) path = String(path).split('/').filter(Boolean);

    if (path[0] === 'users') {
      const uid = path[1];
      if (path.length === 2) {
        const rows = await selectMany('profiles', {}, token, 'created_at.asc');
        return rows.map(r => ({ id: r.id, data: camelProfile(r) }));
      }
      if (path[2] === 'clients') {
        const rows = await selectMany('profiles', { subadmin_id: uid }, token, 'created_at.asc');
        return rows
          .filter(r => r.role === 'client')
          .map(r => ({ id: r.id, data: camelProfile(r) }));
      }
      if (path[2] === 'sites') {
        const rows = await selectMany('sites', { subadmin_id: uid }, token, 'created_at.asc');
        return rows.map(r => ({
          id: r.id,
          data: { siteId: r.id, name: r.name, origin: r.origin, hostname: r.hostname, active: r.active !== false, createdAt: r.created_at || '', updatedAt: r.updated_at || '' }
        }));
      }
    }

    if (path[0] === 'sites' && path.length === 1) {
      const rows = await selectMany('sites', {}, token, 'created_at.asc');
      return rows.map(r => ({ id: r.id, data: camelSite(r) }));
    }

    throw new Error(`Unsupported list path: ${path.join('/')}`);
  }

  async function createDoc(path, data, token) {
    if (!Array.isArray(path)) path = String(path).split('/').filter(Boolean);

    if (path[0] === 'devices') {
      const row = rowDevice(data, path[1]);
      const result = await insertOne('devices', row, token);
      return wrap(true, camelDevice(result?.[0] || row));
    }

    if (path[0] === 'deviceClaims') {
      const row = rowClaim(data, path[1]);
      try {
        const result = await insertOne('device_claims', row, token);
        return wrap(true, camelClaim(result?.[0] || row));
      } catch (e) {
        // Some deployed Supabase databases enforce a UNIQUE constraint on
        // device_claims.device_id. When this Chrome installation is already
        // claimed by another account, surface the intended device-claim error
        // instead of leaking the raw Postgres constraint message into the UI.
        const raw = String(e?.message || e || '');
        const code = String(e?.code || '');
        if (code === '23505' || /device_claims_device_id_idx|duplicate key value violates unique constraint/i.test(raw)) {
          const x = new Error('This Chrome device is already registered to another account. Use Reset Device on the existing account before moving it.');
          x.code = 'DEVICE_ALREADY_CLAIMED';
          throw x;
        }
        throw e;
      }
    }

    throw new Error(`Unsupported create path: ${path.join('/')}`);
  }

  async function queryDocsByField(collectionSegments, fieldPath, op, value, token, options = {}) {
    const segments = Array.isArray(collectionSegments) ? collectionSegments : [];
    if (String(op || 'EQUAL') !== 'EQUAL') throw new Error('Only equality queries are supported.');

    if (segments[0] === 'sites') {
      const col = {
        subadminUid: 'subadmin_id',
        ownerUid: 'owner_id',
        active: 'active',
        enabled: 'enabled',
        id: 'id'
      }[String(fieldPath)] || String(fieldPath);
      const rows = await selectMany('sites', { [col]: value }, token, 'created_at.asc');
      return rows.map(r => ({ id: r.id, data: camelSite(r) }));
    }

    if (segments[0] === 'users' && segments[2] === 'clients') {
      const uid = segments[1];
      const rows = await selectMany('profiles', { subadmin_id: uid }, token, 'created_at.asc');
      let out = rows.filter(r => r.role === 'client');
      if (String(fieldPath) === 'visibleToSubadmin') out = out.filter(r => r.visible_to_subadmin === Boolean(value));
      if (String(fieldPath) === 'active') out = out.filter(r => r.active === Boolean(value));
      return out.map(r => ({ id: r.id, data: camelProfile(r) }));
    }

    throw new Error(`Unsupported query path: ${segments.join('/')}`);
  }

  async function commitDocs(writes, token) {
    for (const w of (writes || [])) {
      await setDoc(w.path || w.segments, w.data || {}, token);
    }
    return { writeResults: [] };
  }

  return {
    request,
    signIn,
    signUp,
    refresh,
    deleteAuthAccount,
    getDoc,
    createDoc,
    setDoc,
    deleteDoc,
    commitDocs,
    touchDevicePresence,
    listDocs,
    queryDocsByField,
    parseFields: x => x || {},
    fieldValue: x => x
  };
})();
