globalThis.CS = globalThis.CS || {};
CS.Recovery = (() => {
  function assignedDestination(sites, profile) {
    if (!profile || profile.role !== 'client' || profile.active === false || !profile.subadminUid) return null;
    for (const site of Array.isArray(sites) ? sites : []) {
      if (!site || site.active === false || site.enabled === false ||
          String(site.subadminUid || '') !== String(profile.subadminUid)) continue;
      try {
        const url = new URL(String(site.origin || ''));
        const hostname = String(site.hostname || '').toLowerCase().replace(/\.$/, '');
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
            !hostname || url.hostname.toLowerCase().replace(/\.$/, '') !== hostname) continue;
        return { url: url.origin + '/', hostname: url.hostname };
      } catch {}
    }
    return null;
  }

  const cacheKeys = ['authSession', 'profileCache', 'clientSitesCache', 'clientSitesCacheSubadminUid'];
  function cachedDestination(cache) {
    const profile = cache?.profileCache;
    if (!cache?.authSession?.uid || String(cache.authSession.uid) !== String(profile?.uid || profile?.id || '') ||
        String(cache.clientSitesCacheSubadminUid || '') !== String(profile?.subadminUid || '')) return null;
    return assignedDestination(cache.clientSitesCache, profile);
  }

  function syncStatus(sync) {
    if (!sync?.ok || sync.error || sync.suspended || sync.locked || sync.deviceBlocked || sync.needsPermission) return 'retry';
    const diagnostics = Array.isArray(sync.syncDiagnostics) ? sync.syncDiagnostics : [];
    const successful = diagnostics.filter(item => ['applied', 'already-applied'].includes(item.status)).length;
    if (Number(sync.cookieFailures || 0) > 0 || diagnostics.some(item => !['applied', 'already-applied'].includes(item.status))) {
      return successful || Number(sync.applied || 0) > 0 ? 'partial' : 'retry';
    }
    return successful || Number(sync.applied || 0) > 0 ? 'restored' : 'retry';
  }

  return { assignedDestination, cachedDestination, cacheKeys, syncStatus };
})();

