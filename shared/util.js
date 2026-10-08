globalThis.CS = globalThis.CS || {};
CS.Util = {
  now: () => new Date().toISOString(),
  sleep: ms => new Promise(r => setTimeout(r, ms)),
  uuid: () => (crypto.randomUUID ? crypto.randomUUID() : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`),
  clampString: (v, max=2000) => String(v ?? '').trim().slice(0, max),
  normalizeEmail: v => String(v || '').trim().toLowerCase(),
  safeDecodeURIComponent: v => { try { return decodeURIComponent(v); } catch { return v; } },
  async timeout(promise, ms, message='Timed out') {
    let timer;
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), ms); });
    try { return await Promise.race([promise, timeout]); } finally { clearTimeout(timer); }
  },
  originFromUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) throw new Error('Website URL is required.');
    const url = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP/HTTPS websites are supported.');
    return url.origin;
  },
  siteFromOrigin(origin) {
    const u = new URL(origin);
    return { origin: u.origin, hostname: u.hostname.toLowerCase(), scheme: u.protocol.slice(0,-1) };
  },
  hostnameMatches(siteHostname, candidate) {
    const s = String(siteHostname || '').replace(/^\./,'').toLowerCase();
    const c = String(candidate || '').replace(/^\./,'').toLowerCase();
    return !!s && (c === s || c.endsWith(`.${s}`));
  },
  scopeHostname(hostname) {
    const host=String(hostname||'').replace(/^\./,'').trim().toLowerCase();
    return CS.PublicSuffix ? CS.PublicSuffix.scopeHostname(host) : host;
  },
  dnrSiteFilter(hostname) { return `||${hostname.replace(/^\./,'')}^`; },
  toJsonSafe(value) { return JSON.parse(JSON.stringify(value)); },
  fileSafeName(value) { return String(value || '').replace(/[^a-z0-9._-]/gi, '_'); }
};