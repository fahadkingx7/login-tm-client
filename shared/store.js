globalThis.CS = globalThis.CS || {};
CS.Store = {
  async get(keys) { return chrome.storage.local.get(keys); },
  async set(values) { return chrome.storage.local.set(values); },
  async remove(keys) { return chrome.storage.local.remove(keys); },
  async clear() { return chrome.storage.local.clear(); }
};