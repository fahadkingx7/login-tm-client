(() => {
  const action = document.getElementById('recovery-action');
  if (action) {
    action.href = 'https://one.dat.com/';
    action.textContent = 'Visit one.dat.com';
    action.removeAttribute('target');
  }
  const params = new URLSearchParams(location.search);
  const page = document.body.dataset.recoveryPage;
  const message = document.getElementById('recovery-message');
  const title = document.querySelector('h1');
  const recoveryContact = document.getElementById('recovery-contact');
  if (recoveryContact) recoveryContact.hidden = true;

  // These are confirmation pages, not diagnostics: never display partial-sync
  // statuses or ask the user to retry when browser cleanup was completed.
  if (page === 'refreshed') {
    if (title) title.textContent = 'Chrome refreshed';
    if (message) message.textContent = 'Your browser has been refreshed. Visit one.dat.com to continue.';
    return;
  }
  if (page === 'welcome') {
    if (title) title.textContent = 'Extension installed';
    if (message) message.textContent = 'LogIn is ready. Visit one.dat.com to continue.';
    // Preserve v6.1.32's confirmed working one-time login Fresh Sync.
    if (params.get('autosync') === '1') {
      setTimeout(() => {
        try {
          chrome.runtime.sendMessage({type:'auto-sync-after-login'}, () => {
            void chrome.runtime.lastError;
          });
        } catch {}
      }, 700);
    }
    return;
  }
  if (page === 'proxy' && message) {
    message.textContent = 'Your connection settings are ready. Visit one.dat.com to continue.';
  }
})();
