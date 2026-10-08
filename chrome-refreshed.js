(() => {
  const params=new URLSearchParams(location.search);
  if(params.get('remote') !== '1') return;
  const title=document.querySelector('h1');
  const message=document.querySelector('p');
  if(title)title.textContent=params.get('profile') === '1' ? 'Your profile has been refreshed' : 'Your Admin has cleaned your browser';
  if(message)message.textContent='Your browser data was cleared. Open the extension to check your shared login and connected websites.';
})();
