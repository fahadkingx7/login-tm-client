const q=new URLSearchParams(location.search);const target=q.get('target')||'';let navigating=false;
function go(){if(!target||navigating)return;try{const u=new URL(target);if(!['http:','https:'].includes(u.protocol))throw new Error('bad target')}catch{return}navigating=true;location.href=target;}
async function check(){try{const r=await chrome.runtime.sendMessage({type:'proxy-wait-status'});if(r?.status==='connected'){go();}}catch(e){}}
check();setInterval(check,1000);
