const action=document.getElementById('action');
action.addEventListener('click',async()=>{
  action.disabled=true; action.textContent='Checking…';
  try{
    const r=await chrome.runtime.sendMessage({type:'warning-check'});
    if(r?.ok){location.href='about:blank';return;}
    action.disabled=false; action.textContent='Check Again';
  }catch{
    action.disabled=false; action.textContent='Check Again';
  }
});
