(() => {
  let hideTimer = null;
  let lastY = -1;
  const activate = () => {
    const scroller = document.scrollingElement || document.documentElement;
    document.documentElement.classList.add('scrollbar-active');
    if (document.body) document.body.classList.add('scrollbar-active');
    if (scroller) scroller.classList.add('scrollbar-active');
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => {
      document.documentElement.classList.remove('scrollbar-active');
      if (document.body) document.body.classList.remove('scrollbar-active');
      if (scroller) scroller.classList.remove('scrollbar-active');
    }, 850);
  };
  window.addEventListener('scroll', activate, { passive: true, capture: true });
  document.addEventListener('scroll', activate, { passive: true, capture: true });
  window.addEventListener('wheel', activate, { passive: true });
  window.addEventListener('touchmove', activate, { passive: true });
  const poll = () => {
    const scroller = document.scrollingElement || document.documentElement;
    const y = scroller ? scroller.scrollTop : window.scrollY;
    if (y !== lastY) {
      lastY = y;
      activate();
    }
    requestAnimationFrame(poll);
  };
  requestAnimationFrame(poll);
})();
