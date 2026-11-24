/* Trade coin site settings: loads what the admin saved (Admin > Site) and applies it. Safe if the server has none. */
(function(){
  var D=document.documentElement;
  function apply(c){
    if(!c)return;
    var l=parseInt(c.layout,10);if(l>=1&&l<=10)D.setAttribute('data-layout',l);
    var v=c.vars||{};for(var k in v)if(/^[a-z-]+$/.test(k)&&/^#[0-9a-f]{6}$/i.test(v[k]))D.style.setProperty('--'+k,v[k]);
    if(c.css){var s=document.getElementById('tcCss')||document.head.appendChild(Object.assign(document.createElement('style'),{id:'tcCss'}));s.textContent=String(c.css).slice(0,20000);}
    function t(){(c.texts||[]).forEach(function(r){try{if(!r.sel)return;document.querySelectorAll(r.sel).forEach(function(e){e.textContent=r.text})}catch(x){}});
      if(c.title)document.title=c.title;
      (c.hideTabs||[]).forEach(function(n){document.querySelectorAll('[data-tab="'+n+'"]').forEach(function(e){e.style.display='none'})});}
    if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',t);else t();
    addEventListener('load',function(){setTimeout(t,1500)});
  }
  var cached;try{cached=JSON.parse(localStorage.getItem('tcSite')||'null')}catch(e){}
  apply(cached);
  var q=location.search.match(/[?&]layout=(\d+)/);if(q)apply({layout:q[1]});   // preview: /?layout=5
  fetch('/site/config',{cache:'no-store'}).then(function(r){return r.ok?r.json():null}).then(function(c){if(c&&c.layout){try{localStorage.setItem('tcSite',JSON.stringify(c))}catch(e){}apply(c)}}).catch(function(){});
})();
